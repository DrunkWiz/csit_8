# TISC 2026 — Level 8 `cmdwrap` — Solution Plan / Findings Log

**Goal:** recover the `TISC{...}` flag from `nc cmdwrap.chals.tisc26.ctf.sg 4444`.
Given file: `cmdwrap.exe` (34 KB, x64 PE). Catalog is server-side only (127.0.0.1:8080 from the worker).

Status as of 2026-09-15 (second execution session): **flag not yet recovered.** All client-side
static analysis is now complete and verified independently; the one *new* hidden mechanic was found
and exploited (broker `secret-var` recovery), but it did not directly unlock the decode key.

---

## 0. TL;DR of the mechanism (unchanged, verified)

1. Broker on :4444 spawns a worker per connection:
   `cmdwrap.exe --session-socket <h> --client-ip <ip> --ip-count <n> --secret-var <rand32> --max-concurrent <m>`
2. Worker = plaintext line shell (`cmdwrap> `, `\n`-terminated, `\r` **skipped anywhere in the line**,
   empty line disconnects, line buffer 0x1000, hard limit 4095 bytes/line). Base verbs: `help`,
   `add_capability <name> <password>`.
3. Capabilities = DLLs fetched over HTTP from the catalog, saved to `sessions\<uuid>\<name>.dll`,
   `LoadLibraryA`'d, verb registered. **`easy_load <cap>` == `add_capability <cap> <UUID>`.**
4. `/load` body = `name=%s&password=%s&session=%s`, all three **URL-encoded by the worker**
   (allow-set verified = RFC3986 unreserved `A-Za-z0-9-._~`). **No HTTP parameter injection possible.**
5. Flag = `flag_decode <key>` → catalog `POST /decode` body `key=<url-encoded key>` (no session field).
   Wrong key → non-200 → worker writes `DECODE FAILED`; right key → response bytes written to
   `sessions\<uuid>\flag.txt` → `file_download flag.txt`.
6. **The open problem remains the global `/decode` key.**

---

## 1. New findings this session (2026-09-15, session 2)

### 1.1 Broker `secret-var` is recoverable via a *blocked session* (CONFIRMED, worked live)

* Broker generates ONE random 32-bit `secret-var` per broker process (BCryptGenRandom; IAT confirmed
  `bcrypt.dll!BCryptGenRandom`, fallback GetTickCount) and passes the same value to every worker.
* At session setup the worker checks `ip-count > max-concurrent`; if so it creates
  `sessions\<uuid>\<%08X_blocker.dat` in **its own sandbox**, where the value = `client_ip ^ secret_var`.
* A blocked session prints, on *every* command, `[<its-uuid>] Too many sessions from IP a.b.c.d`,
  i.e. it leaks both **its UUID** and **our source IP** even though all other commands are refused.
* Another (normal) session can then `list_sandbox <blocked-uuid>` → read the blocker filename →
  `secret_var = filename_value ^ ip_value`.
* Live values recovered:
  * `secret_var = 0xD0A8C06D` (stable per broker process)
  * our exit IP `= 58.182.96.79` (`0x3AB6604F`), remote `max-concurrent = 3`.
* The worker folds it as
  `x = (FNV1a64(uuid)>>32) ^ secret_var ^ (FNV1a64(uuid)&0xffffffff)`, `session_key = (x^(x>>16))&0xffff`,
  stored at `priv+0x238/0x23c`; used ONLY by the FSM keystream (`FUN_140002e90`) which is used by
  arena slot tags (readable via `recall` n=64) and `dump_cipher_state` (api[15], unreachable).
* **Tested live and rejected as passwords/keys for `rename_session`, `cheat`, and `/decode`** (many
  encodings incl. raw bytes, decimal, hex, session_key, x, FNV64, uuid variants). So the catalog's
  secrets are *not* derived from the broker secret-var.

### 1.2 Further protocol facts

* `/list` response lines have shape `<name>\t<field2>\t<field3>` — the worker's renderer requires
  **two tabs per line** and prints only field 1 (`    %.*s`). Fields 2/3 are sent by the catalog but
  never displayed. (No known way to read the raw list: the cache lives at `session+0x8c8`, only
  `help` touches it, and the only arbitrary-session-memory read capability is `history`, which
  SipHashes the value read — see §2.4.)
* Catalog auth model (live-verified): `whoami`/`easy_load` password = literal `newuser`;
  every other loadable cap = the session UUID exactly; `rename_session` rejects the UUID and every
  guess tried (401); `cheat` = only UUID passes auth, then **HTTP 500** on serve.
* `add_capability <name> <password>` tokenization: name 1..63 chars and subject to the bitmask filter
  blocking `" * / : < > ? \ |` and any `..` pair; **password is unrestricted** (1..127 bytes, no
  spaces) but is still URL-encoded. Body buffer 0x800; local DLL path `<sandbox>\<name>.dll`.
* `help` URL: `/list?session=<override>` only if the session-override buffer is non-empty, else `/list`.
  The override is allocated at session setup but only `set_session_override` (api[4]) writes it, and
  **no loadable capability calls api[4]** (`rename_session` is the only caller).
* Same for api[15] (dump_cipher_state): no loadable capability calls it.

### 1.3 Catalog cannot be attacked by length/parameter tricks (all live-verified)

* Double-URL-decoding: NOT present (probed with `%26...`-double-encoded injections; all 401/404).
* Long inputs (name 63, password 127 incl. all-`&` = 381 encoded bytes) → clean 401/404, catalog
  stays alive. No crash ⇒ catalog buffers ≥128/≥192 bytes.
* Hidden capability names: fuzzed ~45 names (`flag`, `flag.txt`, `key`, `decode`, `cheat.dll`,
  `whoami.dll`, `catalog.py`, `.env`, ...) → all 404.
* Planting files in our own sandbox (`cheat.dll`, `cheat`, `cheat.bin`, `rename_session...`) does NOT
  change the 500/401 ⇒ catalog does not serve from the session sandbox.
* Repeated `cheat` attempts + `help` never produce `<crash>` strikes ⇒ catalog `/list` is static
  (the `<crash>`/`Strike` rendering in `help` is a red herring as previously concluded).

### 1.4 Complete credential brute force (all failed)

* ~1250 thematic/common/leet candidates tested as `rename_session`/`cheat` passwords (session ended
  mid-run, no hits) and ~920 candidates tested live as `/decode` keys (**no hit**).
* Derived values (secret-var/session_key/FNV/x/UUID transforms) also tested against all three
  endpoints — no hit.
* PASSWORDS ARE NOT GUESSABLE; the hard path must be a real leak/RCE.

---

## 2. Memory-safety audit (completed, with /GS verification)

All capability DLLs audited from the Ghidra C and selective disassembly. Summary:

### 2.1 `base64_decode` — real stack buffer overflow, /GS-blocked
`FUN_180001500`: decodes base64 into `byte local_418[1024]` on the stack with NO bounds check
(writes `out[i]` for i = decoded length). Input = `base64_decode <name> <b64>`, b64 is the raw rest
of the line (up to ~4095 chars ⇒ up to ~3 KB decoded). Layout (verified in disassembly):
`out[1024] @ rsp+0x30`, cookie `@ rsp+0x430`, saved rdi `@ rsp+0x440`, return `@ rsp+0x448`.
⇒ overflow first overwrites the /GS cookie; `__security_check_cookie` → `__fastfail`.
**Live-confirmed:** decoding 2000 bytes (b64 of a 2000-byte blob) instantly kills the worker
(connection reset). Exploit would need a cookie+stack leak; none found.

### 2.2 `parse_json` — unbounded `vsprintf` into 256-byte stack buffer, also a dead end
`FUN_180001e30` is a **sprintf with size = 0xffffffffffffffff**; `FUN_1800017c0` calls it as
`FUN_180001e30(local_928 /*256 B*/, "cmd.exe /c dir /b \"%s\\%s\"", sandbox, filtered_subdir)`.
The subdir is filtered but can be up to ~4095 bytes ⇒ spills over `local_828[2048]` (which sits right
after it) and can reach the cookie at `+0x900`. Dead end for two verified reasons:
  * `strcpy_s(local_828, 0x800, local_928)` runs BEFORE CreateProcessA; on overflow the UCRT
    `strcpy_s` **terminates the process** via the invalid-parameter handler (verified locally:
    exit code 0xC0000409). So a >0x7FF command never reaches `CreateProcessA` with our bytes.
  * Cookie still checked; no leak.
The filter (verified by extracting the bitmask `0x97fffffe03ffe001`) allows `space - . / 0-9 A-Z \ _`
plus a-z, replaces `..` pairs and disallowed chars with `_`; `"`, `|`, `&`, `%`, `^`, `:`, `?`, `*`
are all impossible ⇒ even past the quote no cmd metachar injection.

### 2.3 Everything else is bounded/hardened (re-verified this session)
All functions containing stack arrays reference the module cookie. `chain` clamp fine.
`regex_match` command uses bounded `_snwprintf_s` + bounded `strcpy_s` (only the recursive glob
matcher is quadratic/exponential — DoS at best). `xor_cipher` name <0x400, key <0x100, both copied
into correctly sized state buffers; XOR loop uses keylen modulo. `stash` hex parse bounded by slot
size 0x38; `recall` reads ≤64 B from a 0x40-stride arena slot (leaks only the 8-byte tag:
`<16-bit keystream word><0x0038><0x00000000>`). `list_sandbox` strict 36-char UUID validator (dashes
at 8/13/18/23, hex only). `file_download`/`base64_decode` name filters block `" * : ? < > | / \ ..`.
`flag_decode` reuses its global state/key buffers (so unlimited calls per session) and clamps key
length to the 0x38-byte arena slot. `easy_load` tracking buffer bounded. `whoami` prints UUID.
`file_transfer` is a genuine one-string stub (no `cmdwrap_wants_args` export ⇒ args rejected).

### 2.4 `history` OOB (the one deliberate logic bug) is SipHash-protected
`api[6]` reads `[session + 0x150 + slot*8]` with only a `slot >= 0` check. `FUN_180001600` prints
`[history] slot %d @ %016llx: (entry|null)` where the value is put through a verbatim SipHash-2-4
keyed by two BCryptGenRandom 64-bit words generated once per history.dll instance. No inversion /
reuse found. Note the *worker stack* layout also puts the 0x1000-byte input line buffer at
`session+0x18d0`, i.e. reachable by `history` slots ≈ 480+ — but still hashed.

### 2.5 SDK / arena facts worth keeping
* SDK table = session+0x238 (16 entries). api[4]=set_session_override, api[6]=history fetch
  (unchecked), api[7]=arena alloc (size ≤ 0x38), api[8]=arena free, api[10]=catalog_decode,
  api[11]=stash alloc, api[12]=stash fetch (bounds-checked), api[13]=stash free, api[14]=stash
  count, api[15]=dump_cipher_state. No loadable DLL calls api[4]/api[15].
* Arena: one `VirtualAlloc(0x3000)` at `priv[0]` (priv = session+0x230), 0x40-byte slots with
  16-bit keystream tags; allocator has an `int3` anti-tamper check; `FLG` tag reads only via `recall`.
* Override buffer = arena slot (0x38) at session+0x1d8, empty by default.
* History ring = session+0x150..0x1d0 (16 × strdup'd command lines), head/count at +0x1d4/+0x1d0.
* `help` cache: flag/len/buffer at session+0x8c0/+0x8c4/+0x8c8 (0x1000).
* Broker's per-IP count decrements via a thread waiting on the worker process handle.

---

## 3. What was tried against the `/decode` key (all rejected)

* `newuser`, `admin`, `password`, `key`, `flag`, `decode`, `cheat`, `cmdwrap`, `TISC`, `tisc`,
  `singularity` (case/leet/perm variants), `omnitrix`, `flag_decode`, `easy_load`, description words,
  ~920 more dictionary/pattern candidates.
* secret-var / session_key / x / FNV64(uuid) / UUID (all encodings incl. raw bytes).
* UUID of every session recorded this session incl. blocked ones; uppercase/no-dash/reversed/braced.

---

## 4. Where to look next (ranked)

### 4.0 Additional experiments run (all negative) — do not repeat
* **Accelerated brute force via `chain`** works great: `chain flag_decode k1;flag_decode k2;...`
  (~64 keys/line, ≈300 keys/s, unlimited per session because flag_decode reuses its state buffers).
  Swept: all 4-digit `%04d`, all 4-hex `%04x`, all 5-digit `%05d`, all unpadded 0..65535, plus
  common ports/numbers. **No `/decode` hit.**
* Word/phrase lists: ~920 themed/leet/dictionary-ish candidates + all contiguous-word/leet
  permutations of the challenge description against `/decode` — no hit. ~1250 candidates against
  `rename_session`/`cheat` — no hit.
* **Full top-100k common-password list (SecLists xato 100000) swept** via the chain trick against
  `flag_decode` (~500 s), `rename_session` (~209 s) and `cheat` (~212 s) — **all no hit**.
  An English dictionary sweep (`words_alpha.txt`, 370k) is downloaded in `lists/` and can be run
  with `python dict_sweep.py words` if desired (not yet run).
* Port scan of the challenge host: only 4444 is reachable (80/443/8000/8080/8081/... all filtered).
  The catalog is NOT externally exposed.
* Catalog DLLs are identical across sessions (no per-session customisation).
* Format-string probes in password/name (`%s%n%p...`) → clean 401s, catalog unaffected.
* Double-decoded traversal via `%2e%2e%2f` names (`%` is allowed in names, `..` literal is blocked):
  all 404, no second decode anywhere (params or path).
* Planting small marker files in our sandbox under many special names (`cheat`, `cheat.bin`,
  `rename_session`, ...) does not change `cheat`'s 500 → catalog does not read the session sandbox.
* `help`'s /list cache is only produced once per session (no override) and is never re-read elsewhere.

1. **Read the two hidden `/list` columns.** They are the most deliberate piece of hidden data in the
   protocol (renderer requires 2 tabs, hides fields 2-3). A leak of session memory at
   `session+0x8c8` is needed; the only candidate is `history` (SipHash) — look for:
   * any way to make a capability print raw session bytes (recheck `chain`'s `%.*s` paths etc.);
   * a way to make SipHash input/output useful (key leak, or a slot whose value we control and can
     compare — slot 47 = `{0, wants_args}` is fully known, but that only gives a PRF pair).
2. **Reconsider `/GS` bypass for base64_decode/parse_json** — is the invalid-parameter handler or
   `__security_check_cookie` ever neutralised in the worker (imports say no)? Any way to leak the
   cookie (module .data) without a raw read? Any *partial* overflow that changes control-relevant
   data before the check? (Both functions call only `malloc`/`memcpy`/`strcpy_s` after the write.)
3. **`secret-var` remains unexplained.** It is deliberately obfuscated in the blocker filename, and
   the whole FSM-cipher/arena-tag apparatus exists only to consume it. Look for a *consumer we can
   reach*: e.g. a capability that compares the keystream/tag, or `dump_cipher_state` being invoked
   indirectly. (api[15] unreachable from the 14 loadable caps — maybe from `cheat`.)
4. **`cheat` 500**: try to find the one condition that turns it into 200 (its password? session
   format? catalog state?). Everything controllable through `/load` has been varied except the
   hidden `session` override (api[4], only rename_session).
5. If the above stalls: consider `parse_json`'s overflow as a way to run a *fixed* `cmd.exe` line
   with a fully quoted argument — the only remaining user-controlled content there is the raw
   `dir` path (no metachars). Not currently seen as exploitable.

---

## 5. Tooling / repro notes

* `loot/` has all 14 loadable DLLs (downloaded via `easy_load` + `file_download`).
* `decompiled/` has Ghidra C for all 14 (plus `whoami`, `flag_decode`, `easy_load`, `file_transfer`).
* `pe_analyze.py` (strings/xrefs/disasm for cmdwrap.exe), `dll_disas.py` (DLL disasm),
  `tools_decode_strings.py` (XOR string tables), `decomp_one.bat` (Ghidra headless) are all working.
* Scripts used this session: `recon2/3.py`, `probe1/2/4/5/6/7.py`, `blocker.py` (secret-var recovery),
  `sv_test.py`, `sv_decode.py`, `sv_raw.py`, `brute1/2/3.py`, `plant.py`, `plant2.py`.
* Ghidra 12.1.3 at
  `%LOCALAPPDATA%\Temp\claude\C--Users-mingy-Documents-Projects-TISC-2026\744ac648-5c5e-402e-9bec-074b911ba1f1\scratchpad\ghidra_12.1.3_PUBLIC`;
  `JAVA_HOME=C:\Program Files\Android\Android Studio\jbr`.
* Remote allows **3 concurrent sessions per IP**; 4th+ get blocked (blocker mechanic above).

# casphash

C11 command-line verifier for locally supplied `WPA*01` PMKID and `WPA*02`
EAPOL handshake records and password masks. Requires OpenSSL 3.0+ libcrypto,
CMake 3.17+, and a POSIX system
(macOS or Linux).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./output/casphash examples/demo.pmkid 'CaspDemo?d'
./output/casphash examples/demo.hc22000 'CaspDemo?d'
```

Masks support literal characters and `?u` (uppercase), `?l` (lowercase),
`?d` (digits), `?s` (symbols), `?c` (letters), and `?a` (letters, digits,
symbols). Use `??` for a literal question mark. Quote masks so the shell does not
expand them. Candidate lengths are limited to 1–63 bytes; candidates are
generated in bounded batches of at most 128.

## Wordlists and background use

```sh
./output/casphash examples/demo.hc22000 --wordlist wordlists/turkish.txt
hashcat --stdout -a 0 words.txt -r custom.rule | ./output/casphash examples/demo.hc22000 --wordlist -
```

Wordlists are read as byte strings, one candidate per line. LF/CRLF endings are
removed; spaces are preserved. Empty, NUL-containing and >63-byte candidates are
skipped and counted. Each candidate is tested against all unmatched records;
stdin is consumed once, including for multi-record files. Malformed hash input
fails before candidate testing. Searching stops early when all records match.

Wordlist mode emits line-buffered `PROGRESS`, `MATCH` and `SUMMARY` records for
background clients. MATCH includes the original hash-file line number and
`password_hex`, preserving non-UTF-8 candidate bytes. The scanner's lower CaspHash
panel decodes these results, supports wordlists, rule files, custom rule text and
masks, and manages background processes and cancellation. Hashcat is used only
to expand rules; CaspHash owns password verification.
Progress includes monotonic search time in `seconds`. Mask progress includes
`aggregate=1`, the shared candidate search size (`space`), record counts (`matched`
and `total`), and a search-completion flag (`finished`). One mask candidate checks
all unmatched records, so `tested` and `space` count candidates once, regardless
of the number of records. The scanner understands both this protocol and older
per-record mask progress.

## General and router wordlists

- `wordlists/general-wordlist.txt`: 106,868 lines of general password candidates,
  including common words, names, numeric sequences and keyboard patterns.
- `wordlists/routers.txt`: 167 lines of router-related candidates, including
  administrator passwords, vendor terms and default-credential strings. These
  are candidate strings, not a verified mapping of passwords to router models
  or a list limited to Wi-Fi passphrases.

Run either list directly, without Hashcat or a rule file:

```sh
./output/casphash output/capture.hc22000 --wordlist wordlists/general-wordlist.txt
./output/casphash output/capture.hc22000 --wordlist wordlists/routers.txt
```

Use a converted hash file as described under Scanner captures. Each line is
tried literally; rules are applied only when expanded separately with Hashcat.
Both lists are copied unchanged from the sibling project's `wordlists/`
directory. Line counts include any duplicates or entries skipped by the
verifier's input limits.

## Turkish wordlist and presets

`wordlists/turkish.txt` contains 548,530 UTF-8 entries: Turkish vocabulary,
names, places, football terms, and curated university, political and historical
terms. This collection is not a measured password
frequency ranking.

`rules/turkish.rule` expands base words with capitalization, numeric suffixes,
years, punctuation, selected prefixes and ASCII substitutions. Recent years
2015–2026 are prioritized. CaspHash accepts candidates, so use Hashcat to expand
the rules and pipe its output into the verifier:

```sh
hashcat --stdout -a 0 --wordlist-autohex-disable wordlists/turkish.txt -r rules/turkish.rule | ./output/casphash output/capture.hc22000 --wordlist -
```

Use a converted hash file as shown under Scanner captures. Hashcat is required
only for rule expansion; the plain wordlist command needs no Hashcat. The full
rule expansion produces billions of candidates, including repeats. Unicode
case variants are stored in the wordlist because byte-based case rules cannot
reliably construct Turkish casing. Short bases are retained for suffix expansion;
normal WPA passphrases are 8–63 bytes.

`rules/turkish-mobile.rule` contains 208 standard Hashcat rules. Each input
must be exactly seven ASCII digits, including leading zeros. The rules prepend
530–555, with and without a leading `0`, and emit each number plain or ending
in `!`, `.` or `*`. For example, `1234567` produces `5301234567`,
`05301234567!`, and equivalents through prefix 555. The rules do not generate
or validate the seven-digit inputs themselves.

Generate the seven-digit base list (10 million lines, about 80 MB), then stream
its rule expansion into CaspHash:

```sh
hashcat --stdout -a 3 --markov-disable '?d?d?d?d?d?d?d' > output/mobile-seven-digits.txt
hashcat --stdout -a 0 --wordlist-autohex-disable output/mobile-seven-digits.txt -r rules/turkish-mobile.rule | ./output/casphash output/capture.hc22000 --wordlist -
```

This covers 2,080,000,000 candidates; only the base list is stored on disk.
Use a smaller list of seven-digit strings to restrict the search. Run the mobile
rules separately from `turkish.rule` and `wordlists/turkish.txt`: combining rule
files composes transformations, and the vocabulary is not seven-digit input.
CaspHash reads the expanded candidates through stdin; it does not parse rules.
These are numeric patterns, not a validation of allocated mobile prefixes.

The bundled wordlist is copied from the sibling project's `wordlists/turkish.txt`;
`turkish.rule` is copied unchanged from its `rules/` directory. CaspHash's mobile
rule file replaces that project's scanner-specific marker with standard
[Hashcat prepend/append rules](https://hashcat.net/wiki/doku.php?id=rule_based_attack).
The sibling CaspScanner marker remains unchanged. Source
snapshots and checksums are recorded in `wordlists/sources.json`; upstream MIT
notices are retained in `wordlists/licenses/`. Curated terms supplement the
dictionary, name and geography sources. No Python tooling is required or bundled.

## Layout

- `source/`: C source code.
- `output/`: compiled executable, generated by CMake.
- `build/`: CMake build files.
- `examples/`: synthetic input records.
- `wordlists/`: bundled Turkish vocabulary, source manifest and license notices.
- `rules/`: Turkish vocabulary and mobile-number Hashcat rules.

## Scanner captures

Convert the saved capture before passing it to the verifier:

```sh
hcxpcapngtool -o output/capture.hc22000 /path/to/your-capture.pcapng
./output/casphash output/capture.hc22000 'CaspDemo?d'
```

Conversion requires `hcxpcapngtool` from hcxtools on PATH. Choose a new output
path and check that conversion extracted usable records before running the
verifier. Raw pcap/pcapng input to the C verifier is rejected with a conversion
hint.

A usable EAPOL message pair and the exact SSID are required; all four handshake
messages are not required. The updated scanner keeps beacon/probe-response frames
alongside EAPOL so conversion can obtain the SSID. Older EAPOL-only captures may
lack that information. Empty captures cannot be recovered by conversion.

## Supported EAPOL records

Uses the [hc22000 text format](https://hashcat.net/forum/thread-10253-post-53276.html):
`WPA*02*MIC*AP_MAC*CLIENT_MAC*SSID_HEX*OTHER_NONCE*EAPOL_HEX*MESSAGE_PAIR`.
The separate nonce is normally ANonce; records containing an AP M3 instead
carry SNonce there. Both nonce and MAC ordering are handled.

- Descriptor version 1: HMAC-MD5 MIC (WPA).
- Descriptor version 2: truncated HMAC-SHA1 MIC (WPA2).
- Descriptor version 3: SHA256 PTK derivation and AES-128-CMAC MIC (WPA2 PSK-SHA256).

Mixed PMKID/EAPOL files are accepted. EAPOL headers, lengths, hex fields,
message-pair direction and nonce presence are validated before searching.
The MIC field is zeroed for verification. Missing nonces and unsupported
descriptor versions fail explicitly. Nonce-error correction, WPA3-SAE, FT,
and enterprise authentication are not implemented. Records with nonce-correction
flags are checked against their exact recorded nonces, with a warning.

## Synthetic demo

`examples/demo.pmkid` is generated from these fictional values:

| Field | Value |
| --- | --- |
| Wi-Fi name (SSID) | `CaspDemoWiFi` |
| Access point MAC | `02:00:00:00:00:01` |
| Client MAC | `02:00:00:00:00:02` |
| Password | `CaspDemo7` |
| Search mask | `CaspDemo?d` |

The example command above searches ten candidates and prints
`Match found with password: CaspDemo7`. No real network capture is needed.
`examples/demo.hc22000` is an EAPOL example using the same SSID and password.

Each record uses `WPA*01*PMKID*AP_MAC*CLIENT_MAC*SSID_HEX*` followed by any
remaining fields. Hex fields are validated; SSIDs may contain embedded zero
bytes. Unsupported or malformed records produce a nonzero exit status.
A valid search with no match exits successfully and reports no password found.
Empty files and files with no usable records return a nonzero exit status.

The C port corrects the original PMKID message buffer overflow (the message
is 20 bytes), checks OpenSSL failures, and avoids materializing the complete
mask expansion in memory. Verification uses a persistent POSIX CPU worker pool. By default it uses the
online logical CPU count, capped at 32. Override with a trailing `--threads N`
(1–32) in either search mode; `--threads 1` runs on the coordinator thread.
No GPU backend is used.

For each candidate, PBKDF2-HMAC-SHA1 derives one PMK per unique SSID (exact bytes
and length), then reuses it for all unmatched PMKID/EAPOL records in that group.
The required 4,096 iterations are unchanged. PMKs are local to a worker's current
candidate; there is no persistent password/PMK cache.

Workers verify batches of at most 128 candidates. The coordinator publishes
matches in input order and only once per record. `tested` counts committed
candidates; a final batch may speculatively verify later candidates that are
not counted after an early match. A pipe with an incomplete batch is processed
without waiting for more lines or EOF. Memory is bounded by the input records
and one batch, independent of wordlist/mask search size. SIGTERM stops all worker
threads with the verifier process, preserving scanner cancellation.

```sh
./output/casphash examples/demo.hc22000 'CaspDemo?d' --threads 4
```

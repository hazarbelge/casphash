# CPU workers and PMK reuse — 2026-11-04

Implemented and rebuilt the scanner's `output/casphash` verifier. Both mask and
wordlist modes use a persistent POSIX worker pool, with a default of the online
logical CPU count (8 here), capped at 32. A trailing `--threads 1–32` overrides it.
Each candidate derives one PMK per exact SSID byte string and length; that PMK
is reused across the group's unmatched PMKID/EAPOL records. The 4,096 PBKDF2
iterations and verification algorithms are unchanged.

## Measurements

Apple M2, 4 performance + 4 efficiency cores, native ARM64 release binaries,
`-O3 -DNDEBUG`, OpenSSL 3. The Python runner itself was x86_64; both executables
were confirmed ARM64 using `file`. Each cell is candidates/sec, with speedup
relative to the preserved pre-change executable in parentheses. One candidate
checks **all** records in the workload, including in the old per-record mask
search; this normalization includes the benefit of PMK reuse.

Median of three process-wall-time trials with 1,000 nonmatching synthetic
candidates each. Variants were rotated between trials. Startup is included.
Normal desktop/background activity remained running; this is not an idle-machine
or sustained thermal benchmark. Four same-SSID records mix PMKID with EAPOL
versions 1/2/3; four distinct-SSID records are PMKIDs.

| Workload | Mode | Original | 1 worker | 2 workers | 4 workers | 8 workers (default) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| single_pmkid | mask | 638 | 643 (1.01×) | 1,230 (1.93×) | 1,577 (2.47×) | 1,435 (2.25×) |
| single_pmkid | wordlist | 629 | 731 (1.16×) | 990 (1.57×) | 1,462 (2.32×) | 1,812 (2.88×) |
| single_eapol | mask | 606 | 648 (1.07×) | 1,349 (2.22×) | 1,830 (3.02×) | 1,834 (3.02×) |
| single_eapol | wordlist | 838 | 837 (1.00×) | 1,264 (1.51×) | 2,460 (2.94×) | 2,486 (2.97×) |
| same_ssid_mixed_4 | mask | 218 | 857 (3.92×) | 1,656 (7.58×) | 2,420 (11.08×) | 2,485 (11.38×) |
| same_ssid_mixed_4 | wordlist | 240 | 990 (4.12×) | 1,810 (7.53×) | 2,704 (11.25×) | 2,611 (10.86×) |
| distinct_ssid_4 | mask | 235 | 245 (1.04×) | 445 (1.89×) | 684 (2.91×) | 652 (2.77×) |
| distinct_ssid_4 | wordlist | 242 | 232 (0.96×) | 414 (1.71×) | 583 (2.41×) | 646 (2.67×) |

At eight workers, single-record searches improved 2.25–3.02×, four same-SSID
records improved 10.86–11.38×, and four distinct-SSID records improved 2.67–2.77×.
Same-SSID reuse alone yielded 3.92–4.12× at one worker. Four workers were slightly
faster than eight in some trials; the best setting depends on machine/load.
One-worker distinct-SSID wordlist throughput was about 4% lower than baseline in
these short trials, so this change is not a universal single-core speedup.

Raw trials, executable SHA-256 values, and provenance are in
[`workers-benchmark.json`](workers-benchmark.json). The original executable is
also preserved at `output/casphash-before-workers` (generated/ignored output).

Reproduce from the casphash directory:

```sh
python3 -B tools/benchmark_workers.py --baseline output/casphash-before-workers --output results/workers-benchmark-rerun.json
```

## Correctness and integration

Passed:

- Existing independent synthetic CLI checks (PMKID, all MIC algorithms, mask
  classes, nonce/MAC ordering, malformed inputs, and missing input handling).
- 5 wordlist tests and 5 capture-conversion tests.
- 7 new worker tests, covering 1/2/8 workers, mixed algorithms, shared and
  distinct SSIDs, embedded NUL/non-UTF-8 bytes, empty SSIDs, candidate boundaries,
  nonadjacent groups, batch boundaries, deterministic counters, duplicate-match
  suppression, early stop, partial matches, and exact exhaustion.
- Open-stdin early match without waiting for EOF; repeated worker startup/join;
  process cancellation. Existing scanner cancellation also reaps the verifier
  and rule generator.
- 12 scanner-job/ETA tests, including shared-mask progress and compatibility
  with old per-record progress, rule expansion, and capture conversion.
- 5 native-Python Tk panel tests, including background result handling, elapsed
  time, stopped-run ETA, and shutdown. The x86 Python lacked Tk; the same tests
  passed with `/opt/homebrew/bin/python3`.
- UndefinedBehaviorSanitizer worker suite (7 tests), with nonrecovering errors.
- Release compiler warnings and `git diff --check`/cached whitespace checks.

That is 34 release unittest cases plus the standalone synthetic CLI suite;
UBSan reran the 7 worker cases separately.

## Ownership and remaining limits

The coordinator alone reads input and changes record match state. Workers read
an immutable batch snapshot and write separate candidate result rows. The
coordinator waits for all workers before consuming results in input order.
Groups and result storage are released after joining all created workers;
partial thread-start failure joins already-created workers before cleanup.
Wordlists remain streamed; storage is bounded by records plus a 128-candidate
batch. Final batches may compute candidates beyond an early match; `tested`
counts committed candidates and excludes that speculative suffix.

Mask progress now marks `aggregate=1` and counts the shared candidate space once.
The scanner metrics code handles it while retaining support for legacy progress.
Restart an already-running scanner to load the updated Python metrics handling.

ASan/TSan were **not validated**: ASan startup timed out and TSan crashed before
main, including minimal standalone `puts()` smoke executables. UBSan passed.
Clang's static analyzer also emitted two errno-model warnings and a possible
stream-leak warning at pool initialization failure. The stream warning's
ownership path was reviewed: every opened wordlist is closed on that failure,
while borrowed stdin is left open. These diagnostics are not counted as a clean
static-analyzer pass. No Linux execution, manual real-capture GUI run, sustained
thermal test, or GPU backend validation was performed.

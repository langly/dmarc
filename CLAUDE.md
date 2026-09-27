# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Not a git repo or a package: a working folder of DMARC aggregate (RUA) reports for the user's domains, plus one stdlib-only script, `dmarc_report.py`, that summarizes them. `dmarc-summary.html` is generated output. Report files are named the way the senders name them (`<reporter>!<domain>!<begin-epoch>!<end-epoch>.{xml,zip,xml.gz}`).

## Running

No dependencies, no build, no tests. System Python here is 3.9, so keep syntax 3.9-compatible (`X | None` only works in annotations because of `from __future__ import annotations`).

```sh
python3 dmarc_report.py                    # scan . recursively, print summary, write dmarc-summary.html
python3 dmarc_report.py some.zip other.xml # specific files
python3 dmarc_report.py --no-html          # terminal summary only
python3 dmarc_report.py --json agg.json    # also dump the aggregate dict
python3 dmarc_report.py --rdns             # reverse-DNS sending IPs (network calls)
python3 dmarc_report.py --spf              # classify sources as yours/other from live SPF (runs `dig`)
python3 dmarc_report.py --mine 203.0.113.10 # same split, hosts given by hand (repeatable, CIDR ok)
```

To check a change, run the script against this folder and compare the terminal summary / open the HTML.

## Architecture of dmarc_report.py

A single pipeline in `main()`: `collect` → `aggregate` → (`resolve_rdns`) → `print_summary` / `render_html` / JSON.

- **Parsing**: `extract_xml` yields `(label, bytes)` from a `.zip` (every `.xml` inside), `.gz`, or `.xml`. `parse_report` turns XML into `Report`/`Record` dataclasses. Bad input is warned about on stderr and skipped, never raised.
- **Dedup**: reports are deduplicated on `(org.lower(), report_id)`, so the same report arriving as both `.xml` and `.zip` is counted once.
- **Pass/fail semantics**: `Record.aligned_pass` uses the receiver's `policy_evaluated` dkim/spf results (which already mean pass-and-aligned). "Aligned" counters use those; the `*_raw` counters use the unaligned `auth_results`.
- **Aggregation**: `aggregate` returns one plain dict (with `defaultdict`s and `set`s) keyed by totals, `by_day`, `by_source` (per IP), `by_org`, `by_domain`, `policies` (most recent published policy per domain), `reasons`. The terminal, HTML, and JSON outputs all read from this dict, so a new metric goes there first. The JSON writer converts sets and defaultdicts itself.
- **Yours vs other**: `classify_sources` sets `mine` on each `by_source` entry and fills `fail_mine`/`fail_other`, but only when `--spf`/`--mine` is given (`agg["classified"]`). `spf_networks` follows include/redirect and resolves a/mx through `dig`, because stdlib has no TXT lookup. Per-source `fail_details` counts *only failing* records, so passing records' auth results don't muddy the diagnosis.
- **HTML**: built from f-strings with inline `CSS`/`JS` constants. There are no external assets, so the file stays self-contained. Everything interpolated from reports must go through `esc()`. Tooltips are HTML stored in `data-tt` attributes and shown by the small JS block. The CSS uses color tokens on `:root` with dark-mode overrides for both `prefers-color-scheme` and `[data-theme]`, so new colors need all three definitions.

## Gotcha

`collect` filters on the file extension (`.xml`, `.zip`, `.gz`, `.gzip`), so files with odd names (e.g. a truncated name with no real extension) are silently skipped even when they are valid zips. Passing such a file on the command line doesn't help, because the same suffix check applies to explicit paths. Rename it to `.zip` instead. `extract_xml` itself would read it, since it detects zips by content with `zipfile.is_zipfile`.

# DMARC report summarizer

`dmarc_report.py` reads DMARC aggregate (RUA) reports, the XML files that mailbox providers email to the `rua=` address in your DMARC record, and summarizes them. It prints a report in the terminal and writes a self-contained HTML dashboard.

It uses only the Python standard library (3.9+). You don't need to install anything.

## Quick start

Put the reports in this folder, in whatever form they arrived (`.xml`, `.xml.gz`, or `.zip`), and run:

```sh
python3 dmarc_report.py
```

The script scans the current directory recursively, prints a summary, and writes `dmarc-summary.html`.

## Usage

```sh
python3 dmarc_report.py [paths ...] [options]
```

| Option | What it does |
| --- | --- |
| `paths` | Files or directories to read. The default is `.` |
| `-o`, `--out PATH` | Where to write the HTML dashboard. The default is `dmarc-summary.html` |
| `--no-html` | Print the terminal summary only |
| `--json PATH` | Also write the aggregated data as JSON |
| `--no-recursive` | Don't descend into subdirectories |
| `--rdns` | Look up the reverse DNS of each sending IP. This makes network calls |
| `--spf` | Fetch your domains' live SPF records (using `dig`) to separate your own senders from everyone else |
| `--mine IP_OR_CIDR` | Mark an address or network as your own sender. You can repeat it, and use it with or without `--spf` |

Examples:

```sh
python3 dmarc_report.py reports/ -o out.html     # a specific directory and output file
python3 dmarc_report.py --spf --rdns             # split your hosts from others and name the IPs
python3 dmarc_report.py --mine 192.0.2.0/24      # list your sending hosts yourself
python3 dmarc_report.py --no-html --json agg.json
```

## What you get

- **Totals** for the period covered: the number of reports and messages, the DMARC pass/fail rate, SPF and DKIM alignment, and the dispositions the receivers applied (none, quarantine, or reject).
- **Published policy** for each domain (`p`, `sp`, `pct`, `adkim`, `aspf`), taken from the most recent report.
- **Sending sources**: every IP that sent mail as your domains, with its message count and pass rates. If you use `--rdns`, each IP also shows its hostname.
- **Failures**: the sources that fail DMARC, with the SPF and DKIM results of only their failing messages. If you use `--spf` or `--mine`, the failures are split in two:
  - *Your hosts failing DMARC.* These are configuration problems for you to fix, such as missing DKIM signing or an incomplete SPF record.
  - *Other senders failing DMARC.* These are usually spoofing or forwarded mail, and your policy is doing its job on them.
- **HTML dashboard**: the same data with a timeline and tooltips. It is a single file with no external assets, and it supports light and dark mode.

"Aligned" results come from the receiver's `policy_evaluated` verdict, which already means that the check passed *and* aligned with the From domain. The unaligned SPF and DKIM results are tracked separately.

## Notes

- If the same report arrives twice, for example as both `.xml` and `.zip`, it is counted once. Duplicates are identified by reporting organization and report ID.
- The script warns about unreadable or malformed files on stderr and skips them.
- Files are selected by extension (`.xml`, `.zip`, `.gz`, `.gzip`). This also applies to paths you pass on the command line. A report whose file name was truncated, and so lost its extension, is skipped. Rename it to `.zip` to include it.
- `--spf` needs `dig` on your `PATH`. It follows `include:` and `redirect=`, and resolves `a` and `mx` mechanisms.
- Report files and generated output contain real domains and IP addresses, so `.gitignore` excludes them.

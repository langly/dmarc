#!/usr/bin/env python3
"""Aggregate DMARC aggregate (RUA) reports into a summary + HTML dashboard.

Reads DMARC aggregate reports as .xml, .xml.gz, or .zip (the three forms
mailbox providers send), de-duplicates by report id, and emits a terminal
summary plus a self-contained HTML dashboard.

    ./dmarc_report.py                    # scan ., write dmarc-summary.html
    ./dmarc_report.py reports/ -o d.html # scan a directory, choose the output
    ./dmarc_report.py --rdns             # also reverse-resolve sending IPs
    ./dmarc_report.py --spf              # mark sources your SPF authorizes as yours
    ./dmarc_report.py --mine 192.0.2.0/24  # ...or list your hosts yourself
    ./dmarc_report.py --no-html          # terminal summary only
"""

from __future__ import annotations

import argparse
import gzip
import html
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    pol_dkim: str
    pol_spf: str
    header_from: str
    envelope_from: str
    envelope_to: str
    dkim: list  # [(domain, result, selector)]
    spf: list  # [(domain, result, scope)]
    reasons: list  # [(type, comment)]

    @property
    def aligned_pass(self) -> bool:
        """DMARC passes when either identifier passes *and* aligns."""
        return self.pol_dkim == "pass" or self.pol_spf == "pass"


@dataclass
class Report:
    org: str
    email: str
    report_id: str
    begin: int
    end: int
    domain: str
    policy: dict
    source_file: str
    records: list = field(default_factory=list)

    @property
    def key(self):
        return (self.org.lower(), self.report_id)

    @property
    def messages(self) -> int:
        return sum(r.count for r in self.records)


def _text(node, path, default=""):
    if node is None:
        return default
    found = node.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def parse_report(data: bytes, source_file: str) -> Report | None:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        print(f"  ! skipping {source_file}: malformed XML ({exc})", file=sys.stderr)
        return None
    if root.tag != "feedback":
        print(f"  ! skipping {source_file}: not a DMARC report", file=sys.stderr)
        return None

    meta = root.find("report_metadata")
    pol = root.find("policy_published")

    report = Report(
        org=_text(meta, "org_name", "unknown"),
        email=_text(meta, "email"),
        report_id=_text(meta, "report_id"),
        begin=int(_text(meta, "date_range/begin", "0") or 0),
        end=int(_text(meta, "date_range/end", "0") or 0),
        domain=_text(pol, "domain", "unknown"),
        policy={
            "p": _text(pol, "p"),
            "sp": _text(pol, "sp"),
            "pct": _text(pol, "pct"),
            "adkim": _text(pol, "adkim"),
            "aspf": _text(pol, "aspf"),
            "np": _text(pol, "np"),
        },
        source_file=source_file,
    )

    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        ids = rec.find("identifiers")
        auth = rec.find("auth_results")

        dkim, spf = [], []
        if auth is not None:
            for d in auth.findall("dkim"):
                dkim.append(
                    (_text(d, "domain"), _text(d, "result"), _text(d, "selector"))
                )
            for s in auth.findall("spf"):
                spf.append((_text(s, "domain"), _text(s, "result"), _text(s, "scope")))

        reasons = []
        if pe is not None:
            for r in pe.findall("reason"):
                reasons.append((_text(r, "type"), _text(r, "comment")))

        try:
            count = int(_text(row, "count", "0") or 0)
        except ValueError:
            count = 0

        report.records.append(
            Record(
                source_ip=_text(row, "source_ip", "?"),
                count=count,
                disposition=_text(pe, "disposition", "none") or "none",
                pol_dkim=_text(pe, "dkim", "fail") or "fail",
                pol_spf=_text(pe, "spf", "fail") or "fail",
                header_from=_text(ids, "header_from"),
                envelope_from=_text(ids, "envelope_from"),
                envelope_to=_text(ids, "envelope_to"),
                dkim=dkim,
                spf=spf,
                reasons=reasons,
            )
        )
    return report


def extract_xml(path: Path):
    """Yield (label, xml-bytes) for every report inside a file."""
    suf = path.suffixes
    name = path.name
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir() or not info.filename.lower().endswith(".xml"):
                        continue
                    yield f"{name}::{Path(info.filename).name}", zf.read(info)
            return
        if suf and suf[-1].lower() in (".gz", ".gzip"):
            with gzip.open(path, "rb") as fh:
                yield name, fh.read()
            return
        if suf and suf[-1].lower() == ".xml":
            yield name, path.read_bytes()
    except (OSError, zipfile.BadZipFile, gzip.BadGzipFile, EOFError) as exc:
        print(f"  ! cannot read {name}: {exc}", file=sys.stderr)


def collect(paths, recursive=True):
    """Load every report found under the given files/directories."""
    reports, seen, dupes = [], {}, 0
    candidates = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            candidates += sorted(f for f in it if f.is_file())
        elif p.is_file():
            candidates.append(p)
        else:
            print(f"  ! no such path: {p}", file=sys.stderr)

    for f in candidates:
        if f.suffix.lower() not in (".xml", ".zip", ".gz", ".gzip"):
            continue
        for label, data in extract_xml(f):
            rep = parse_report(data, label)
            if rep is None:
                continue
            if rep.key in seen:
                dupes += 1
                continue
            seen[rep.key] = label
            reports.append(rep)
    reports.sort(key=lambda r: (r.begin, r.org))
    return reports, dupes


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def aggregate(reports):
    agg = {
        "messages": 0,
        "pass": 0,
        "fail": 0,
        "spf_aligned": 0,
        "dkim_aligned": 0,
        "spf_raw": 0,
        "dkim_raw": 0,
        "dispositions": defaultdict(int),
        "by_day": defaultdict(lambda: {"pass": 0, "fail": 0, "fail_ips": defaultdict(int)}),
        "by_source": {},
        "by_org": defaultdict(lambda: {"messages": 0, "reports": 0}),
        "by_domain": defaultdict(lambda: {"messages": 0, "pass": 0, "fail": 0}),
        "policies": {},
        "reasons": defaultdict(int),
        "classified": False,  # set by classify_sources
        "authorized": [],
        "fail_mine": 0,
        "fail_other": 0,
        "begin": None,
        "end": None,
    }

    for rep in reports:
        agg["by_org"][rep.org]["reports"] += 1
        agg["by_org"][rep.org]["messages"] += rep.messages
        if rep.domain not in agg["policies"] or rep.begin >= agg["policies"][rep.domain]["begin"]:
            agg["policies"][rep.domain] = dict(rep.policy, begin=rep.begin, org=rep.org)
        if rep.begin:
            agg["begin"] = rep.begin if agg["begin"] is None else min(agg["begin"], rep.begin)
        if rep.end:
            agg["end"] = rep.end if agg["end"] is None else max(agg["end"], rep.end)

        day = (
            datetime.fromtimestamp(rep.begin, timezone.utc).strftime("%Y-%m-%d")
            if rep.begin
            else "unknown"
        )

        for rec in rep.records:
            n = rec.count
            ok = rec.aligned_pass
            agg["messages"] += n
            agg["pass" if ok else "fail"] += n
            agg["by_day"][day]["pass" if ok else "fail"] += n
            if not ok:
                agg["by_day"][day]["fail_ips"][rec.source_ip] += n
            agg["dispositions"][rec.disposition] += n
            if rec.pol_spf == "pass":
                agg["spf_aligned"] += n
            if rec.pol_dkim == "pass":
                agg["dkim_aligned"] += n
            if any(r[1] == "pass" for r in rec.spf):
                agg["spf_raw"] += n
            if any(r[1] == "pass" for r in rec.dkim):
                agg["dkim_raw"] += n
            for rtype, comment in rec.reasons:
                agg["reasons"][rtype or "unspecified"] += n

            d = agg["by_domain"][rec.header_from or rep.domain]
            d["messages"] += n
            d["pass" if ok else "fail"] += n

            src = agg["by_source"].setdefault(
                rec.source_ip,
                {
                    "ip": rec.source_ip,
                    "messages": 0,
                    "pass": 0,
                    "fail": 0,
                    "spf_aligned": 0,
                    "dkim_aligned": 0,
                    "dispositions": defaultdict(int),
                    "header_from": set(),
                    "dkim_domains": set(),
                    "spf_domains": set(),
                    "orgs": set(),
                    "rdns": "",
                    "mine": None,
                    "fail_details": defaultdict(int),
                },
            )
            src["messages"] += n
            src["pass" if ok else "fail"] += n
            if rec.pol_spf == "pass":
                src["spf_aligned"] += n
            if rec.pol_dkim == "pass":
                src["dkim_aligned"] += n
            src["dispositions"][rec.disposition] += n
            if rec.header_from:
                src["header_from"].add(rec.header_from)
            for dom, res, sel in rec.dkim:
                src["dkim_domains"].add(f"{dom}{'/' + sel if sel else ''} {res}")
            for dom, res, _s in rec.spf:
                src["spf_domains"].add(f"{dom} {res}")
            src["orgs"].add(rep.org)
            if not ok:
                src["fail_details"][fail_detail(rec)] += n

    return agg


def fail_detail(rec):
    """One line describing why a failing record failed, for grouping."""
    dkim = ", ".join(f"{d}{'/' + s if s else ''} {r}" for d, r, s in rec.dkim) or "unsigned"
    spf = ", ".join(f"{d} {r}{' (' + sc + ')' if sc else ''}" for d, r, sc in rec.spf) or "none"
    return (
        f"from {rec.header_from or '?'}, envelope {rec.envelope_from or '-'}"
        f" | dkim: {dkim} | spf: {spf}"
    )


# --------------------------------------------------------------------------
# Which sources are yours
# --------------------------------------------------------------------------


def _dig(name, rtype):
    try:
        out = subprocess.run(
            ["dig", "+short", rtype, name], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"  ! dig {rtype} {name} failed: {exc}", file=sys.stderr)
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _host_networks(host, prefix4=32, prefix6=128):
    nets = []
    for rtype, plen in (("A", prefix4), ("AAAA", prefix6)):
        for ans in _dig(host, rtype):
            try:  # skip CNAME lines
                nets.append(ipaddress.ip_network(f"{ans}/{plen}", strict=False))
            except ValueError:
                pass
    return nets


def spf_networks(domain, _depth=0, _seen=None):
    """Networks a domain's SPF record authorizes with a pass ('+') qualifier.

    Follows include:/redirect= and resolves a/mx mechanisms. exists:/ptr and
    macros are ignored, which is fine for listing your own senders.
    """
    seen = set() if _seen is None else _seen
    if _depth > 10 or domain.lower() in seen:
        return []
    seen.add(domain.lower())
    txts = ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', t)) or t for t in _dig(domain, "TXT")]
    records = [t for t in txts if t.lower().split()[:1] == ["v=spf1"]]
    if not records:
        print(f"  ! no SPF record for {domain}", file=sys.stderr)
        return []

    nets = []
    for term in records[0].split()[1:]:
        if term.lower().startswith("redirect="):
            nets += spf_networks(term.split("=", 1)[1], _depth + 1, seen)
            continue
        qual = "+"
        if term[:1] in "+-~?":
            qual, term = term[0], term[1:]
        if qual != "+":
            continue
        mech, _, arg = term.partition(":")
        mech = mech.lower()
        # a/24 and mx//64 style prefixes may sit on the mechanism or the argument
        if "/" in mech:
            mech, _, cidr = mech.partition("/")
        else:
            arg, _, cidr = arg.partition("/")
        p4, _, p6 = cidr.partition("/")
        try:
            p4, p6 = int(p4 or 32), int(p6 or 128)
            if mech in ("ip4", "ip6"):
                nets.append(ipaddress.ip_network(term.split(":", 1)[1], strict=False))
            elif mech == "a":
                nets += _host_networks(arg or domain, p4, p6)
            elif mech == "mx":
                for ans in _dig(arg or domain, "MX"):
                    nets += _host_networks(ans.split()[-1].rstrip("."), p4, p6)
            elif mech == "include":
                nets += spf_networks(arg, _depth + 1, seen)
        except ValueError:
            print(f"  ! {domain}: cannot parse SPF term {term!r}", file=sys.stderr)
    return nets


def parse_networks(values):
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            print(f"  ! --mine: not an IP or CIDR: {v}", file=sys.stderr)
    return nets


def classify_sources(agg, networks):
    """Mark each source as yours (inside `networks`) or another sender's."""
    agg["classified"] = True
    agg["authorized"] = sorted({str(n) for n in networks})
    for src in agg["by_source"].values():
        try:
            ip = ipaddress.ip_address(src["ip"])
        except ValueError:
            ip = None
        src["mine"] = ip is not None and any(ip in n for n in networks)
        agg["fail_mine" if src["mine"] else "fail_other"] += src["fail"]
    for v in agg["by_day"].values():
        v["fail_mine"] = sum(n for ip, n in v["fail_ips"].items() if agg["by_source"][ip]["mine"])


def resolve_rdns(agg, timeout=1.5):
    socket.setdefaulttimeout(timeout)
    for ip, src in agg["by_source"].items():
        try:
            src["rdns"] = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            src["rdns"] = ""
    socket.setdefaulttimeout(None)


# --------------------------------------------------------------------------
# Terminal summary
# --------------------------------------------------------------------------


def pct(n, d):
    return 0.0 if not d else 100.0 * n / d


def fmt_range(agg):
    if not agg["begin"]:
        return "unknown window"
    b = datetime.fromtimestamp(agg["begin"], timezone.utc)
    e = datetime.fromtimestamp(agg["end"] or agg["begin"], timezone.utc)
    if b.date() == e.date():
        return b.strftime("%Y-%m-%d (UTC)")
    return f"{b:%Y-%m-%d} to {e:%Y-%m-%d} (UTC)"


def print_summary(reports, agg, dupes):
    total = agg["messages"]
    line = "-" * 72
    print()
    print(f"DMARC aggregate summary  |  {fmt_range(agg)}")
    print(line)
    print(f"  Reports ingested   {len(reports)}" + (f"  ({dupes} duplicate(s) skipped)" if dupes else ""))
    print(f"  Reporting orgs     {', '.join(sorted(agg['by_org'])) or '-'}")
    print(f"  Messages seen      {total}")
    print(f"  DMARC pass         {agg['pass']}  ({pct(agg['pass'], total):.1f}%)")
    print(f"  DMARC fail         {agg['fail']}  ({pct(agg['fail'], total):.1f}%)")
    print(f"  SPF aligned        {agg['spf_aligned']}  ({pct(agg['spf_aligned'], total):.1f}%)")
    print(f"  DKIM aligned       {agg['dkim_aligned']}  ({pct(agg['dkim_aligned'], total):.1f}%)")
    disp = ", ".join(f"{k}={v}" for k, v in sorted(agg["dispositions"].items())) or "-"
    print(f"  Dispositions       {disp}")

    print()
    print("Published policy")
    print(line)
    for dom, p in sorted(agg["policies"].items()):
        print(
            f"  {dom:<28} p={p['p'] or '-'} sp={p['sp'] or '-'} pct={p['pct'] or '-'} "
            f"adkim={p['adkim'] or '-'} aspf={p['aspf'] or '-'}"
        )

    print()
    print("Sending sources")
    print(line)
    cls = agg["classified"]
    if cls:
        print(f"  Your hosts: {', '.join(agg['authorized']) or 'none found'}")
    hdr = f"  {'source ip':<20} {'msgs':>6} {'dmarc':>7} {'spf':>6} {'dkim':>6}  header-from"
    if cls:
        hdr = f"  {'':<5} {hdr.lstrip()}"
    print(hdr)
    for src in sorted(agg["by_source"].values(), key=lambda s: -s["messages"]):
        n = src["messages"]
        who = (f"{'yours' if src['mine'] else 'other':<5} " if cls else "")
        print(
            f"  {who}{src['ip']:<20} {n:>6} "
            f"{pct(src['pass'], n):>6.0f}% "
            f"{pct(src['spf_aligned'], n):>5.0f}% "
            f"{pct(src['dkim_aligned'], n):>5.0f}%  "
            f"{', '.join(sorted(src['header_from'])) or '-'}"
            + (f"  [{src['rdns']}]" if src["rdns"] else "")
        )

    fails = sorted((s for s in agg["by_source"].values() if s["fail"]), key=lambda s: -s["fail"])
    if cls:
        groups = [
            ("Your hosts failing DMARC: fix your signing/SPF", [s for s in fails if s["mine"]]),
            ("Other senders failing DMARC: spoofing or forwarding", [s for s in fails if not s["mine"]]),
        ]
    else:
        groups = [("Needs attention (messages failing DMARC)", fails)]
    for title, group in groups:
        if not group:
            continue
        print()
        print(f"{title}  ({sum(s['fail'] for s in group)} msgs)")
        print(line)
        for src in group:
            print(f"  {src['ip']:<20} {src['fail']:>6} failing"
                  + (f"  [{src['rdns']}]" if src["rdns"] else ""))
            for d, cnt in sorted(src["fail_details"].items(), key=lambda kv: -kv[1]):
                print(f"      {cnt:>4} x  {d}")
    if cls and not fails:
        print()
        print("No messages failing DMARC.")
    print()


# --------------------------------------------------------------------------
# HTML dashboard
# --------------------------------------------------------------------------

CSS = """
:root{
  color-scheme: light;
  --plane:#f9f9f7; --surface:#fcfcfb;
  --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,.10);
  --series-1:#2a78d6;
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --good-wash:rgba(12,163,12,.10); --crit-wash:rgba(208,59,59,.10);
  --series-wash:rgba(42,120,214,.10);
  --wash:rgba(11,11,11,.04);
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --plane:#0d0d0d; --surface:#1a1a19;
    --ink:#fff; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,.10);
    --series-1:#3987e5;
    --good-wash:rgba(12,163,12,.16); --crit-wash:rgba(208,59,59,.16);
    --series-wash:rgba(57,135,229,.18);
    --wash:rgba(255,255,255,.05);
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --plane:#0d0d0d; --surface:#1a1a19;
  --ink:#fff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,.10);
  --series-1:#3987e5;
  --good-wash:rgba(12,163,12,.16); --crit-wash:rgba(208,59,59,.16);
  --series-wash:rgba(57,135,229,.18);
  --wash:rgba(255,255,255,.05);
}

*{box-sizing:border-box}
body{
  margin:0; background:var(--plane); color:var(--ink);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1080px; margin:0 auto; padding:40px 24px 72px}
header.top{margin-bottom:28px}
h1{font-size:22px; font-weight:600; letter-spacing:-.01em; margin:0 0 6px}
.sub{color:var(--ink-2); font-size:13px; margin:0}
.sub b{color:var(--ink); font-weight:600}
h2{font-size:13px; font-weight:600; letter-spacing:.04em; text-transform:uppercase;
   color:var(--ink-2); margin:36px 0 12px}
.card{background:var(--surface); border:1px solid var(--ring); border-radius:10px; padding:18px 20px}
details.fold > summary{list-style:none; cursor:pointer}
details.fold > summary::-webkit-details-marker{display:none}
details.fold > summary h2{display:inline-flex; align-items:center; gap:8px}
details.fold > summary h2::after{content:""; width:6px; height:6px; margin-top:-3px;
   border:solid currentColor; border-width:0 2px 2px 0; transform:rotate(45deg); transition:transform .15s}
details.fold[open] > summary h2::after{transform:rotate(-135deg); margin-top:3px}
details.fold > summary:hover h2{color:var(--ink)}
details.fold > summary .count{font-weight:400; text-transform:none; letter-spacing:0}

/* stat tiles */
.tiles{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px}
.tile{background:var(--surface); border:1px solid var(--ring); border-radius:10px; padding:16px 18px}
.tile .label{font-size:12px; color:var(--ink-2); margin-bottom:8px}
.tile .value{font-size:30px; line-height:1.1; font-weight:600; letter-spacing:-.02em}
.tile .note{font-size:12px; color:var(--muted); margin-top:6px}
.meter{height:4px; border-radius:2px; background:var(--wash); margin-top:12px; overflow:hidden}
.meter span{display:block; height:100%; border-radius:2px}

/* timeline */
.chart{padding:20px 20px 8px}
.plotwrap{overflow-x:auto; overflow-y:hidden; padding-top:18px}
.plot{display:flex; align-items:flex-end; height:180px;
      border-bottom:1px solid var(--axis); padding-bottom:0; position:relative}
.gridline{position:absolute; left:0; right:0; height:1px; background:var(--grid)}
.gridline b{position:absolute; left:0; top:-16px; font:11px/1 system-ui,sans-serif;
            color:var(--muted); font-weight:400; font-variant-numeric:tabular-nums}
.col{flex:1 1 0; min-width:14px; max-width:48px; display:flex; flex-direction:column;
     justify-content:flex-end; height:100%; position:relative; cursor:default}
.col .stack{display:flex; flex-direction:column; justify-content:flex-end; gap:2px; height:100%}
.seg{border-radius:0; min-height:2px}
.stack > .seg:first-child{border-radius:4px 4px 0 0}
.seg.pass{background:var(--series-1)}
.seg.fail{background:var(--critical)}
.seg.fail-other{background:var(--serious)}
.xaxis{display:flex; margin-top:8px; padding-bottom:12px}
.xaxis div{flex:1 1 0; min-width:14px; max-width:48px; text-align:center;
           font-size:11px; color:var(--muted); font-variant-numeric:tabular-nums;
           overflow:hidden; white-space:nowrap}

/* legend */
.legend{display:flex; flex-wrap:wrap; gap:16px; margin:0 0 14px; font-size:12px; color:var(--ink-2)}
.legend span{display:inline-flex; align-items:center; gap:6px}
.swatch{width:10px; height:10px; border-radius:2px; display:inline-block}

/* tables */
table{width:100%; border-collapse:collapse; font-size:13px}
.scroll{overflow-x:auto}
th{text-align:left; font-weight:600; font-size:11px; letter-spacing:.04em;
   text-transform:uppercase; color:var(--muted); padding:0 12px 8px 0;
   border-bottom:1px solid var(--grid); white-space:nowrap}
td{padding:10px 12px 10px 0; border-bottom:1px solid var(--grid); vertical-align:top}
tr:last-child td{border-bottom:0}
th.num,td.num{text-align:right; font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px}
.dim{color:var(--muted); font-size:12px}
.volbar{height:4px; border-radius:2px; background:var(--series-1); margin-top:5px; min-width:2px}

/* chips */
.chip{display:inline-flex; align-items:center; gap:5px; padding:2px 8px; border-radius:999px;
      font-size:12px; font-weight:500; white-space:nowrap}
.chip.ok{background:var(--good-wash); color:var(--good)}
.chip.bad{background:var(--crit-wash); color:var(--critical)}
.chip.warn{background:rgba(250,178,25,.16); color:#8a5c00}
.chip.mine{background:var(--series-wash); color:var(--series-1)}
.chip.other{background:var(--wash); color:var(--ink-2)}
:root[data-theme="dark"] .chip.warn{color:var(--warning)}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]) .chip.warn{color:var(--warning)}
}

.note{font-size:12.5px; color:var(--ink-2); margin:10px 0 0}
.attn{border-left:2px solid var(--critical); padding-left:14px; margin:10px 0 0}
.attn.other{border-left-color:var(--axis)}
.attn-group + .attn-group{margin-top:22px}
.attn-group h4{font-size:12px; font-weight:600; color:var(--ink-2); margin:0}
.attn h3{font-size:13px; margin:0 0 4px; font-weight:600}
.attn ul{margin:4px 0 0; padding-left:18px; color:var(--ink-2); font-size:12.5px}
footer{margin-top:40px; color:var(--muted); font-size:12px}

#tt{position:fixed; pointer-events:none; opacity:0; transition:opacity .1s;
    background:var(--surface); color:var(--ink); border:1px solid var(--ring);
    border-radius:8px; padding:8px 10px; font-size:12px; line-height:1.45;
    box-shadow:0 6px 24px rgba(0,0,0,.14); z-index:9; max-width:260px}
#tt b{font-weight:600}
#tt .r{display:flex; justify-content:space-between; gap:14px; font-variant-numeric:tabular-nums}
"""

JS = """
(function(){
  var tt=document.getElementById('tt');
  function show(e){
    var t=e.currentTarget.getAttribute('data-tt'); if(!t) return;
    tt.innerHTML=t; tt.style.opacity=1; move(e);
  }
  function move(e){
    var r=tt.getBoundingClientRect();
    var x=Math.min(e.clientX+14, window.innerWidth-r.width-8);
    var y=Math.max(8, e.clientY-r.height-12);
    tt.style.left=x+'px'; tt.style.top=y+'px';
  }
  function hide(){ tt.style.opacity=0; }
  document.querySelectorAll('[data-tt]').forEach(function(el){
    el.addEventListener('mouseenter',show);
    el.addEventListener('mousemove',move);
    el.addEventListener('mouseleave',hide);
    el.addEventListener('focus',function(e){show({currentTarget:el,clientX:el.getBoundingClientRect().left+20,clientY:el.getBoundingClientRect().top});});
    el.addEventListener('blur',hide);
  });
})();
"""


def esc(s):
    return html.escape(str(s), quote=True)


def chip(ok, label):
    cls = "ok" if ok else "bad"
    mark = "&#10003;" if ok else "&#10007;"
    return f'<span class="chip {cls}">{mark} {esc(label)}</span>'


def tile(label, value, note="", meter=None, color="var(--series-1)"):
    m = ""
    if meter is not None:
        m = (
            f'<div class="meter"><span style="width:{max(0.0, min(100.0, meter)):.1f}%;'
            f'background:{color}"></span></div>'
        )
    n = f'<div class="note">{note}</div>' if note else ""
    return (
        f'<div class="tile"><div class="label">{esc(label)}</div>'
        f'<div class="value">{value}</div>{n}{m}</div>'
    )


def render_timeline(agg):
    days = sorted(d for d in agg["by_day"] if d != "unknown")
    if len(days) < 2:
        return ""
    peak = max(agg["by_day"][d]["pass"] + agg["by_day"][d]["fail"] for d in days) or 1
    cls = agg["classified"]
    cols, labels = [], []
    for d in days:
        v = agg["by_day"][d]
        tot = v["pass"] + v["fail"]
        hp = 100.0 * v["pass"] / peak
        hf = 100.0 * v["fail"] / peak
        segs = ""
        tt = (
            f"<b>{esc(d)}</b>"
            f'<div class="r"><span>Messages</span><span>{tot}</span></div>'
            f'<div class="r"><span>DMARC pass</span><span>{v["pass"]} ({pct(v["pass"], tot):.0f}%)</span></div>'
        )
        if cls:
            fm, fo = v["fail_mine"], v["fail"] - v["fail_mine"]
            if fm:
                segs += f'<div class="seg fail" style="height:{100.0 * fm / peak:.2f}%"></div>'
            if fo:
                segs += f'<div class="seg fail-other" style="height:{100.0 * fo / peak:.2f}%"></div>'
            tt += (
                f'<div class="r"><span>Fail, your hosts</span><span>{fm} ({pct(fm, tot):.0f}%)</span></div>'
                f'<div class="r"><span>Fail, other senders</span><span>{fo} ({pct(fo, tot):.0f}%)</span></div>'
            )
        else:
            if v["fail"]:
                segs += f'<div class="seg fail" style="height:{hf:.2f}%"></div>'
            tt += f'<div class="r"><span>DMARC fail</span><span>{v["fail"]} ({pct(v["fail"], tot):.0f}%)</span></div>'
        if v["pass"]:
            segs += f'<div class="seg pass" style="height:{hp:.2f}%"></div>'
        cols.append(f'<div class="col" tabindex="0" data-tt="{esc(tt)}"><div class="stack">{segs}</div></div>')
        labels.append(d)

    grid = "".join(
        f'<div class="gridline" style="bottom:{f:.0f}%"><b>{int(peak * f / 100)}</b></div>'
        for f in (100, 50)
    )
    # Keep bars legible past a few weeks: thin the gap, then let the track scroll.
    gap = 10 if len(days) <= 20 else 6 if len(days) <= 45 else 3
    every = 1 if len(days) <= 20 else 3 if len(days) <= 45 else 7
    labels = [
        f"<div>{esc(d[5:]) if i % every == 0 else '&nbsp;'}</div>"
        for i, d in enumerate(labels)
    ]
    track = f"min-width:{len(days) * (14 + gap)}px; gap:{gap}px"
    if cls:
        legend_fail = (
            '<span><i class="swatch" style="background:var(--critical)"></i>&#10007; Fail from your hosts</span>'
            '<span><i class="swatch" style="background:var(--serious)"></i>&#10007; Fail from other senders</span>'
        )
    else:
        legend_fail = '<span><i class="swatch" style="background:var(--critical)"></i>&#10007; DMARC fail</span>'
    return f"""
<h2>Volume over time</h2>
<div class="card chart">
  <div class="legend">
    <span><i class="swatch" style="background:var(--series-1)"></i>&#10003; DMARC pass</span>
    {legend_fail}
  </div>
  <div class="plotwrap">
    <div class="plot" style="{track}">{grid}{''.join(cols)}</div>
    <div class="xaxis" style="{track}">{''.join(labels)}</div>
  </div>
</div>"""


def render_html(reports, agg, dupes, out_path):
    total = agg["messages"] or 1
    p_pass = pct(agg["pass"], total)
    domains = sorted(agg["policies"])
    peak_src = max((s["messages"] for s in agg["by_source"].values()), default=1) or 1

    tiles = "".join(
        [
            tile("Messages seen", f"{agg['messages']:,}",
                 f"from {len(agg['by_source'])} sending source"
                 f"{'s' if len(agg['by_source']) != 1 else ''}"),
            tile("DMARC pass rate", f"{p_pass:.1f}%",
                 f"{agg['pass']:,} pass &middot; {agg['fail']:,} fail",
                 meter=p_pass, color="var(--good)" if p_pass >= 95 else "var(--critical)"),
            tile("SPF aligned", f"{pct(agg['spf_aligned'], total):.1f}%",
                 f"{agg['spf_aligned']:,} of {agg['messages']:,}",
                 meter=pct(agg["spf_aligned"], total)),
            tile("DKIM aligned", f"{pct(agg['dkim_aligned'], total):.1f}%",
                 f"{agg['dkim_aligned']:,} of {agg['messages']:,}",
                 meter=pct(agg["dkim_aligned"], total)),
        ]
    )
    if agg["classified"]:
        tiles += tile("Failing from your hosts", f"{agg['fail_mine']:,}",
                      f"{agg['fail_other']:,} failing from other senders")

    # policy panel
    prow = "".join(
        f"<tr><td class='mono'>{esc(d)}</td>"
        f"<td><span class='chip {'ok' if p['p'] == 'reject' else 'warn' if p['p'] == 'quarantine' else 'bad'}'>"
        f"p={esc(p['p'] or '-')}</span></td>"
        f"<td class='mono dim'>sp={esc(p['sp'] or '-')}</td>"
        f"<td class='mono dim'>pct={esc(p['pct'] or '-')}</td>"
        f"<td class='mono dim'>adkim={esc(p['adkim'] or '-')}</td>"
        f"<td class='mono dim'>aspf={esc(p['aspf'] or '-')}</td></tr>"
        for d, p in sorted(agg["policies"].items())
    )

    # sources
    srows = []
    for s in sorted(agg["by_source"].values(), key=lambda s: -s["messages"]):
        n = s["messages"]
        w = 100.0 * n / peak_src
        disp = ", ".join(f"{k} {v}" for k, v in sorted(s["dispositions"].items()))
        tt = (
            f"<b>{esc(s['ip'])}</b>"
            + (f"<div class='dim'>{esc(s['rdns'])}</div>" if s["rdns"] else "")
            + f'<div class="r"><span>Messages</span><span>{n}</span></div>'
            f'<div class="r"><span>Pass / fail</span><span>{s["pass"]} / {s["fail"]}</span></div>'
            f'<div class="r"><span>Disposition</span><span>{esc(disp)}</span></div>'
            + "".join(f"<div class='dim'>dkim: {esc(x)}</div>" for x in sorted(s["dkim_domains"]))
            + "".join(f"<div class='dim'>spf: {esc(x)}</div>" for x in sorted(s["spf_domains"]))
        )
        dmarc_chip = chip(s["fail"] == 0, f"{pct(s['pass'], n):.0f}% pass")
        spf_chip = chip(s["spf_aligned"] == n, f"{pct(s['spf_aligned'], n):.0f}%")
        dkim_chip = chip(s["dkim_aligned"] == n, f"{pct(s['dkim_aligned'], n):.0f}%")
        who = ""
        if agg["classified"]:
            who = ('<td><span class="chip mine">yours</span></td>' if s["mine"]
                   else '<td><span class="chip other">other</span></td>')
        srows.append(
            f'<tr tabindex="0" data-tt="{esc(tt)}">{who}'
            f"<td class='mono'>{esc(s['ip'])}"
            + (f"<div class='dim'>{esc(s['rdns'])}</div>" if s["rdns"] else "")
            + "</td>"
            f"<td class='num'>{n:,}<div class='volbar' style='width:{w:.1f}%'></div></td>"
            f"<td>{dmarc_chip}</td>"
            f"<td>{spf_chip}</td>"
            f"<td>{dkim_chip}</td>"
            f"<td class='mono dim'>{esc(', '.join(sorted(s['header_from'])) or '-')}</td>"
            f"<td class='dim'>{esc(disp)}</td></tr>"
        )

    # needs attention
    attn = ""
    fails = sorted((s for s in agg["by_source"].values() if s["fail"]), key=lambda s: -s["fail"])
    if fails:
        def attn_blocks(group, cls=""):
            blocks = []
            for s in group:
                detail = sorted(s["fail_details"].items(), key=lambda kv: -kv[1])
                blocks.append(
                    f"<div class='attn {cls}'><h3>{esc(s['ip'])} &mdash; {s['fail']:,} message"
                    f"{'s' if s['fail'] != 1 else ''} failing DMARC</h3>"
                    + (f"<div class='dim'>{esc(s['rdns'])}</div>" if s["rdns"] else "")
                    + "<ul>"
                    + "".join(f"<li class='mono'>{c}&times; {esc(d)}</li>" for d, c in detail)
                    + "</ul></div>"
                )
            return "".join(blocks)

        if agg["classified"]:
            mine = [s for s in fails if s["mine"]]
            other = [s for s in fails if not s["mine"]]
            groups = []
            if mine:
                groups.append(
                    "<div class='attn-group'><h4>Your hosts: fix signing or SPF</h4>"
                    + attn_blocks(mine) + "</div>")
            if other:
                groups.append(
                    "<div class='attn-group'><h4>Other senders: spoofing or forwarding"
                    " (your policy decides what happens to these)</h4>"
                    + attn_blocks(other, "other") + "</div>")
            body = "".join(groups)
        else:
            body = attn_blocks(fails)
        attn = f"<h2>Needs attention</h2><div class='card'>{body}</div>"

    # reports
    rrows = "".join(
        f"<tr><td>{esc(r.org)}</td>"
        f"<td class='mono dim'>{esc(r.report_id)}</td>"
        f"<td class='dim'>{datetime.fromtimestamp(r.begin, timezone.utc):%Y-%m-%d %H:%M} &rarr; "
        f"{datetime.fromtimestamp(r.end or r.begin, timezone.utc):%H:%M} UTC</td>"
        f"<td class='num'>{len(r.records)}</td>"
        f"<td class='num'>{r.messages:,}</td>"
        f"<td class='mono dim'>{esc(r.source_file)}</td></tr>"
        for r in reports
    )

    disp_line = " &middot; ".join(
        f"{esc(k)} <b>{v:,}</b>" for k, v in sorted(agg["dispositions"].items())
    ) or "&mdash;"

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DMARC summary &mdash; {esc(', '.join(domains) or 'reports')}</title>
<style>{CSS}</style></head><body>
<div id="tt"></div>
<div class="wrap">
<header class="top">
  <h1>DMARC aggregate summary</h1>
  <p class="sub"><b>{esc(', '.join(domains) or 'unknown domain')}</b> &middot; {esc(fmt_range(agg))}
  &middot; {len(reports)} report{'s' if len(reports) != 1 else ''} from
  {esc(', '.join(sorted(agg['by_org'])) or 'unknown')}
  {f'&middot; {dupes} duplicate file(s) skipped' if dupes else ''}</p>
</header>

<div class="tiles">{tiles}</div>

{render_timeline(agg)}

<h2>Sending sources</h2>
<div class="card scroll">
<table>
<thead><tr>{'<th>Sender</th>' if agg['classified'] else ''}<th>Source IP</th><th class="num">Messages</th><th>DMARC</th>
<th>SPF aligned</th><th>DKIM aligned</th><th>Header from</th><th>Disposition</th></tr></thead>
<tbody>{''.join(srows)}</tbody></table>
</div>

{attn}

<h2>Published policy</h2>
<div class="card scroll">
<table><tbody>{prow}</tbody></table>
<p class="note">Dispositions applied by receivers: {disp_line}</p>
</div>

<details class="fold">
<summary><h2>Reports ingested <span class="count">({len(reports)})</span></h2></summary>
<div class="card scroll">
<table>
<thead><tr><th>Reporter</th><th>Report ID</th><th>Window</th>
<th class="num">Records</th><th class="num">Messages</th><th>File</th></tr></thead>
<tbody>{rrows}</tbody></table>
</div>
</details>

<footer>Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} by dmarc_report.py.
&ldquo;Aligned&rdquo; means the identifier passed authentication <em>and</em> matched the
header-from domain &mdash; DMARC passes when either SPF or DKIM aligns.</footer>
</div>
<script>{JS}</script>
</body></html>"""
    Path(out_path).write_text(doc, encoding="utf-8")


# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Aggregate and visualize DMARC reports.")
    ap.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    ap.add_argument("-o", "--out", default="dmarc-summary.html", help="HTML output path")
    ap.add_argument("--no-html", action="store_true", help="terminal summary only")
    ap.add_argument("--json", metavar="PATH", help="also write the aggregate as JSON")
    ap.add_argument("--rdns", action="store_true", help="reverse-resolve sending IPs")
    ap.add_argument("--spf", action="store_true",
                    help="look up your domains' SPF records (via dig) to tell your hosts from others")
    ap.add_argument("--mine", action="append", default=[], metavar="IP_OR_CIDR",
                    help="treat this address/network as your own sender (repeatable)")
    ap.add_argument("--no-recursive", action="store_true", help="do not descend into subdirectories")
    args = ap.parse_args()

    reports, dupes = collect(args.paths or ["."], recursive=not args.no_recursive)
    if not reports:
        print("No DMARC reports found (.xml, .xml.gz, .zip).", file=sys.stderr)
        return 1

    agg = aggregate(reports)
    if args.spf or args.mine:
        networks = parse_networks(args.mine)
        if args.spf:
            for dom in sorted(agg["policies"]):
                networks += spf_networks(dom)
        classify_sources(agg, networks)
    if args.rdns:
        resolve_rdns(agg)

    print_summary(reports, agg, dupes)

    if args.json:
        def plain(o):
            if isinstance(o, set):
                return sorted(o)
            if isinstance(o, defaultdict):
                return dict(o)
            raise TypeError(type(o))
        Path(args.json).write_text(json.dumps(agg, indent=2, default=plain), encoding="utf-8")
        print(f"JSON written to {args.json}")

    if not args.no_html:
        render_html(reports, agg, dupes, args.out)
        print(f"Dashboard written to {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

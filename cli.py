"""MAVIS command-line entry point."""

import argparse
import json
import shutil
import sys
import textwrap
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class StageTimer:
    """Records the wall-clock duration of each named stage of a command."""

    def __init__(self) -> None:
        self.stages: list[tuple[str, float]] = []

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.monotonic()
        try:
            yield
        finally:
            self.stages.append((name, time.monotonic() - started))

    def summary(self) -> str:
        return " | ".join(f"{name}: {seconds:.1f}s" for name, seconds in self.stages)


def cmd_poll(args: argparse.Namespace) -> None:
    """Pull recent CVEs from NVD plus KEV and EPSS data into MySQL."""
    # Imported here so `--help` works without a .env or network access
    from mavis.ingest import epss, kev, nvd

    timer = StageTimer()
    started = time.monotonic()
    print(f"Polling NVD for CVEs published in the last {args.days} day(s)...")

    with timer.stage("NVD fetch"):
        rows = [nvd.parse_cve(cve) for cve in nvd.fetch_recent_cves(args.days)]
    with timer.stage("NVD save"):
        saved = nvd.save_cves(rows)
    unscored = sum(1 for row in rows if row['cvss_score'] is None)
    print(f"NVD: saved {saved} CVEs ({unscored} without a CVSS score yet)")

    # KEV lists CVEs long after publication, so fetch those separately by KEV date
    print(f"Polling NVD for CVEs added to KEV in the last {args.kev_days} day(s)...")
    with timer.stage("NVD KEV-date fetch"):
        kev_cve_rows = [nvd.parse_cve(cve) for cve in nvd.fetch_recent_kev_cves(args.kev_days)]
    with timer.stage("NVD KEV-date save"):
        saved_kev_cves = nvd.save_cves(kev_cve_rows)
    print(f"NVD: saved {saved_kev_cves} recently added KEV CVEs")

    print("Downloading the CISA KEV catalog...")
    with timer.stage("KEV fetch"):
        kev_rows = [kev.parse_kev_entry(entry) for entry in kev.fetch_kev()]
    with timer.stage("KEV save"):
        saved_kev = kev.save_kev(kev_rows)
    print(f"KEV: saved {saved_kev} known-exploited CVEs")

    # Every stored CVE, not just this poll's: EPSS is re-scored daily
    with timer.stage("CVE ID lookup"):
        cve_ids = nvd.stored_cve_ids()
    print(f"Fetching EPSS scores for {len(cve_ids)} stored CVEs...")
    with timer.stage("EPSS fetch"):
        epss_rows = [epss.parse_epss(item) for item in epss.fetch_epss(cve_ids)]
    with timer.stage("EPSS save"):
        saved_epss = epss.save_epss(epss_rows)
    print(f"EPSS: saved {saved_epss} scores ({len(cve_ids) - saved_epss} CVEs not scored by EPSS yet)")

    elapsed = time.monotonic() - started
    if args.timing:
        print(f"Timing: {timer.summary()}")
    print(f"Done in {elapsed:.1f}s")


def _match_label(row: dict[str, Any]) -> str:
    if not row['matches']:
        return ''
    return f"{', '.join(m['name'] for m in row['matches'])} ({row['match_type']})"


def format_score_table(ranked: list[dict[str, Any]], width: int) -> list[str]:
    """Render ranked CVEs as plain-ASCII table lines, cutting descriptions to fit ``width``."""
    match_width = max([len('Match')] + [len(_match_label(r)) for r in ranked])
    header = f"{'#':>3}  {'CVE':<16} {'Score':>5} {'CVSS':>5} {'EPSS':>6}  {'KEV':<3}  {'Match':<{match_width}}  "
    desc_width = max(width - len(header), 10)

    lines = [header + 'Description']
    for rank, row in enumerate(ranked, start=1):
        # '-' rather than the neutral 5.0 used for scoring, so the screen doesn't imply NVD gave it a 5
        cvss = '-' if row['cvss_score'] is None else f"{row['cvss_score']:.1f}"
        epss = '-' if row['epss'] is None else f"{row['epss']:.1%}"
        kev = 'yes' if row['in_kev'] else ''
        description = ' '.join((row['description'] or '').split())
        if len(description) > desc_width:
            description = description[:desc_width - 3] + '...'
        lines.append(
            f"{rank:>3}  {row['cve_id']:<16} {row['score']:>5.1f} {cvss:>5} {epss:>6}  {kev:<3}  "
            f"{_match_label(row):<{match_width}}  {description}"
        )
    return lines


def cmd_score(args: argparse.Namespace) -> None:
    """Score stored CVEs against the local watchlist."""
    from mavis.scoring.inputs import fetch_scoring_inputs
    from mavis.scoring.ranking import rank_cves
    from mavis.scoring.watchlist import load_watchlist

    try:
        watchlist = load_watchlist(args.watchlist)
    except FileNotFoundError:
        sys.exit(f"No watchlist found at {args.watchlist}. Create it to list the software you run "
                 "(format: see 'Watchlist' in README.md).")

    ranked = rank_cves(fetch_scoring_inputs(), watchlist)
    matched = [r for r in ranked if r['matches']]
    by_cpe = sum(1 for r in matched if r['match_type'] == 'cpe')
    in_kev = sum(1 for r in ranked if r['in_kev'])
    no_cvss = sum(1 for r in ranked if r['cvss_score'] is None)

    print(f"Scored {len(ranked):,} CVEs against {len(watchlist)} watchlist entries")
    print(f"  {in_kev} in KEV | {len(matched)} match your watchlist "
          f"({by_cpe} CPE, {len(matched) - by_cpe} keyword) | {no_cvss} without CVSS (scored as 5.0)")
    print()

    shown = (matched if args.matched else ranked)[:args.limit]
    for line in format_score_table(shown, shutil.get_terminal_size().columns):
        print(line)

    print()
    print(f"Showing top {len(shown)}. Use --limit N for more"
          + ("." if args.matched else ", --matched to show only watchlist matches."))


_ASCII_PUNCTUATION = str.maketrans({'\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
                                    '\u2013': '-', '\u2014': '-', '\u2026': '...', '\u00a0': ' '})


def _ascii(text: str) -> str:
    """Gemini likes curly quotes and dashes; the console is cp1252, so keep output plain ASCII."""
    return text.translate(_ASCII_PUNCTUATION).encode('ascii', 'replace').decode('ascii')


def format_brief(digest: dict[str, Any], local: dict[str, dict[str, Any]], width: int) -> list[str]:
    """Render a digest as wrapped plain-ASCII lines.

    ``local`` maps CVE ID to its ranked row, so the local score and watchlist match
    can be shown next to Gemini's text. They are only printed, never sent.
    """
    width = max(min(width, 100), 40)
    lines = textwrap.wrap(_ascii(digest['summary']), width) + ['']
    # Local score decides the order (as in `score`); Gemini only writes the text
    items = sorted(digest['items'], key=lambda i: local.get(i['cve_id'], {}).get('score', 0), reverse=True)
    for item in items:
        row = local.get(item['cve_id'], {})
        context = f"score {row['score']:.1f}" if row else ''
        if row.get('matches'):
            context += f" | matches {_match_label(row)}"
        lines.append(f"[{item['urgency'].upper()}] {item['cve_id']}  {context}")
        lines.extend(textwrap.wrap(_ascii(item['headline']), width, initial_indent='  ',
                                   subsequent_indent='  '))
        for label in ('what_it_is', 'why_it_matters', 'action'):
            lines.extend(textwrap.wrap(_ascii(item[label]), width, initial_indent='    ',
                                       subsequent_indent='    '))
        lines.append('')
    return lines


def cmd_brief(args: argparse.Namespace) -> None:
    """Generate a patch briefing for the top-scored CVEs."""
    from mavis import config
    from mavis.briefing import digest as digest_mod
    from mavis.briefing.boundary import build_llm_payload
    from mavis.scoring.inputs import fetch_scoring_inputs
    from mavis.scoring.ranking import rank_cves
    from mavis.scoring.watchlist import load_watchlist

    args.model = args.model or config.GEMINI_MODEL
    if not args.dry_run and not config.GEMINI_API_KEY:
        sys.exit("GEMINI_API_KEY is not set in .env (see .env.example).")
    try:
        watchlist = load_watchlist(args.watchlist)
    except FileNotFoundError:
        sys.exit(f"No watchlist found at {args.watchlist}. Create it to list the software you run "
                 "(format: see 'Watchlist' in README.md).")

    ranked = rank_cves(fetch_scoring_inputs(), watchlist)
    top = ([r for r in ranked if r['matches']] if args.matched else ranked)[:args.limit]
    if not top:
        sys.exit("Nothing to brief: no CVEs" + (" match your watchlist." if args.matched else " stored."))

    # The only data that leaves the machine; everything above stays local
    payload = build_llm_payload(top)
    if args.dry_run:
        print(f"Would send these {len(payload)} records to {args.model} (nothing was sent):")
        print(json.dumps(payload, indent=2, ensure_ascii=True))
        return

    input_hash = digest_mod.payload_hash(payload)
    cached = None if args.fresh else digest_mod.find_cached_digest(input_hash, args.model)
    if cached:
        digest, note = cached, "reused a stored digest for the same CVEs (--fresh to regenerate)"
    else:
        print(f"Sending {len(payload)} CVEs (public fields only) to {args.model}...")
        try:
            digest = digest_mod.generate_digest(payload, args.model)
        except Exception as exc:
            sys.exit(f"The digest couldn't be generated. Raw feed data is still current. ({exc})")
        digest_id = digest_mod.save_digest(payload, digest, args.model)
        note = f"saved as digest #{digest_id}"

    print()
    print(f"MAVIS patch briefing: top {len(payload)} CVEs")
    print()
    for line in format_brief(digest, {r['cve_id']: r for r in top}, shutil.get_terminal_size().columns):
        print(line)
    print(f"Sources: NVD, CISA KEV, FIRST EPSS | {args.model} | {note}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mavis", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    poll = sub.add_parser("poll", help=cmd_poll.__doc__)
    poll.add_argument("--days", type=int, default=7, help="NVD lookback window in days")
    poll.add_argument("--kev-days", type=int, default=30,
                      help="also fetch CVEs added to KEV in this many days")
    poll.add_argument("--timing", action="store_true",
                      help="print how long each fetch and save stage took")
    poll.set_defaults(func=cmd_poll)

    score = sub.add_parser("score", help=cmd_score.__doc__)
    score.add_argument("--limit", type=int, default=20, help="how many CVEs to show")
    score.add_argument("--matched", action="store_true",
                       help="only show CVEs that match the watchlist")
    score.add_argument("--watchlist", default="watchlist.yaml", help="path to the watchlist file")
    score.set_defaults(func=cmd_score)

    brief = sub.add_parser("brief", help=cmd_brief.__doc__)
    brief.add_argument("--limit", type=int, default=5, help="how many top-scored CVEs to brief")
    brief.add_argument("--matched", action="store_true",
                       help="only brief CVEs that match the watchlist")
    brief.add_argument("--watchlist", default="watchlist.yaml", help="path to the watchlist file")
    brief.add_argument("--dry-run", action="store_true",
                       help="print exactly what would be sent to Gemini, and send nothing")
    brief.add_argument("--fresh", action="store_true",
                       help="call Gemini even if a digest for the same CVEs is stored")
    brief.add_argument("--model", default=None, help="Gemini model (default: GEMINI_MODEL or gemini-flash-latest)")
    brief.set_defaults(func=cmd_brief)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

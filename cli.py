"""MAVIS command-line entry point."""

import argparse
import time


def cmd_poll(args: argparse.Namespace) -> None:
    """Pull recent CVEs from NVD plus KEV and EPSS data into MySQL."""
    # Imported here so `--help` works without a .env or network access
    from mavis.ingest import nvd

    started = time.monotonic()
    print(f"Polling NVD for CVEs published in the last {args.days} day(s)...")

    rows = [nvd.parse_cve(cve) for cve in nvd.fetch_recent_cves(args.days)]
    saved = nvd.save_cves(rows)
    unscored = sum(1 for row in rows if row['cvss_score'] is None)

    # TODO(Day 3): ingest KEV and EPSS here as well
    elapsed = time.monotonic() - started
    print(f"NVD: saved {saved} CVEs ({unscored} without a CVSS score yet) in {elapsed:.1f}s")


def cmd_score(args: argparse.Namespace) -> None:
    """Score stored CVEs against the local watchlist."""
    raise NotImplementedError


def cmd_brief(args: argparse.Namespace) -> None:
    """Generate a patch briefing for the top-scored CVEs."""
    raise NotImplementedError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mavis", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    poll = sub.add_parser("poll", help=cmd_poll.__doc__)
    poll.add_argument("--days", type=int, default=7, help="NVD lookback window in days")
    poll.set_defaults(func=cmd_poll)

    score = sub.add_parser("score", help=cmd_score.__doc__)
    score.set_defaults(func=cmd_score)

    brief = sub.add_parser("brief", help=cmd_brief.__doc__)
    brief.set_defaults(func=cmd_brief)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

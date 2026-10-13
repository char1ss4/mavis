"""MAVIS command-line entry point."""

import argparse
import time
from collections.abc import Iterator
from contextlib import contextmanager


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
    poll.add_argument("--timing", action="store_true",
                      help="print how long each fetch and save stage took")
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

"""Command-line entry point."""

import argparse
import json
import logging
from pathlib import Path

from .clients import LiveSources
from .demo import DEMO_SBOM, DemoSources
from .reports import write_reports
from .sbom import MAX_BYTES
from .triage import scan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Triage CycloneDX packages with OSV, EPSS and CISA KEV."
    )
    parser.add_argument(
        "sbom", nargs="?", type=Path, help="CycloneDX JSON path (required in live mode)"
    )
    parser.add_argument("--demo", action="store_true", help="Use synthetic offline responses")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="Export directory")
    parser.add_argument(
        "--fail-on",
        choices=["P0", "P1", "P2", "P3"],
        help="Exit 1 when findings reach this priority or higher",
    )
    args = parser.parse_args(argv)
    if not args.demo and args.sbom is None:
        parser.error("Provide an SBOM path, or use --demo.")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sources = DemoSources() if args.demo else LiveSources()
    try:
        if args.sbom:
            with args.sbom.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        else:
            raw = json.dumps(DEMO_SBOM).encode()
        if not args.demo:
            logging.info(
                "Live mode sends package identifiers and versions to OSV, and CVE IDs to FIRST."
            )
        report = scan(raw, sources)
        write_reports(report, args.output)
    except (OSError, ValueError) as exc:
        logging.error("Cannot complete scan: %s", exc)
        return 2
    finally:
        sources.close()
    print(
        f"{report['mode'].upper()} | {report['status']} | {report['summary']['findings']} findings"
    )
    print(f"Reports: {args.output.resolve()}")
    if report["status"] == "partial":
        print("Incomplete coverage: inspect components and errors in report.json.")
        return 3
    if args.fail_on and any(f["priority"] <= args.fail_on for f in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

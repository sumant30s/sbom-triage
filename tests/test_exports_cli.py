import csv
import io
import json

from sbom_triage.cli import main
from sbom_triage.demo import DEMO_SBOM, DemoSources
from sbom_triage.reports import csv_bytes, pdf_bytes, safe_cell
from sbom_triage.triage import scan


def test_csv_formula_injection():
    for value in ["=cmd()", "+cmd()", "-cmd()", "@cmd()", "  =cmd()", "\t=cmd()"]:
        assert safe_cell(value).startswith("'")
    assert safe_cell("ordinary") == "ordinary" and safe_cell(3) == 3


def test_csv_pdf_and_empty_reports(demo_bytes):
    report = scan(demo_bytes, DemoSources())
    rows = list(csv.DictReader(io.StringIO(csv_bytes(report).decode("utf-8-sig"))))
    assert len(rows) == 4 and rows[0]["priority"] == "P0"
    assert pdf_bytes(report).startswith(b"%PDF-")
    report["findings"] = []
    assert pdf_bytes(report).startswith(b"%PDF-")
    assert len(list(csv.DictReader(io.StringIO(csv_bytes(report).decode("utf-8-sig"))))) == 0


def test_cli_partial_and_saved_evidence(tmp_path):
    assert main(["--demo", "--output", str(tmp_path)]) == 3
    assert {p.name for p in tmp_path.iterdir()} == {"report.json", "report.csv", "report.pdf"}
    assert json.loads((tmp_path / "report.json").read_text())["mode"] == "demo"


def test_cli_gate_and_complete(tmp_path):
    bom = {**DEMO_SBOM, "components": DEMO_SBOM["components"][:1]}
    path = tmp_path / "input.json"
    path.write_text(json.dumps(bom))
    args = [str(path), "--demo", "--output", str(tmp_path / "reports")]
    assert main(args) == 0
    assert main(args + ["--fail-on", "P0"]) == 1


def test_cli_bad_input(tmp_path):
    assert main([str(tmp_path / "absent"), "--demo"]) == 2

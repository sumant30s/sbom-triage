"""Deterministic exports with spreadsheet-formula protection and paginated PDF."""

import csv
import io
import json
from html import escape
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

FIELDS = [
    "priority",
    "component",
    "version",
    "vulnerability",
    "severity",
    "cvss",
    "epss",
    "kev",
    "reason",
    "component_ref",
    "purl",
    "aliases",
    "review_notes",
]


def safe_cell(value):
    if isinstance(value, list):
        value = "; ".join(str(v) for v in value)
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_bytes(report: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({k: safe_cell(finding.get(k)) for k in FIELDS})
    return output.getvalue().encode("utf-8-sig")


def json_bytes(report: dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False).encode()


def pdf_bytes(report: dict) -> bytes:
    # Embed fonts for portable, consistent glyph metrics on PDF viewers.
    fonts = Path(reportlab.__file__).parent / "fonts"
    if "TriageVera" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("TriageVera", str(fonts / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("TriageVeraBold", str(fonts / "VeraBd.ttf")))
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4),
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=15 * mm,
        bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    for style_name in ("BodyText", "Normal"):
        styles[style_name].fontName = "TriageVera"
    for style_name in ("Title", "Heading2"):
        styles[style_name].fontName = "TriageVeraBold"
    styles["BodyText"].fontSize = 8
    styles["BodyText"].leading = 11
    styles["BodyText"].wordWrap = "CJK"

    def p(value):
        return Paragraph(escape(str(value)), styles["BodyText"])

    heading = "SBOM vulnerability triage"
    story = [
        Paragraph(heading, styles["Title"]),
        p(
            f"Mode: {report['mode'].upper()} | Coverage: {report['status']} | Generated: {report['generated_at']}"
        ),
        p(
            "DEMO values are synthetic training data; not current vulnerability intelligence."
            if report["mode"] == "demo"
            else "Evidence supports analyst review. This report does not establish exploitability or clinical risk."
        ),
        Spacer(1, 4 * mm),
        p(" | ".join(f"{k}: {v}" for k, v in report["summary"].items())),
        Spacer(1, 4 * mm),
    ]
    rows = [
        [
            p(s)
            for s in [
                "Priority",
                "Component / version",
                "Vulnerability",
                "CVSS",
                "EPSS",
                "KEV",
                "Reason / review",
            ]
        ]
    ]
    for finding in report["findings"]:
        rows.append(
            [
                p(finding["priority"]),
                p(f"{finding['component']} / {finding['version']}"[:200]),
                p(finding["vulnerability"][:100]),
                p(finding["cvss"] if finding["cvss"] is not None else "Unknown"),
                p(f"{finding['epss']:.2%}" if finding["epss"] is not None else "Unknown"),
                p({True: "Yes", False: "No", None: "Unknown"}[finding["kev"]]),
                p((finding["reason"] + " " + " ".join(finding["review_notes"]))[:800]),
            ]
        )
    if report["findings"]:
        table = Table(
            rows,
            colWidths=[16 * mm, 42 * mm, 39 * mm, 20 * mm, 22 * mm, 22 * mm, 104 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce9f3")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f3f6fa")],
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#7190aa")),
                ]
            )
        )
        story.append(table)
    else:
        story.append(
            p(
                "No findings returned. Review scan coverage and source errors before drawing conclusions."
            )
        )
    story.extend([Spacer(1, 5 * mm), Paragraph("Coverage and evidence notes", styles["Heading2"])])
    for component in report["components"]:
        if component["status"] in {"skipped", "error"}:
            story.append(p(f"{component['ref']}: {component['status']} - {component['issue']}"))
    for note in report["errors"] + report["limitations"]:
        story.append(p(note))
    story.append(p("Source provenance: " + json.dumps(report["sources"], ensure_ascii=True)))
    story.append(
        p(
            "Long table text may be abbreviated. See report.json for vectors, aliases, source timestamps, affected ranges and full evidence."
        )
    )

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("TriageVera", 8)
        canvas.drawString(16 * mm, 9 * mm, "SBOM Triage | Analyst review required")
        canvas.drawRightString(281 * mm, 9 * mm, str(doc.page))
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def write_reports(report: dict, directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in [
        ("report.json", json_bytes(report)),
        ("report.csv", csv_bytes(report)),
        ("report.pdf", pdf_bytes(report)),
    ]:
        (directory / name).write_bytes(data)

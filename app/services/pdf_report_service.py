from __future__ import annotations

from html import escape
from pathlib import Path
import re
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


TACTIC_BY_TECHNIQUE_PREFIX = {
    "T1003": "Credential Access",
    "T1027": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1041": "Exfiltration",
    "T1047": "Execution",
    "T1053": "Persistence",
    "T1055": "Defense Evasion",
    "T1068": "Privilege Escalation",
    "T1070": "Defense Evasion",
    "T1082": "Discovery",
    "T1090": "Command and Control",
    "T1105": "Command and Control",
    "T1112": "Defense Evasion",
    "T1115": "Collection",
    "T1129": "Execution",
    "T1134": "Privilege Escalation",
    "T1486": "Impact",
    "T1489": "Impact",
    "T1497": "Defense Evasion",
    "T1505": "Persistence",
    "T1547": "Persistence",
    "T1555": "Credential Access",
    "T1562": "Defense Evasion",
    "T1564": "Defense Evasion",
    "T1573": "Command and Control",
}


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clean_text(value: Any) -> str:
    if isinstance(value, str):
        text = value
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        text = re.sub(r"__([^_]+)__", r"\1", text)
        text = re.sub(r"`([^`]+)`", r"\1", text)
        text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", text)
        return re.sub(r"\s+", " ", text).strip()
    return ""


def _split_numbered_items(text: str) -> list[str]:
    if not text:
        return []
    normalized = _clean_text(text).replace("\r", "\n")
    normalized = re.sub(r"\s+(\d+\.\s+)", r"\n\1", normalized)
    parts = re.split(r"(?:^|\n)\s*\d+\.\s+", normalized)
    if len(parts) > 1:
        return [_clean_text(p) for p in parts if _clean_text(p)]
    lines = [re.sub(r"^\s*[-*]\s*", "", line).strip() for line in normalized.split("\n")]
    return [line for line in lines if line]


def _extract_technique_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text or "")))


class PDFReportService:
    """Generate professional Sandbox + AI PDF reports (no Parse data)."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self.theme = {
            "primary": colors.HexColor("#00FF88"),
            "secondary": colors.HexColor("#0088FF"),
            "accent": colors.HexColor("#FF0088"),
            "teal": colors.HexColor("#00D4AA"),
            "deep_blue": colors.HexColor("#0066CC"),
            "warn": colors.HexColor("#F59E0B"),
            "danger": colors.HexColor("#EF4444"),
            "muted_bg": colors.HexColor("#F8FAFC"),
            "panel_bg": colors.HexColor("#ECFFF5"),
            "line": colors.HexColor("#D1D5DB"),
            "text": colors.HexColor("#111827"),
        }
        workspace_root = Path(__file__).resolve().parents[3]
        self.watermark_logo_path = workspace_root / "chameleon-frontend" / "public" / "text_wo_bg.png"
        self.logo_candidates = [
            workspace_root / "chameleon-frontend" / "public" / "Logo_wo_bg.png",
            workspace_root / "chameleon-frontend" / "public" / "text_wo_bg.png",
        ]

        self.styles.add(
            ParagraphStyle(
                name="ChTitle",
                parent=self.styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=20,
                textColor=colors.HexColor("#0B1F36"),
                spaceAfter=8,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChSubtitle",
                parent=self.styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                textColor=colors.HexColor("#0B1F36"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChHeading",
                parent=self.styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13.4,
                textColor=colors.HexColor("#0B1F36"),
                spaceBefore=10,
                spaceAfter=7,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChBody",
                parent=self.styles["BodyText"],
                fontName="Helvetica",
                fontSize=9.6,
                leading=13.8,
                textColor=colors.HexColor("#1F2937"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChMuted",
                parent=self.styles["BodyText"],
                fontName="Helvetica",
                fontSize=8.6,
                leading=11.8,
                textColor=colors.HexColor("#4B5563"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChKpiLabel",
                parent=self.styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=7.6,
                leading=10,
                textColor=colors.HexColor("#334155"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChKpiValue",
                parent=self.styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=14,
                leading=16,
                textColor=colors.HexColor("#0F172A"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChTableHeader",
                parent=self.styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=8.2,
                leading=10.5,
                textColor=colors.HexColor("#111827"),
                wordWrap="CJK",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChTableCell",
                parent=self.styles["BodyText"],
                fontName="Helvetica",
                fontSize=8.4,
                leading=11.2,
                textColor=colors.HexColor("#1F2937"),
                wordWrap="CJK",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ChBullet",
                parent=self.styles["BodyText"],
                fontName="Helvetica",
                fontSize=8.9,
                leading=12.2,
                leftIndent=10,
                bulletIndent=2,
                textColor=colors.HexColor("#1F2937"),
            )
        )

    def generate_pdf_report(
        self,
        analysis: dict[str, Any],
        cape_report: dict[str, Any] | None,
        ai_report: dict[str, Any] | None,
    ) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=17 * mm,
            rightMargin=17 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"Chameleon Analysis Report - {analysis.get('analysis_id', 'N/A')}",
            author="Chameleon",
            subject="Sandbox and AI malware analysis report",
        )

        cape_data = _safe_dict(cape_report.get("data") if cape_report else {})
        ai_results = _safe_dict(ai_report.get("results") if ai_report else {})
        ai_final = self._get_ai_final(ai_results)

        story: list[Any] = []
        story.extend(self._build_cover(analysis, cape_data, ai_final, ai_report))
        story.extend(self._build_compact_brief(analysis, cape_data, ai_results, ai_final))
        story.extend(self._build_executive_summary(ai_final))
        story.append(Spacer(1, 2.4 * mm))
        story.extend(self._build_behavior_section(cape_data))
        story.append(Spacer(1, 2.4 * mm))
        story.extend(self._build_ai_section(ai_results, ai_final))
        story.append(Spacer(1, 2.4 * mm))
        story.extend(self._build_mitre_section(cape_data, ai_final))
        story.append(Spacer(1, 2.4 * mm))
        story.extend(self._build_threat_intel_and_iocs(cape_data, ai_final))
        story.extend(self._build_mitigation_section(ai_final))

        generated_at = datetime.now(timezone.utc)

        def on_page(canvas, _: Any) -> None:
            canvas.saveState()

            # Light watermark using text-based brand logo.
            if self.watermark_logo_path.exists():
                try:
                    if hasattr(canvas, "setFillAlpha"):
                        canvas.setFillAlpha(0.07)
                    wm_width = 96 * mm
                    wm_height = 20 * mm
                    canvas.drawImage(
                        str(self.watermark_logo_path),
                        (A4[0] - wm_width) / 2,
                        (A4[1] - wm_height) / 2,
                        width=wm_width,
                        height=wm_height,
                        preserveAspectRatio=True,
                        mask="auto",
                    )
                    if hasattr(canvas, "setFillAlpha"):
                        canvas.setFillAlpha(1)
                except Exception:
                    pass

            # Premium frame and top accent lines.
            frame_x = 11 * mm
            frame_y = 14 * mm
            frame_w = A4[0] - (22 * mm)
            frame_h = A4[1] - (28 * mm)
            canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
            canvas.setLineWidth(0.65)
            canvas.roundRect(frame_x, frame_y, frame_w, frame_h, 2.6 * mm, fill=0, stroke=1)

            canvas.setStrokeColor(colors.HexColor("#0EA5A4"))
            canvas.setLineWidth(1.2)
            canvas.line(16 * mm, A4[1] - 14 * mm, A4[0] - 16 * mm, A4[1] - 14 * mm)
            canvas.setStrokeColor(colors.HexColor("#93C5FD"))
            canvas.setLineWidth(0.45)
            canvas.line(16 * mm, A4[1] - 15.5 * mm, A4[0] - 16 * mm, A4[1] - 15.5 * mm)

            # Header metadata.
            canvas.setFillColor(colors.HexColor("#0F172A"))
            canvas.setFont("Helvetica-Bold", 8.2)
            canvas.drawString(16 * mm, A4[1] - 11.5 * mm, "CHAMELEON INTELLIGENCE REPORT")
            canvas.setFillColor(colors.HexColor("#475569"))
            canvas.setFont("Helvetica", 7.3)
            canvas.drawRightString(
                A4[0] - 16 * mm,
                A4[1] - 11.5 * mm,
                f"ID: {str(analysis.get('analysis_id', 'N/A'))[:36]}",
            )

            # Footer metadata.
            canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
            canvas.setLineWidth(0.5)
            canvas.line(16 * mm, 14 * mm, A4[0] - 16 * mm, 14 * mm)
            canvas.setFillColor(colors.HexColor("#475569"))
            canvas.setFont("Helvetica", 7.5)
            canvas.drawString(16 * mm, 10.4 * mm, f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%SZ')}")
            canvas.drawRightString(
                A4[0] - 16 * mm,
                10.4 * mm,
                f"Page {canvas.getPageNumber()}",
            )
            canvas.restoreState()

        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        return buffer.getvalue()

    def _build_cover(
        self,
        analysis: dict[str, Any],
        cape_data: dict[str, Any],
        ai_final: dict[str, Any],
        ai_report: dict[str, Any] | None,
    ) -> list[Any]:
        logo = self._build_logo_flowable()
        info = _safe_dict(cape_data.get("info"))
        target_file = _safe_dict(_safe_dict(cape_data.get("target")).get("file"))
        confidence = ai_final.get("threat_confidence_score")
        confidence_score = float(confidence) if isinstance(confidence, (int, float)) else 0.0
        sandbox_score = float(cape_data.get("malscore", 0) or 0)
        processes_count = len(_safe_list(_safe_dict(cape_data.get("behavior")).get("processes")))
        ioc_map = self._extract_iocs(
            cape_data, _safe_dict(_safe_dict(cape_data.get("behavior")).get("summary"))
        )
        ioc_count = sum(len(v) for v in ioc_map.values())

        meta_rows = [
            ["Analysis ID", analysis.get("analysis_id", "N/A")],
            ["Filename", analysis.get("filename", "Unknown")],
            ["SHA256", target_file.get("sha256", "N/A")],
            ["SHA1", target_file.get("sha1", "N/A")],
            ["MD5", target_file.get("md5", "N/A")],
            ["Sandbox Verdict", cape_data.get("malstatus", "Unknown")],
            ["AI Threat Level", ai_final.get("overall_threat_level", "Unknown")],
            [
                "AI Confidence",
                f"{confidence}%" if isinstance(confidence, (int, float)) else "Not available",
            ],
            ["Runtime (sec)", str(info.get("duration", "N/A"))],
            ["AI Sections", str(len(_safe_list((ai_report or {}).get("sections_analyzed"))))],
        ]

        meta_table = Table(self._as_table_data(meta_rows), colWidths=[45 * mm, 120 * mm])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D8EEE8")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1F2937")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C7D2D0")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FBFA")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        kpi_cards = Table(
            [
                [
                    self._kpi_cell("SANDBOX SCORE", f"{sandbox_score:.1f}/10"),
                    self._kpi_cell("AI CONFIDENCE", f"{confidence_score:.0f}%"),
                    self._kpi_cell("PROCESSES", str(processes_count)),
                    self._kpi_cell("IP IOCs", str(ioc_count)),
                ]
            ],
            colWidths=[40 * mm, 40 * mm, 40 * mm, 40 * mm],
        )
        kpi_cards.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), self.theme["panel_bg"]),
                    ("BOX", (0, 0), (-1, -1), 0.25, self.theme["line"]),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, self.theme["line"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )

        risk_chart = self._build_dual_risk_chart(sandbox_score, confidence_score)

        return [
            logo,
            Spacer(1, 3 * mm),
            Paragraph("Cybersecurity Analysis Report", self.styles["ChTitle"]),
            Paragraph("Scope: sandbox behavioral telemetry + AI synthesis only", self.styles["ChMuted"]),
            Spacer(1, 4 * mm),
            kpi_cards,
            Spacer(1, 3 * mm),
            Paragraph("Risk Profile", self.styles["ChSubtitle"]),
            risk_chart,
            Spacer(1, 2 * mm),
            meta_table,
            Spacer(1, 4 * mm),
        ]

    def _build_executive_summary(self, ai_final: dict[str, Any]) -> list[Any]:
        report = _safe_dict(ai_final.get("report"))
        confidence_assessment = _safe_dict(ai_final.get("confidence_assessment"))
        exec_summary = _clean_text(report.get("executive_summary"))
        integrated = _clean_text(report.get("integrated_threat_assessment"))
        if not exec_summary and not integrated:
            return [Paragraph("Executive Summary", self.styles["ChHeading"]), Paragraph("AI executive summary is not available for this analysis.", self.styles["ChBody"])]

        threat_level = _clean_text(ai_final.get("overall_threat_level") or "Unknown")
        confidence = ai_final.get("threat_confidence_score", "N/A")
        badge = self._severity_chip(threat_level)

        matrix_rows = [
            ["Threat Level", badge],
            ["Confidence", f"{confidence}%" if isinstance(confidence, (int, float)) else str(confidence)],
            [
                "Evidence Convergence",
                _clean_text(confidence_assessment.get("evidence_convergence_level") or "Not specified"),
            ],
            [
                "Forensic Completeness",
                _clean_text(confidence_assessment.get("forensic_completeness") or "Not specified"),
            ],
        ]
        decision_matrix = Table(self._as_table_data(matrix_rows), colWidths=[45 * mm, 115 * mm])
        decision_matrix.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6F2EF")),
                    ("GRID", (0, 0), (-1, -1), 0.25, self.theme["line"]),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        blocks = [
            Paragraph("Executive Summary", self.styles["ChHeading"]),
            Paragraph("Decision Panel", self.styles["ChSubtitle"]),
            decision_matrix,
            Spacer(1, 1.6 * mm),
        ]
        if exec_summary:
            blocks.append(Paragraph(exec_summary, self.styles["ChBody"]))
            blocks.append(Spacer(1, 2 * mm))
        if integrated:
            blocks.append(Paragraph(f"<b>Integrated Threat Assessment:</b> {integrated}", self.styles["ChBody"]))
        return blocks

    def _build_behavior_section(self, cape_data: dict[str, Any]) -> list[Any]:
        behavior = _safe_dict(cape_data.get("behavior"))
        summary = _safe_dict(behavior.get("summary"))
        processes = _safe_list(behavior.get("processes"))

        api_counter = Counter()
        for process in processes:
            for call in _safe_list(_safe_dict(process).get("calls")):
                api_name = _safe_dict(call).get("api")
                if api_name:
                    api_counter[str(api_name)] += 1

        top_api_rows = [["API", "Count"]] + [[k, str(v)] for k, v in api_counter.most_common(12)]
        if len(top_api_rows) == 1:
            top_api_rows.append(["No API telemetry", "0"])

        top_api_table = Table(self._as_table_data(top_api_rows), colWidths=[95 * mm, 22 * mm])
        top_api_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F3F7")),
                    ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        cards = [
            ["Processes", str(len(processes))],
            ["Registry keys", str(len(_safe_list(summary.get("keys"))))],
            ["Files written", str(len(_safe_list(summary.get("write_files"))))],
            ["Files deleted", str(len(_safe_list(summary.get("delete_files"))))],
            ["Commands", str(len(_safe_list(summary.get("executed_commands"))))],
            ["Mutexes", str(len(_safe_list(summary.get("mutexes"))))],
        ]

        metrics_rows = [["Behavior Metrics", ""]] + cards
        metrics_table = Table(self._as_table_data(metrics_rows), colWidths=[45 * mm, 20 * mm])
        metrics_table.setStyle(
            TableStyle(
                [
                    ("SPAN", (0, 0), (1, 0)),
                    ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#EAF5EE")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        network = _safe_dict(cape_data.get("network"))
        network_rows = [
            ["Hosts contacted", str(len(_safe_list(network.get("hosts"))))],
            ["Domains queried", str(len(_safe_list(network.get("domains"))))],
            ["HTTP requests", str(len(_safe_list(network.get("http"))))],
            ["DNS queries", str(len(_safe_list(network.get("dns"))))],
        ]
        network_table = Table(self._as_table_data(network_rows), colWidths=[45 * mm, 20 * mm])
        network_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        combined = Table([[metrics_table, network_table]], colWidths=[67 * mm, 67 * mm])
        combined.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))

        sample_rows = [["Executed Commands", "File Operations", "Registry Keys"]]
        commands = _safe_list(summary.get("executed_commands"))[:5]
        file_ops = (_safe_list(summary.get("write_files")) + _safe_list(summary.get("delete_files")))[:5]
        registry = _safe_list(summary.get("keys"))[:5]
        max_len = max(len(commands), len(file_ops), len(registry), 1)
        for i in range(max_len):
            sample_rows.append(
                [
                    commands[i] if i < len(commands) else "-",
                    file_ops[i] if i < len(file_ops) else "-",
                    registry[i] if i < len(registry) else "-",
                ]
            )

        sample_table = Table(self._as_table_data(sample_rows), colWidths=[52 * mm, 52 * mm, 52 * mm])
        sample_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2FF")),
                    ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        behavior_chart = self._build_behavior_distribution_chart(
            {
                "Processes": len(processes),
                "Commands": len(_safe_list(summary.get("executed_commands"))),
                "Registry": len(_safe_list(summary.get("keys"))),
                "Write Files": len(_safe_list(summary.get("write_files"))),
                "Delete Files": len(_safe_list(summary.get("delete_files"))),
                "Network": len(_safe_list(network.get("http"))) + len(_safe_list(network.get("dns"))),
            }
        )

        return [
            Paragraph("Sandbox Behavioral Analysis", self.styles["ChHeading"]),
            combined,
            Spacer(1, 2 * mm),
            Paragraph("Activity Distribution", self.styles["ChSubtitle"]),
            behavior_chart,
            Spacer(1, 2 * mm),
            Paragraph("Top API Calls", self.styles["ChBody"]),
            top_api_table,
            Spacer(1, 2 * mm),
            Paragraph("Behavior Samples", self.styles["ChBody"]),
            sample_table,
            Spacer(1, 2 * mm),
            Paragraph(
                "This section is generated from raw sandbox behavioral output (processes, API calls, registry, file and network activity).",
                self.styles["ChMuted"],
            ),
        ]

    def _build_ai_section(self, ai_results: dict[str, Any], ai_final: dict[str, Any]) -> list[Any]:
        report = _safe_dict(ai_final.get("report"))
        confidence = ai_final.get("threat_confidence_score", "N/A")
        level = ai_final.get("overall_threat_level", "Unknown")
        coverage = _clean_text(report.get("analysis_scope_and_coverage"))
        correlation = _clean_text(report.get("cross_stage_evidence_correlation"))
        progression = _clean_text(report.get("threat_progression_and_kill_chain"))

        analyzed_sections = sorted(ai_results.keys())
        section_text = ", ".join(analyzed_sections) if analyzed_sections else "None"

        content: list[Any] = [
            Paragraph("AI Classification and Reasoning", self.styles["ChHeading"]),
            Paragraph(
                f"<b>Verdict:</b> {level} &nbsp;&nbsp; <b>Confidence:</b> {confidence}",
                self.styles["ChBody"],
            ),
            Paragraph(f"<b>AI sections analyzed:</b> {section_text}", self.styles["ChMuted"]),
            Spacer(1, 1.5 * mm),
        ]

        if coverage:
            content.append(Paragraph(f"<b>Coverage:</b> {coverage}", self.styles["ChBody"]))
            content.append(Spacer(1, 1 * mm))
        if correlation:
            content.append(Paragraph(f"<b>Evidence Correlation:</b> {correlation}", self.styles["ChBody"]))
            content.append(Spacer(1, 1 * mm))
        if progression:
            content.append(Paragraph(f"<b>Kill Chain Narrative:</b> {progression}", self.styles["ChBody"]))

        findings = self._extract_ai_findings(ai_results)
        if findings:
            content.append(Spacer(1, 1.5 * mm))
            content.append(Paragraph("Key AI Findings", self.styles["ChBody"]))
            for item in findings[:8]:
                content.append(Paragraph(f"- {_clean_text(item)}", self.styles["ChBullet"]))

        if len(content) <= 4:
            content.append(Paragraph("Detailed AI reasoning was not available for this sample.", self.styles["ChBody"]))
        return content

    def _build_mitre_section(self, cape_data: dict[str, Any], ai_final: dict[str, Any]) -> list[Any]:
        report = _safe_dict(ai_final.get("report"))
        mitre_text = _clean_text(report.get("mitre_attack_mapping"))
        cape_ttps = _safe_list(cape_data.get("ttps"))

        entries: list[tuple[str, str, str, str]] = []
        for ttp in cape_ttps:
            ttp_dict = _safe_dict(ttp)
            signature = _clean_text(ttp_dict.get("signature")) or "Sandbox signature"
            for tech_id in _safe_list(ttp_dict.get("ttps")):
                tid = _clean_text(tech_id)
                if not tid:
                    continue
                tactic = self._infer_tactic(tid)
                entries.append((tactic, tid, signature, "Sandbox behavioral mapping"))

        for tid in _extract_technique_ids(mitre_text):
            tactic = self._infer_tactic(tid)
            entries.append((tactic, tid, "AI final synthesis", "Narrative ATT&CK mapping"))

        unique_entries: list[tuple[str, str, str, str]] = []
        seen = set()
        for item in entries:
            key = (item[0], item[1], item[2])
            if key in seen:
                continue
            seen.add(key)
            unique_entries.append(item)

        if not unique_entries:
            return [
                Paragraph("MITRE ATT&CK Mapping", self.styles["ChHeading"]),
                Paragraph("No MITRE ATT&CK techniques were found in sandbox + AI data.", self.styles["ChBody"]),
            ]

        by_tactic = Counter([entry[0] for entry in unique_entries])
        chart = self._build_tactic_horizontal_chart(by_tactic)

        table_rows = [["Tactic", "Technique ID", "Source", "Description"]]
        for tactic, tid, source, desc in unique_entries[:18]:
            table_rows.append([tactic, tid, source, desc])

        mitre_table = Table(self._as_table_data(table_rows), colWidths=[35 * mm, 26 * mm, 33 * mm, 64 * mm])
        mitre_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6F2EF")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        return [
            Paragraph("MITRE ATT&CK Mapping", self.styles["ChHeading"]),
            Paragraph("Technique distribution by tactic", self.styles["ChMuted"]),
            chart,
            Spacer(1, 1.5 * mm),
            mitre_table,
            Spacer(1, 1 * mm),
            Paragraph("Technique mappings are collected from sandbox TTP telemetry and AI final synthesis narrative.", self.styles["ChMuted"]),
        ]

    def _build_threat_intel_and_iocs(self, cape_data: dict[str, Any], ai_final: dict[str, Any]) -> list[Any]:
        report = _safe_dict(ai_final.get("report"))
        ti_narrative = _clean_text(report.get("threat_intelligence_and_sharing"))
        behavior = _safe_dict(cape_data.get("behavior"))
        summary = _safe_dict(behavior.get("summary"))

        iocs = self._extract_iocs(cape_data, summary)
        ti_matches = _split_numbered_items(ti_narrative)

        ioc_rows = [["IOC Type", "Values (sample)"]]
        for label, values in [
            ("IP addresses", iocs["ips"]),
            ("Domains", iocs["domains"]),
            ("URLs", iocs["urls"]),
            ("File paths", iocs["paths"]),
            ("Hashes", iocs["hashes"]),
        ]:
            sample = ", ".join(values[:5]) if values else "None"
            ioc_rows.append([label, sample])

        ioc_table = Table(self._as_table_data(ioc_rows), colWidths=[35 * mm, 123 * mm])
        ioc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )

        blocks: list[Any] = [
            Paragraph("Threat Intelligence and IOC Extraction", self.styles["ChHeading"]),
            Paragraph("IOC Composition", self.styles["ChSubtitle"]),
            self._build_ioc_composition_chart(iocs),
            Spacer(1, 1.2 * mm),
            ioc_table,
            Spacer(1, 1.5 * mm),
        ]

        if ti_matches:
            blocks.append(Paragraph("Threat Intelligence Context", self.styles["ChBody"]))
            for line in ti_matches[:7]:
                blocks.append(Paragraph(f"- {_clean_text(line)}", self.styles["ChBullet"]))
        else:
            blocks.append(Paragraph("No explicit threat-intelligence narrative was present in AI context.", self.styles["ChMuted"]))
        return blocks

    def _build_mitigation_section(self, ai_final: dict[str, Any]) -> list[Any]:
        report = _safe_dict(ai_final.get("report"))
        response = _split_numbered_items(_clean_text(report.get("incident_response_guidance")))
        lessons = _split_numbered_items(_clean_text(report.get("lessons_learned_and_recommendations")))

        if not response and not lessons:
            return [
                Paragraph("Mitigation Recommendations", self.styles["ChHeading"]),
                Paragraph("AI mitigation guidance is not available for this run.", self.styles["ChBody"]),
            ]

        content: list[Any] = [
            PageBreak(),
            Paragraph("Mitigation Recommendations", self.styles["ChHeading"]),
            Paragraph("Actionable response recommendations from AI synthesis.", self.styles["ChMuted"]),
            Spacer(1, 1.5 * mm),
        ]

        if response:
            content.append(Paragraph("Incident Response Guidance", self.styles["ChBody"]))
            for idx, item in enumerate(response[:10], start=1):
                content.append(Paragraph(f"{idx}. {_clean_text(item)}", self.styles["ChBullet"]))
            content.append(Spacer(1, 1.2 * mm))

        if lessons:
            content.append(Paragraph("Defensive Improvement Recommendations", self.styles["ChBody"]))
            for idx, item in enumerate(lessons[:10], start=1):
                content.append(Paragraph(f"{idx}. {_clean_text(item)}", self.styles["ChBullet"]))

        return content

    def _build_compact_brief(
        self,
        analysis: dict[str, Any],
        cape_data: dict[str, Any],
        ai_results: dict[str, Any],
        ai_final: dict[str, Any],
    ) -> list[Any]:
        behavior = _safe_dict(cape_data.get("behavior"))
        summary = _safe_dict(behavior.get("summary"))
        iocs = self._extract_iocs(cape_data, summary)
        top_findings = self._extract_ai_findings(ai_results)[:6]
        threat_level = _clean_text(ai_final.get("overall_threat_level") or "Unknown")
        confidence = ai_final.get("threat_confidence_score", "N/A")

        brief_rows = [
            ["Sample", str(analysis.get("filename", "Unknown"))],
            ["Threat Level", self._severity_chip(threat_level)],
            ["AI Confidence", f"{confidence}%" if isinstance(confidence, (int, float)) else str(confidence)],
            ["Processes", str(len(_safe_list(behavior.get("processes"))))],
            ["API Calls (Top Set)", str(sum(Counter([_safe_dict(call).get("api") for p in _safe_list(behavior.get("processes")) for call in _safe_list(_safe_dict(p).get("calls")) if _safe_dict(call).get("api")]).values()))],
            ["MITRE Techniques", str(len(_safe_list(cape_data.get("ttps"))))],
            ["Total IOCs", str(sum(len(v) for v in iocs.values()))],
        ]
        brief_table = Table(self._as_table_data(brief_rows), colWidths=[45 * mm, 115 * mm])
        brief_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ECFFF5")),
                    ("GRID", (0, 0), (-1, -1), 0.25, self.theme["line"]),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        findings_rows = [["Top Findings"]]
        for item in top_findings:
            findings_rows.append([f"- {_clean_text(item)}"])
        if len(findings_rows) == 1:
            findings_rows.append(["- No summarized findings available"]) 

        findings_table = Table(self._as_table_data(findings_rows), colWidths=[160 * mm])
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#EAF3FF")),
                    ("GRID", (0, 0), (-1, -1), 0.25, self.theme["line"]),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        small_charts = Table(
            [[
                self._build_behavior_distribution_chart(
                    {
                        "Proc": len(_safe_list(behavior.get("processes"))),
                        "Cmd": len(_safe_list(summary.get("executed_commands"))),
                        "Reg": len(_safe_list(summary.get("keys"))),
                        "Files": len(_safe_list(summary.get("write_files")))
                        + len(_safe_list(summary.get("delete_files"))),
                        "Net": len(_safe_list(_safe_dict(cape_data.get("network")).get("http")))
                        + len(_safe_list(_safe_dict(cape_data.get("network")).get("dns"))),
                    },
                    compact=True,
                ),
                self._build_ioc_composition_chart(iocs, compact=True),
            ]],
            colWidths=[76 * mm, 76 * mm],
        )
        small_charts.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 1.5 * mm),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 1.5 * mm),
                ]
            )
        )

        return [
            PageBreak(),
            Paragraph("Quick Brief (One-Page)", self.styles["ChHeading"]),
            Paragraph("Executive snapshot for rapid analyst handoff.", self.styles["ChMuted"]),
            Spacer(1, 1.5 * mm),
            brief_table,
            Spacer(1, 1.5 * mm),
            small_charts,
            Spacer(1, 1.5 * mm),
            findings_table,
            PageBreak(),
        ]

    def _get_ai_final(self, ai_results: dict[str, Any]) -> dict[str, Any]:
        final_block = _safe_dict(ai_results.get("final_synthesis"))
        final_analysis = _safe_dict(final_block.get("analysis"))
        return final_analysis if final_analysis else final_block

    def _infer_tactic(self, technique_id: str) -> str:
        base = technique_id.split(".")[0]
        return TACTIC_BY_TECHNIQUE_PREFIX.get(base, "Unknown")

    def _extract_iocs(
        self, cape_data: dict[str, Any], summary: dict[str, Any]
    ) -> dict[str, list[str]]:
        all_text_parts: list[str] = []
        all_paths = []

        for key in ["files", "write_files", "delete_files", "executed_commands", "keys"]:
            values = [str(v) for v in _safe_list(summary.get(key))]
            all_text_parts.extend(values)
            if "file" in key:
                all_paths.extend(values)

        dropped = _safe_list(cape_data.get("dropped"))
        for d in dropped:
            path = _safe_dict(d).get("filepath") or _safe_dict(d).get("name")
            if path:
                all_paths.append(str(path))
                all_text_parts.append(str(path))

        full_text = "\n".join(all_text_parts)

        ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_text)))
        urls = sorted(set(re.findall(r"https?://[^\s\"']+", full_text)))
        domains = sorted(
            set(
                re.findall(
                    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|co|gov|edu)\b",
                    full_text,
                )
            )
        )
        hashes = sorted(
            set(
                re.findall(
                    r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b",
                    full_text,
                )
            )
        )

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
            "paths": sorted(set(all_paths)),
        }

    def _kpi_cell(self, label: str, value: str) -> Paragraph:
        return Paragraph(
            f'<font color="#4B5563" size="7"><b>{escape(label)}</b></font><br/>'
            f'<font color="#0F172A" size="14"><b>{escape(value)}</b></font>',
            self.styles["ChBody"],
        )

    def _severity_chip(self, level: str) -> Paragraph:
        normalized = level.lower().strip()
        if "critical" in normalized:
            bg, fg = "#FEE2E2", "#991B1B"
        elif "high" in normalized:
            bg, fg = "#FFF7ED", "#9A3412"
        elif "medium" in normalized:
            bg, fg = "#FEF3C7", "#92400E"
        elif "low" in normalized:
            bg, fg = "#DCFCE7", "#166534"
        else:
            bg, fg = "#E2E8F0", "#1E293B"
        return Paragraph(
            f'<font backColor="{bg}" color="{fg}"><b>&nbsp; {escape(level or "Unknown")} &nbsp;</b></font>',
            self.styles["ChTableCell"],
        )

    def _build_dual_risk_chart(self, sandbox_score: float, ai_confidence: float) -> Drawing:
        chart = Drawing(160 * mm, 40 * mm)

        bar = VerticalBarChart()
        bar.x = 15
        bar.y = 8
        bar.height = 70
        bar.width = 360
        bar.data = [[max(0.0, min(sandbox_score, 10.0)), max(0.0, min(ai_confidence / 10.0, 10.0))]]
        bar.categoryAxis.categoryNames = ["Sandbox", "AI"]
        bar.categoryAxis.labels.fontSize = 8
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = 10
        bar.valueAxis.valueStep = 2
        bar.valueAxis.labels.fontSize = 7
        bar.bars[0].fillColor = self.theme["deep_blue"]
        chart.add(bar)
        chart.add(String(12, 84, "Unified Threat Signal (0-10 scale)", fontSize=8, fillColor=self.theme["text"]))
        chart.add(Rect(245, 84, 6, 6, fillColor=self.theme["deep_blue"], strokeColor=None))
        chart.add(String(255, 83, "Sandbox & AI scores", fontSize=7, fillColor=self.theme["text"]))
        return chart

    def _build_behavior_distribution_chart(self, metrics: dict[str, int], compact: bool = False) -> Drawing:
        names = list(metrics.keys())
        values = [max(0, int(v)) for v in metrics.values()]
        if compact:
            chart = Drawing(70 * mm, 40 * mm)
            bar_x, bar_y, bar_h, bar_w = 8, 8, 62, 176
            label_angle = 35
            cat_font = 6
            val_font = 6
        else:
            chart = Drawing(160 * mm, 45 * mm)
            bar_x, bar_y, bar_h, bar_w = 12, 10, 86, 395
            label_angle = 28
            cat_font = 7
            val_font = 7
        bar = VerticalBarChart()
        bar.x = bar_x
        bar.y = bar_y
        bar.height = bar_h
        bar.width = bar_w
        bar.data = [values]
        bar.categoryAxis.categoryNames = names
        bar.categoryAxis.labels.angle = label_angle
        bar.categoryAxis.labels.fontSize = cat_font
        max_val = max(values + [1])
        step = max(1, max_val // 5)
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = max_val + step
        bar.valueAxis.valueStep = step
        bar.valueAxis.labels.fontSize = val_font
        bar.bars[0].fillColor = self.theme["secondary"]
        chart.add(bar)
        return chart

    def _build_tactic_horizontal_chart(self, tactic_counts: Counter[str]) -> Drawing:
        sorted_items = sorted(tactic_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        labels = [item[0] for item in sorted_items] or ["None"]
        values = [item[1] for item in sorted_items] or [0]

        chart = Drawing(160 * mm, 55 * mm)
        hbar = HorizontalBarChart()
        hbar.x = 90
        hbar.y = 10
        hbar.height = 120
        hbar.width = 300
        hbar.data = [values]
        hbar.categoryAxis.categoryNames = labels
        hbar.categoryAxis.labels.fontSize = 7
        hbar.categoryAxis.labels.dx = -5
        hbar.valueAxis.valueMin = 0
        hbar.valueAxis.valueMax = max(values + [1])
        hbar.valueAxis.valueStep = 1
        hbar.valueAxis.labels.fontSize = 7
        hbar.bars[0].fillColor = self.theme["teal"]
        chart.add(hbar)
        return chart

    def _build_ioc_composition_chart(self, iocs: dict[str, list[str]], compact: bool = False) -> Drawing:
        labels = ["IPs", "Domains", "URLs", "Hashes", "Paths"]
        values = [
            len(iocs.get("ips", [])),
            len(iocs.get("domains", [])),
            len(iocs.get("urls", [])),
            len(iocs.get("hashes", [])),
            len(iocs.get("paths", [])),
        ]
        if sum(values) == 0:
            values = [1, 0, 0, 0, 0]

        chart = Drawing(70 * mm, 40 * mm) if compact else Drawing(160 * mm, 45 * mm)
        pie = Pie()
        if compact:
            pie.x = 86
            pie.y = 6
            pie.width = 62
            pie.height = 62
        else:
            pie.x = 110
            pie.y = 12
            pie.width = 95
            pie.height = 95
        pie.data = values
        pie.labels = labels
        pie.slices.fontSize = 6 if compact else 7
        pie.slices.strokeWidth = 0.4
        palette = [
            self.theme["primary"],
            self.theme["secondary"],
            self.theme["accent"],
            self.theme["teal"],
            self.theme["deep_blue"],
        ]
        for idx, color in enumerate(palette):
            pie.slices[idx].fillColor = color
        chart.add(pie)
        if compact:
            chart.add(String(8, 68, "IOC Type Mix", fontSize=7, fillColor=self.theme["text"]))
            chart.add(String(8, 57, f"Total: {sum(values)}", fontSize=8, fillColor=self.theme["text"]))
        else:
            chart.add(String(16, 92, "IOC Type Mix", fontSize=8, fillColor=self.theme["text"]))
            chart.add(String(16, 78, f"Total IOCs: {sum(values)}", fontSize=10, fillColor=self.theme["text"]))
        return chart

    def _build_logo_flowable(self) -> Any:
        for candidate in self.logo_candidates:
            if candidate.exists():
                img = Image(str(candidate))
                img._restrictSize(55 * mm, 20 * mm)
                return img

        fallback = Drawing(60, 40)
        fallback.add(Rect(0, 2, 14, 30, fillColor=colors.HexColor("#0A7C66"), strokeColor=None))
        fallback.add(Rect(16, 9, 14, 23, fillColor=colors.HexColor("#169A84"), strokeColor=None))
        fallback.add(Rect(32, 16, 14, 16, fillColor=colors.HexColor("#39B69F"), strokeColor=None))
        fallback.add(String(0, -1, "CHAMELEON", fontSize=8, fillColor=colors.HexColor("#143D35")))
        return fallback

    def _as_table_data(self, rows: list[list[Any]]) -> list[list[Paragraph]]:
        formatted: list[list[Paragraph]] = []
        for r_idx, row in enumerate(rows):
            formatted_row: list[Paragraph] = []
            for c_idx, cell in enumerate(row):
                if isinstance(cell, Paragraph):
                    formatted_row.append(cell)
                    continue
                style = self.styles["ChTableHeader"] if r_idx == 0 else self.styles["ChTableCell"]
                if c_idx == 0 and r_idx > 0:
                    style = self.styles["ChTableHeader"]
                formatted_row.append(Paragraph(self._format_cell(cell), style))
            formatted.append(formatted_row)
        return formatted

    def _format_cell(self, value: Any) -> str:
        raw = _clean_text(str(value) if value is not None else "")
        safe = escape(raw)
        return self._break_long_tokens(safe)

    def _break_long_tokens(self, text: str, max_token: int = 38) -> str:
        tokens = text.split(" ")
        wrapped: list[str] = []
        for token in tokens:
            if len(token) <= max_token:
                wrapped.append(token)
                continue
            # Break very long uninterrupted tokens (hashes/paths/URLs) to prevent cell overflow.
            chunked = [token[i : i + max_token] for i in range(0, len(token), max_token)]
            wrapped.append("<br/>".join(chunked))
        return " ".join(wrapped)

    def _extract_ai_findings(self, ai_results: dict[str, Any]) -> list[str]:
        findings: list[str] = []
        behavior = _safe_dict(_safe_dict(ai_results.get("behavior_analysis")).get("analysis"))
        final_synthesis = _safe_dict(_safe_dict(ai_results.get("final_synthesis")).get("analysis"))
        network = _safe_dict(_safe_dict(ai_results.get("network_analysis")).get("analysis"))
        memory = _safe_dict(_safe_dict(ai_results.get("memory_analysis")).get("analysis"))

        findings.extend(_safe_list(_safe_dict(behavior.get("ai_insights_summary")).get("key_findings")))
        findings.extend(_safe_list(_safe_dict(network.get("network_forensic_insights")).get("key_network_findings")))
        findings.extend(_safe_list(_safe_dict(memory.get("ai_forensic_insights")).get("key_memory_findings")))

        report = _safe_dict(final_synthesis.get("report"))
        for key in ["executive_summary", "integrated_threat_assessment", "cross_stage_evidence_correlation"]:
            value = _clean_text(report.get(key))
            if value:
                findings.append(value)

        deduped: list[str] = []
        seen = set()
        for item in findings:
            item_text = _clean_text(item)
            if not item_text:
                continue
            k = item_text.lower()
            if k in seen:
                continue
            seen.add(k)
            deduped.append(item_text)
        return deduped
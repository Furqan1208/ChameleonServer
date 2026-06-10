# app/services/pdf_report_service.py
"""
Professional Malware Analysis PDF Report Generator
Industry-grade design with refined color palette and professional charts
"""

from __future__ import annotations

import tempfile
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, Line, String, Circle, Polygon
from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from reportlab.lib.utils import ImageReader

# ─────────────────────────────────────────────────────────────────────────────
# PROFESSIONAL COLOUR PALETTE
# Muted, dark-mode-inspired palette — no neon, high contrast where needed
# ─────────────────────────────────────────────────────────────────────────────

# Primary brand — deep teal/slate green (not neon)
BRAND_PRIMARY       = colors.HexColor("#1A7F5A")   # Deep emerald
BRAND_SECONDARY     = colors.HexColor("#134E3A")   # Forest dark
BRAND_ACCENT        = colors.HexColor("#2DC08A")   # Muted mint (accent only)
BRAND_LIGHT         = colors.HexColor("#E8F5EF")   # Very light mint tint

# Surface / structural
SURFACE_DARK        = colors.HexColor("#1C2B2B")   # Near-black teal (header/footer)
SURFACE_MID         = colors.HexColor("#2D3E3E")   # Dark card bg
SURFACE_LIGHT       = colors.HexColor("#F4F7F5")   # Off-white page bg
SURFACE_WHITE       = colors.white
SURFACE_RULE        = colors.HexColor("#D0DDD6")   # Subtle dividers

# Typography
TEXT_PRIMARY        = colors.HexColor("#1A2E2A")   # Near black, warm
TEXT_SECONDARY      = colors.HexColor("#4A5E58")   # Mid grey-green
TEXT_MUTED          = colors.HexColor("#8AA49B")   # Light muted
TEXT_ON_DARK        = colors.white
TEXT_ON_DARK_MUTED  = colors.HexColor("#A8C4BA")

# Severity — professional, desaturated
SEV_CRITICAL        = colors.HexColor("#C0392B")   # Deep red
SEV_HIGH            = colors.HexColor("#C87941")   # Burnt orange
SEV_MEDIUM          = colors.HexColor("#B8962E")   # Amber gold
SEV_LOW             = colors.HexColor("#2E7D32")   # Deep green
SEV_INFO            = colors.HexColor("#2563A8")   # Steel blue
SEV_CLEAN           = colors.HexColor("#388E3C")   # Confident green
SEV_UNKNOWN         = colors.HexColor("#78909C")   # Blue-grey

# Severity tints (for row backgrounds)
SEV_CRITICAL_BG     = colors.HexColor("#FDECEA")
SEV_HIGH_BG         = colors.HexColor("#FDF3E7")
SEV_MEDIUM_BG       = colors.HexColor("#FDF8E4")
SEV_LOW_BG          = colors.HexColor("#E8F5E9")

# Chart palette — distinct but harmonious
CHART_PALETTE = [
    colors.HexColor("#1A7F5A"),   # Primary green
    colors.HexColor("#2563A8"),   # Steel blue
    colors.HexColor("#C87941"),   # Burnt orange
    colors.HexColor("#8E44AD"),   # Muted purple
    colors.HexColor("#C0392B"),   # Deep red
    colors.HexColor("#16A085"),   # Teal
]

PAGE_W, PAGE_H = A4
MARGIN = 22 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

SEVERITY_COLOUR_MAP = {
    "CRITICAL":   SEV_CRITICAL,
    "HIGH":       SEV_HIGH,
    "MEDIUM":     SEV_MEDIUM,
    "LOW":        SEV_LOW,
    "INFO":       SEV_INFO,
    "MALICIOUS":  SEV_CRITICAL,
    "SUSPICIOUS": SEV_HIGH,
    "CLEAN":      SEV_CLEAN,
    "LOW RISK":   SEV_LOW,
    "UNKNOWN":    SEV_UNKNOWN,
}

SEVERITY_BG_MAP = {
    "CRITICAL":   SEV_CRITICAL_BG,
    "HIGH":       SEV_HIGH_BG,
    "MEDIUM":     SEV_MEDIUM_BG,
    "LOW":        SEV_LOW_BG,
    "LOW RISK":   SEV_LOW_BG,
    "MALICIOUS":  SEV_CRITICAL_BG,
    "SUSPICIOUS": SEV_HIGH_BG,
    "CLEAN":      SEV_LOW_BG,
}


def sev_color(text: str) -> colors.Color:
    return SEVERITY_COLOUR_MAP.get(str(text).upper(), SEV_UNKNOWN)


def sev_bg(text: str) -> colors.Color:
    return SEVERITY_BG_MAP.get(str(text).upper(), SURFACE_LIGHT)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SERVICE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class PDFReportService:
    """Professional Malware Analysis Report Generator — Industry Grade"""

    def __init__(self, logo_path: Optional[str] = None):
        self._init_styles()
        self.logo_path = logo_path or self._find_logo()

    # ── Logo ──────────────────────────────────────────────────────────────────

    def _find_logo(self) -> Optional[str]:
        for p in [
            Path("app/static/logo.png"), Path("app/static/logo.svg"),
            Path("static/logo.png"), Path("logo.png"),
        ]:
            if p.exists():
                return str(p)
        return None

    # ── Styles ────────────────────────────────────────────────────────────────

    def _init_styles(self):
        self.styles = {
            # Cover
            "cover_report_type": self._ps("cover_report_type",
                fontSize=9, fontName="Helvetica-Bold",
                textColor=TEXT_ON_DARK_MUTED, alignment=TA_CENTER,
                tracking=2, spaceAfter=4),
            "cover_title": self._ps("cover_title",
                fontSize=26, fontName="Helvetica-Bold",
                textColor=TEXT_ON_DARK, alignment=TA_CENTER,
                leading=32, spaceAfter=4),
            "cover_family": self._ps("cover_family",
                fontSize=14, fontName="Helvetica",
                textColor=BRAND_ACCENT, alignment=TA_CENTER,
                spaceAfter=2),
            "cover_meta_key": self._ps("cover_meta_key",
                fontSize=8, fontName="Helvetica-Bold",
                textColor=TEXT_ON_DARK_MUTED),
            "cover_meta_val": self._ps("cover_meta_val",
                fontSize=8, fontName="Helvetica",
                textColor=TEXT_ON_DARK),

            # Section headers
            "section_num": self._ps("section_num",
                fontSize=8, fontName="Helvetica-Bold",
                textColor=BRAND_ACCENT, spaceAfter=0),
            "section_title": self._ps("section_title",
                fontSize=13, fontName="Helvetica-Bold",
                textColor=TEXT_ON_DARK, leading=16, spaceAfter=0),

            # Body hierarchy
            "h2": self._ps("h2",
                fontSize=10.5, fontName="Helvetica-Bold",
                textColor=BRAND_PRIMARY, spaceBefore=10,
                spaceAfter=5, leading=14),
            "h3": self._ps("h3",
                fontSize=9.5, fontName="Helvetica-Bold",
                textColor=TEXT_PRIMARY, spaceBefore=7,
                spaceAfter=3, leading=13),
            "body": self._ps("body",
                fontSize=9, fontName="Helvetica",
                textColor=TEXT_PRIMARY, leading=13.5,
                spaceAfter=4, alignment=TA_JUSTIFY),
            "body_small": self._ps("body_small",
                fontSize=8.5, fontName="Helvetica",
                textColor=TEXT_SECONDARY, leading=12,
                spaceAfter=2),
            "mono": self._ps("mono",
                fontSize=7.5, fontName="Courier",
                textColor=TEXT_PRIMARY, leading=11,
                spaceAfter=1),
            "label": self._ps("label",
                fontSize=8, fontName="Helvetica-Bold",
                textColor=TEXT_SECONDARY, spaceAfter=1),
            "bullet": self._ps("bullet",
                fontSize=9, fontName="Helvetica",
                textColor=TEXT_PRIMARY, leading=13,
                spaceAfter=3, leftIndent=12),
            "toc_num": self._ps("toc_num",
                fontSize=9.5, fontName="Helvetica-Bold",
                textColor=BRAND_PRIMARY, leading=14),
            "toc_title": self._ps("toc_title",
                fontSize=9.5, fontName="Helvetica",
                textColor=TEXT_PRIMARY, leading=14),
            "caption": self._ps("caption",
                fontSize=7.5, fontName="Helvetica",
                textColor=TEXT_MUTED, alignment=TA_CENTER,
                spaceAfter=4),
        }

    def _ps(self, name: str, **kwargs):
        return ParagraphStyle(name, **kwargs)

    # ── PDF Entry Point ───────────────────────────────────────────────────────

    def generate_pdf_report(
        self,
        complete_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> bytes:
        if output_path:
            self._build_pdf(complete_data, output_path)
            with open(output_path, "rb") as f:
                return f.read()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            self._build_pdf(complete_data, tmp.name)
            with open(tmp.name, "rb") as f:
                return f.read()

    def _build_pdf(self, data: Dict[str, Any], output_path: str):
        analysis   = data.get("analysis", {})
        analysis_id = analysis.get("analysis_id", "unknown")
        filename   = analysis.get("filename", "Unknown File")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=24 * mm,
            bottomMargin=18 * mm,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            title="Malware Analysis Report",
            author="Chameleon Security Platform",
        )

        def hf(canv, doc):
            self._draw_header_footer(canv, doc, filename, analysis_id)

        story = []
        story.extend(self._build_cover(data))
        story.extend(self._build_toc(data))
        story.extend(self._build_executive_summary(data))
        story.extend(self._build_threat_score_dashboard(data))
        story.extend(self._build_analysis_overview(data))
        story.extend(self._build_file_analysis(data))
        story.extend(self._build_cape_findings(data))
        story.extend(self._build_signatures(data))
        story.extend(self._build_behavioral(data))
        story.extend(self._build_memory(data))
        story.extend(self._build_network(data))
        story.extend(self._build_threat_intel(data))
        story.extend(self._build_mitre(data))
        story.extend(self._build_iocs(data))
        story.extend(self._build_incident_response(data))

        doc.build(story, onFirstPage=hf, onLaterPages=hf)

    # ── Header / Footer ───────────────────────────────────────────────────────

    def _draw_header_footer(self, canv: canvas.Canvas, doc, filename: str, analysis_id: str):
        canv.saveState()
        w, h = A4

        # ── Header ──
        # Dark background bar
        canv.setFillColor(SURFACE_DARK)
        canv.rect(0, h - 20 * mm, w, 20 * mm, fill=1, stroke=0)

        # Thin brand accent line at bottom of header
        canv.setFillColor(BRAND_PRIMARY)
        canv.rect(0, h - 20 * mm, w, 1.2 * mm, fill=1, stroke=0)

        # Brand name (left)
        canv.setFillColor(TEXT_ON_DARK)
        canv.setFont("Helvetica-Bold", 9)
        canv.drawString(MARGIN, h - 13 * mm, "CHAMELEON SECURITY")

        # Separator dot
        canv.setFillColor(BRAND_ACCENT)
        canv.circle(MARGIN + 115, h - 12.5 * mm, 1.2, fill=1, stroke=0)

        # Report type (right of dot)
        canv.setFillColor(TEXT_ON_DARK_MUTED)
        canv.setFont("Helvetica", 8)
        canv.drawString(MARGIN + 122, h - 13 * mm, "Malware Analysis Report")

        # Filename (far right, truncated)
        short_name = filename[:55] + "…" if len(filename) > 55 else filename
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(TEXT_ON_DARK_MUTED)
        canv.drawRightString(w - MARGIN, h - 13 * mm, short_name)

        # ── Footer ──
        # Thin rule
        canv.setStrokeColor(SURFACE_RULE)
        canv.setLineWidth(0.5)
        canv.line(MARGIN, 14 * mm, w - MARGIN, 14 * mm)

        canv.setFont("Helvetica", 7)
        canv.setFillColor(TEXT_MUTED)
        canv.drawString(MARGIN, 9 * mm, f"Analysis ID: {analysis_id}")
        canv.drawCentredString(w / 2, 9 * mm, f"Page {doc.page}")
        canv.drawRightString(w - MARGIN, 9 * mm, "CONFIDENTIAL  ·  INTERNAL USE ONLY")

        canv.restoreState()

    # ─────────────────────────────────────────────────────────────────────────
    # VISUALIZATIONS (Professional Charts)
    # ─────────────────────────────────────────────────────────────────────────

    def _threat_gauge_drawing(self, score: float, width: float = 320, height: float = 70) -> Drawing:
        """
        Professional horizontal threat gauge.
        Segmented track: Clean | Suspicious | Malicious
        with a triangular pointer at the score position.
        """
        d = Drawing(width, height)
        pad_l, pad_r = 30, 30
        bar_y = 28
        bar_h = 14
        track_w = width - pad_l - pad_r

        score = max(0.0, min(10.0, float(score)))

        # Background track (three segments)
        segments = [
            (0,   4,  SEV_LOW_BG,          SEV_LOW),
            (4,   7,  SEV_MEDIUM_BG,        SEV_MEDIUM),
            (7,  10,  SEV_CRITICAL_BG,      SEV_CRITICAL),
        ]
        for s_min, s_max, bg, _border in segments:
            x0 = pad_l + (s_min / 10) * track_w
            x1 = pad_l + (s_max / 10) * track_w
            d.add(Rect(x0, bar_y, x1 - x0, bar_h,
                       fillColor=bg, strokeColor=SURFACE_RULE, strokeWidth=0.5))

        # Filled portion up to score
        fill_w = (score / 10) * track_w
        if score < 4:
            fill_col = SEV_LOW
        elif score < 7:
            fill_col = SEV_MEDIUM
        else:
            fill_col = SEV_CRITICAL

        d.add(Rect(pad_l, bar_y, fill_w, bar_h,
                   fillColor=fill_col, strokeColor=None, strokeWidth=0))

        # Score pointer line
        px = pad_l + fill_w
        d.add(Line(px, bar_y - 4, px, bar_y + bar_h + 4,
                   strokeColor=TEXT_PRIMARY, strokeWidth=1.5))

        # Score label above pointer
        d.add(String(px, bar_y + bar_h + 7,
                     f"{score:.1f}",
                     fontSize=9, fontName="Helvetica-Bold",
                     fillColor=TEXT_PRIMARY, textAnchor="middle"))

        # Segment labels below
        label_y = bar_y - 10
        d.add(String(pad_l + (2 / 10) * track_w, label_y, "Clean",
                     fontSize=7, fillColor=TEXT_MUTED, textAnchor="middle"))
        d.add(String(pad_l + (5.5 / 10) * track_w, label_y, "Suspicious",
                     fontSize=7, fillColor=TEXT_MUTED, textAnchor="middle"))
        d.add(String(pad_l + (8.5 / 10) * track_w, label_y, "Malicious",
                     fontSize=7, fillColor=TEXT_MUTED, textAnchor="middle"))

        # Scale markers
        for i in range(11):
            mx = pad_l + (i / 10) * track_w
            d.add(Line(mx, bar_y - 1, mx, bar_y,
                       strokeColor=SURFACE_RULE, strokeWidth=0.5))
            if i % 2 == 0:
                d.add(String(mx, bar_y - 8, str(i),
                             fontSize=6, fillColor=TEXT_MUTED, textAnchor="middle"))

        # "/ 10" label (far right)
        d.add(String(pad_l + track_w + 6, bar_y + 4, "/ 10",
                     fontSize=7, fillColor=TEXT_MUTED))

        return d

    def _horizontal_bar_chart(
        self,
        labels: List[str],
        values: List[float],
        width: float = CONTENT_W,
        height: float = 120,
        max_val: float = None,
        colors_list: List = None,
    ) -> Drawing:
        """
        Clean horizontal bar chart — best for named categories.
        """
        if not labels or not values:
            return Drawing(width, height)

        max_val = max_val or (max(values) * 1.15 if values else 10)
        colors_list = colors_list or [BRAND_PRIMARY] * len(labels)

        pad_l = 90
        pad_r = 30
        pad_t = 10
        pad_b = 20
        bar_area_w = width - pad_l - pad_r
        bar_area_h = height - pad_t - pad_b
        n = len(labels)
        row_h = bar_area_h / n
        bar_thick = row_h * 0.45

        d = Drawing(width, height)

        # Background gridlines (vertical)
        grid_steps = 5
        for i in range(grid_steps + 1):
            gx = pad_l + (i / grid_steps) * bar_area_w
            d.add(Line(gx, pad_b, gx, pad_b + bar_area_h,
                       strokeColor=SURFACE_RULE, strokeWidth=0.4))
            # Axis value label
            val_label = f"{int((i / grid_steps) * max_val)}"
            d.add(String(gx, pad_b - 10, val_label,
                         fontSize=6, fillColor=TEXT_MUTED, textAnchor="middle"))

        # Bars
        for idx, (lbl, val) in enumerate(zip(labels, values)):
            y_center = pad_b + bar_area_h - (idx + 0.5) * row_h
            bar_w = (val / max_val) * bar_area_w if max_val else 0
            col = colors_list[idx % len(colors_list)]

            # Bar background (full width, very light)
            d.add(Rect(pad_l, y_center - bar_thick / 2,
                       bar_area_w, bar_thick,
                       fillColor=SURFACE_LIGHT, strokeColor=None))

            # Actual bar
            if bar_w > 0:
                d.add(Rect(pad_l, y_center - bar_thick / 2,
                           bar_w, bar_thick,
                           fillColor=col, strokeColor=None))

            # Value label inside bar (or just outside if bar too short)
            val_x = pad_l + bar_w + 4
            d.add(String(val_x, y_center - 3, str(int(val)),
                         fontSize=7, fontName="Helvetica-Bold",
                         fillColor=TEXT_SECONDARY))

            # Category label (left)
            short_lbl = lbl[:12] if len(lbl) > 12 else lbl
            d.add(String(pad_l - 4, y_center - 3, short_lbl,
                         fontSize=7.5, fillColor=TEXT_PRIMARY,
                         textAnchor="end"))

        return d

    def _donut_chart(
        self,
        data: List[int],
        labels: List[str],
        colors_list: List,
        width: float = 200,
        height: float = 160,
    ) -> Drawing:
        """
        Professional donut/pie chart with clean external legend.
        """
        total = sum(data)
        if total == 0:
            return Drawing(width, height)

        d = Drawing(width, height)

        cx = width * 0.42
        cy = height / 2
        r_outer = min(cx, cy) * 0.78
        r_inner = r_outer * 0.52   # donut hole

        # Sort by value descending for visual clarity
        combined = sorted(zip(data, labels, colors_list), reverse=True)
        data_s, labels_s, colors_s = zip(*combined)

        # Draw donut slices manually using Pie + white circle overlay
        pie = Pie()
        pie.x = cx - r_outer
        pie.y = cy - r_outer
        pie.width = r_outer * 2
        pie.height = r_outer * 2
        pie.data = list(data_s)
        pie.labels = None
        pie.slices.strokeWidth = 1.5
        pie.slices.strokeColor = SURFACE_WHITE
        for i, col in enumerate(colors_s):
            pie.slices[i].fillColor = col
            pie.slices[i].strokeColor = SURFACE_WHITE
        d.add(pie)

        # White circle for donut hole
        d.add(Circle(cx, cy, r_inner,
                     fillColor=SURFACE_WHITE, strokeColor=SURFACE_WHITE, strokeWidth=0))

        # Total label in centre
        d.add(String(cx, cy + 5, str(total),
                     fontSize=13, fontName="Helvetica-Bold",
                     fillColor=TEXT_PRIMARY, textAnchor="middle"))
        d.add(String(cx, cy - 8, "Total",
                     fontSize=7, fillColor=TEXT_MUTED, textAnchor="middle"))

        # Legend (right side)
        leg_x = cx + r_outer + 8
        leg_y_start = cy + (len(data_s) * 13) / 2
        for i, (lbl, col, val) in enumerate(zip(labels_s, colors_s, data_s)):
            pct = val / total * 100
            ly = leg_y_start - i * 16
            d.add(Rect(leg_x, ly - 4, 8, 8, fillColor=col, strokeColor=None))
            d.add(String(leg_x + 11, ly - 3,
                         f"{lbl[:14]}  {val} ({pct:.0f}%)",
                         fontSize=7, fillColor=TEXT_SECONDARY))

        return d

    def _vertical_bar_chart(
        self,
        categories: List[str],
        values: List[float],
        width: float = CONTENT_W,
        height: float = 130,
        color: colors.Color = BRAND_PRIMARY,
    ) -> Drawing:
        """Clean vertical bar chart with value labels on top."""
        if not categories or not values:
            return Drawing(width, height)

        max_val = max(values) * 1.2 if values else 10
        pad_l, pad_r, pad_t, pad_b = 30, 20, 25, 30
        bar_area_w = width - pad_l - pad_r
        bar_area_h = height - pad_t - pad_b
        n = len(categories)
        col_w = bar_area_w / n
        bar_w = col_w * 0.55

        d = Drawing(width, height)

        # Horizontal gridlines
        for i in range(5):
            gy = pad_b + (i / 4) * bar_area_h
            d.add(Line(pad_l, gy, pad_l + bar_area_w, gy,
                       strokeColor=SURFACE_RULE, strokeWidth=0.4))

        # Axes
        d.add(Line(pad_l, pad_b, pad_l, pad_b + bar_area_h,
                   strokeColor=SURFACE_RULE, strokeWidth=0.8))
        d.add(Line(pad_l, pad_b, pad_l + bar_area_w, pad_b,
                   strokeColor=SURFACE_RULE, strokeWidth=0.8))

        # Bars
        for idx, (cat, val) in enumerate(zip(categories, values)):
            bar_x = pad_l + idx * col_w + (col_w - bar_w) / 2
            bar_h_px = (val / max_val) * bar_area_h if max_val else 0

            if bar_h_px > 0:
                d.add(Rect(bar_x, pad_b, bar_w, bar_h_px,
                           fillColor=color, strokeColor=None))

            # Value on top
            d.add(String(bar_x + bar_w / 2, pad_b + bar_h_px + 3,
                         f"{int(val)}",
                         fontSize=7, fontName="Helvetica-Bold",
                         fillColor=TEXT_SECONDARY, textAnchor="middle"))

            # Category label below axis
            short = cat[:9] if len(cat) > 9 else cat
            d.add(String(bar_x + bar_w / 2, pad_b - 12, short,
                         fontSize=7, fillColor=TEXT_MUTED, textAnchor="middle"))

        return d

    # ─────────────────────────────────────────────────────────────────────────
    # UI PRIMITIVES
    # ─────────────────────────────────────────────────────────────────────────

    def _section_header(self, num: str, title: str) -> list:
        """Dark full-width section header bar with number and title."""
        w = CONTENT_W
        inner = Table([[
            Paragraph(num,   self.styles["section_num"]),
            Paragraph(title, self.styles["section_title"]),
        ]], colWidths=[w * 0.06, w * 0.94])
        inner.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        outer = Table([[inner]], colWidths=[w])
        outer.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_DARK),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("LINEBELOW",     (0, 0), (-1, -1), 2, BRAND_PRIMARY),
        ]))
        return [Spacer(1, 10), outer, Spacer(1, 8)]

    def _kv_table(self, rows: list, col_ratio=(0.30, 0.70)) -> Table:
        """Refined two-column key-value table with alternating rows."""
        cw = [CONTENT_W * col_ratio[0], CONTENT_W * col_ratio[1]]
        data = []
        for k, v in rows:
            kp = Paragraph(str(k), self.styles["label"])
            if isinstance(v, list):
                text = "\n".join(f"• {i}" for i in v) if v else "—"
                vp = Paragraph(text, self.styles["body_small"])
            else:
                vp = Paragraph(str(v) if v not in (None, "", []) else "—",
                               self.styles["body_small"])
            data.append([kp, vp])

        tbl = Table(data, colWidths=cw)
        tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SURFACE_WHITE, SURFACE_LIGHT]),
            ("LINEBELOW",      (0, 0), (-1, -1), 0.3, SURFACE_RULE),
            ("LINEBEFORE",     (1, 0), (1, -1), 1, BRAND_PRIMARY),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        return tbl

    def _severity_row(self, label: str, value: str) -> Table:
        """Single-row verdict display with colour-coded value cell."""
        col    = sev_color(value)
        bg     = sev_bg(value)
        cw     = [CONTENT_W * 0.30, CONTENT_W * 0.70]
        badge  = ParagraphStyle("_badge", fontSize=9, fontName="Helvetica-Bold",
                                textColor=SURFACE_WHITE, alignment=TA_CENTER)
        tbl = Table([[Paragraph(label, self.styles["label"]),
                      Paragraph(value, badge)]], colWidths=cw)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), SURFACE_LIGHT),
            ("BACKGROUND",    (1, 0), (1, 0), col),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.3, SURFACE_RULE),
            ("LINEBEFORE",    (1, 0), (1, 0), 1, col),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return tbl

    def _callout(self, text: str, level: str = "info") -> Table:
        """Coloured left-border callout box."""
        col_map = {
            "info":     BRAND_PRIMARY,
            "warning":  SEV_HIGH,
            "critical": SEV_CRITICAL,
            "success":  SEV_CLEAN,
        }
        border_col = col_map.get(level, BRAND_PRIMARY)
        bg_col = {
            "info":     BRAND_LIGHT,
            "warning":  SEV_HIGH_BG,
            "critical": SEV_CRITICAL_BG,
            "success":  SEV_LOW_BG,
        }.get(level, BRAND_LIGHT)

        tbl = Table([[Paragraph(text, self.styles["body"])]], colWidths=[CONTENT_W])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg_col),
            ("LINEBEFORE",    (0, 0), (0, -1), 3, border_col),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        return tbl

    def _stat_cards(self, stats: List[tuple]) -> Table:
        """
        Horizontal row of stat cards: [(label, value, sub), ...]
        Up to 4 cards per row.
        """
        n = min(len(stats), 4)
        cw = CONTENT_W / n
        row = []
        for lbl, val, sub in stats[:n]:
            cell = Table([[
                Paragraph(str(val),
                          ParagraphStyle("_sv", fontSize=18, fontName="Helvetica-Bold",
                                         textColor=BRAND_PRIMARY, alignment=TA_CENTER)),
                ], [
                Paragraph(lbl,
                          ParagraphStyle("_sl", fontSize=7.5, fontName="Helvetica-Bold",
                                         textColor=TEXT_SECONDARY, alignment=TA_CENTER)),
                ], [
                Paragraph(sub or " ",
                          ParagraphStyle("_ss", fontSize=7, fontName="Helvetica",
                                         textColor=TEXT_MUTED, alignment=TA_CENTER)),
            ]], colWidths=[cw - 10])
            cell.setStyle(TableStyle([
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ]))
            row.append(cell)

        outer = Table([row], colWidths=[cw] * n)
        outer.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_WHITE),
            ("LINEBELOW",     (0, 0), (-1, -1), 2, BRAND_PRIMARY),
            ("LINEBEFORE",    (1, 0), (-1, -1), 0.5, SURFACE_RULE),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("BOX",           (0, 0), (-1, -1), 0.5, SURFACE_RULE),
        ]))
        return outer

    def _bullet_list(self, items: list, max_items: int = None) -> list:
        if not items:
            return [Paragraph("None identified.", self.styles["body_small"])]
        display = items[:max_items] if max_items else items
        elems = [Paragraph(f"· {i}", self.styles["bullet"]) for i in display]
        if max_items and len(items) > max_items:
            elems.append(Paragraph(f"  … and {len(items) - max_items} more entries",
                                   self.styles["body_small"]))
        return elems

    def _mono_list(self, items: list, max_items: int = 50) -> list:
        if not items:
            return [Paragraph("—", self.styles["mono"])]
        display = items[:max_items]
        elems = [Paragraph(str(i), self.styles["mono"]) for i in display]
        if len(items) > max_items:
            elems.append(Paragraph(f"… +{len(items) - max_items} entries truncated",
                                   self.styles["body_small"]))
        return elems

    def _divider(self) -> HRFlowable:
        return HRFlowable(width="100%", thickness=0.5, color=SURFACE_RULE,
                          spaceAfter=6, spaceBefore=4)

    # ─────────────────────────────────────────────────────────────────────────
    # DATA HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _fmt_ts(self, ts) -> str:
        if not ts:
            return "—"
        try:
            if isinstance(ts, datetime):
                return ts.strftime("%Y-%m-%d  %H:%M:%S UTC")
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d  %H:%M:%S UTC")
        except Exception:
            return str(ts)[:19]

    def _get_family(self, data: Dict) -> str:
        ai = data.get("ai_analysis", {}).get("results", {})
        for key in ("final_synthesis", "initial_combined_analysis"):
            fam = (ai.get(key, {}).get("analysis", {})
                     .get("executive_summary", {}).get("malware_family"))
            if fam:
                return fam
        return "Unknown"

    def _get_verdict(self, data: Dict) -> str:
        ai  = data.get("ai_analysis", {}).get("results", {})
        v   = (ai.get("final_synthesis", {}).get("analysis", {})
                 .get("executive_summary", {}).get("final_verdict", ""))
        if v:
            return v.upper()
        ms = data.get("analysis", {}).get("malscore", 0)
        if isinstance(ms, (int, float)):
            if ms >= 7:   return "MALICIOUS"
            if ms >= 4:   return "SUSPICIOUS"
            return "LOW RISK"
        return "UNKNOWN"

    # ─────────────────────────────────────────────────────────────────────────
    # COVER PAGE
    # ─────────────────────────────────────────────────────────────────────────

    def _build_cover(self, data: Dict) -> list:
        analysis   = data.get("analysis", {})
        ti         = analysis.get("threat_intel", {})
        sha256     = ti.get("hash_queried", "—")
        filename   = analysis.get("filename", "—")
        analysis_id = analysis.get("analysis_id", "—")
        malscore   = analysis.get("malscore", 0)
        date       = self._fmt_ts(analysis.get("completed_at") or analysis.get("created_at", ""))
        family     = self._get_family(data)
        verdict    = self._get_verdict(data)
        col        = sev_color(verdict)

        w = CONTENT_W

        # Styles
        st_report = ParagraphStyle("_cv_rpt",
            fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_ON_DARK_MUTED,
            alignment=TA_CENTER, spaceAfter=0)
        st_title = ParagraphStyle("_cv_ttl",
            fontSize=24, fontName="Helvetica-Bold", textColor=TEXT_ON_DARK,
            alignment=TA_CENTER, leading=30, spaceAfter=0)
        st_family = ParagraphStyle("_cv_fam",
            fontSize=13, fontName="Helvetica", textColor=BRAND_ACCENT,
            alignment=TA_CENTER, spaceAfter=0)
        st_verdict = ParagraphStyle("_cv_ver",
            fontSize=11, fontName="Helvetica-Bold", textColor=SURFACE_WHITE,
            alignment=TA_CENTER)
        st_mk = ParagraphStyle("_cv_mk",
            fontSize=8, fontName="Helvetica-Bold", textColor=TEXT_ON_DARK_MUTED)
        st_mv = ParagraphStyle("_cv_mv",
            fontSize=8, fontName="Helvetica", textColor=TEXT_ON_DARK)
        st_conf = ParagraphStyle("_cv_conf",
            fontSize=7.5, fontName="Helvetica", textColor=TEXT_MUTED,
            alignment=TA_CENTER)

        # Verdict badge
        verdict_tbl = Table([[Paragraph(verdict, st_verdict)]], colWidths=[w * 0.32])
        verdict_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), col),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]))

        # Metadata block
        meta_rows = [
            ("SHA-256",     (str(sha256)[:60] + "…") if len(str(sha256)) > 60 else str(sha256)),
            ("File Name",   filename),
            ("Analysis ID", analysis_id),
            ("Malscore",    f"{malscore} / 10" if malscore else "—"),
            ("Date",        date),
        ]
        meta_data = [[Paragraph(k, st_mk), Paragraph(v, st_mv)] for k, v in meta_rows]
        meta_tbl  = Table(meta_data, colWidths=[w * 0.22, w * 0.78])
        meta_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SURFACE_DARK, SURFACE_MID]),
            ("LINEBELOW",      (0, 0), (-1, -2), 0.3, colors.HexColor("#3a5050")),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 10),
        ]))

        # Gauge
        gauge = self._threat_gauge_drawing(
            float(malscore) if malscore else 0, width=w * 0.72, height=65)

        # Wrap gauge centrally
        gauge_tbl = Table([[gauge]], colWidths=[w])
        gauge_tbl.setStyle(TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        # Thin accent divider
        accent_line = Table([[""]], colWidths=[w])
        accent_line.setStyle(TableStyle([
            ("LINEBELOW",     (0, 0), (-1, -1), 2, BRAND_PRIMARY),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        # Assemble cover
        cover_rows = [
            [Spacer(1, 16)],
            [Paragraph("CHAMELEON SECURITY", ParagraphStyle("_cs",
                fontSize=11, fontName="Helvetica-Bold", textColor=BRAND_ACCENT,
                alignment=TA_CENTER, tracking=3))],
            [Spacer(1, 2)],
            [Paragraph("MALWARE ANALYSIS REPORT", st_title)],
            [Spacer(1, 4)],
            [Paragraph(family, st_family)],
            [Spacer(1, 14)],
            [gauge_tbl],
            [Spacer(1, 12)],
            [Table([[verdict_tbl]], colWidths=[w])  # centre the badge
             if True else verdict_tbl],
            [Spacer(1, 18)],
            [accent_line],
            [Spacer(1, 2)],
            [meta_tbl],
            [Spacer(1, 18)],
            [Paragraph("CONFIDENTIAL  ·  FOR INTERNAL USE ONLY  ·  DO NOT DISTRIBUTE",
                       st_conf)],
            [Spacer(1, 16)],
        ]

        # Centre verdict badge properly
        cover_rows[9] = [Table([[verdict_tbl]], colWidths=[w],
                                hAlign="CENTER")]
        cover_rows[9][0].setStyle(TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        cover_tbl = Table(cover_rows, colWidths=[w])
        cover_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_DARK),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        return [cover_tbl, PageBreak()]

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE OF CONTENTS
    # ─────────────────────────────────────────────────────────────────────────

    def _build_toc(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("", "TABLE OF CONTENTS"))

        sections = [
            ("1",  "Executive Summary"),
            ("2",  "Threat Assessment Dashboard"),
            ("3",  "Analysis Overview"),
            ("4",  "File / Target Analysis"),
            ("5",  "CAPE Sandbox Findings"),
            ("6",  "Signatures Analysis"),
            ("7",  "Behavioral Analysis"),
            ("8",  "Memory Analysis"),
            ("9",  "Network Analysis"),
            ("10", "Threat Intelligence"),
            ("11", "MITRE ATT&CK Mapping"),
            ("12", "Indicators of Compromise (IOCs)"),
            ("13", "Incident Response Guidance"),
        ]

        w = CONTENT_W
        for i, (num, title) in enumerate(sections):
            row_bg = SURFACE_WHITE if i % 2 == 0 else SURFACE_LIGHT
            row = Table(
                [[Paragraph(num, self.styles["toc_num"]),
                  Paragraph(title, self.styles["toc_title"]),
                  Paragraph("· · · · · · · · · · · · · · · · · · · ·",
                            ParagraphStyle("_dots", fontSize=7, textColor=TEXT_MUTED,
                                           alignment=TA_CENTER)),
                ]],
                colWidths=[w * 0.06, w * 0.60, w * 0.34])
            row.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), row_bg),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.3, SURFACE_RULE),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elems.append(row)

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 1 — EXECUTIVE SUMMARY
    # ─────────────────────────────────────────────────────────────────────────

    def _build_executive_summary(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("1", "EXECUTIVE SUMMARY"))

        ai          = data.get("ai_analysis", {}).get("results", {})
        fs          = ai.get("final_synthesis", {}).get("analysis", {})
        ica         = ai.get("initial_combined_analysis", {}).get("analysis", {})
        analysis_meta = data.get("analysis", {})

        one_liner = (fs.get("executive_summary", {}).get("one_liner")
                     or ica.get("executive_summary", {}).get("one_liner", "—"))

        elems.append(Paragraph("Key Finding", self.styles["h2"]))
        elems.append(self._callout(one_liner, level="warning"))
        elems.append(Spacer(1, 6))

        summary_para = (fs.get("executive_summary", {}).get("summary_paragraph")
                        or ica.get("executive_summary", {}).get("summary_paragraph", ""))
        if summary_para:
            elems.append(Paragraph("Analytical Summary", self.styles["h2"]))
            elems.append(Paragraph(summary_para, self.styles["body"]))
            elems.append(Spacer(1, 6))

        verdict    = self._get_verdict(data)
        family     = self._get_family(data)
        malscore   = analysis_meta.get("malscore", "—")
        confidence = (fs.get("executive_summary", {}).get("confidence_score")
                      or ica.get("confidence", "—"))

        elems.append(Paragraph("Verdict at a Glance", self.styles["h2"]))
        elems.append(self._severity_row("Verdict", verdict))
        elems.append(self._kv_table([
            ("Malware Family",     family),
            ("Malscore",           f"{malscore} / 10" if malscore != "—" else "—"),
            ("Analysis Confidence", f"{confidence}/10" if isinstance(confidence, (int, float))
                                    else str(confidence)),
        ]))

        ti = analysis_meta.get("threat_intel", {})
        if ti:
            elems.append(self._kv_table([
                ("Threat Intelligence", ti.get("summary", "—")),
                ("Sources Checked",     ti.get("sources_checked", "—")),
            ]))

        confirmed = fs.get("integrated_findings", {}).get("confirmed_families", [])
        if confirmed:
            elems.append(Spacer(1, 6))
            elems.append(Paragraph("Confirmed Malware Families", self.styles["h2"]))
            elems.extend(self._bullet_list(confirmed))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 2 — THREAT ASSESSMENT DASHBOARD
    # ─────────────────────────────────────────────────────────────────────────

    def _build_threat_score_dashboard(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("2", "THREAT ASSESSMENT DASHBOARD"))

        analysis_meta = data.get("analysis", {})
        malscore      = analysis_meta.get("malscore", 0)
        score_val     = float(malscore) if malscore not in (None, "", "—") else 0.0

        parsed   = data.get("parsed", {})
        sections = parsed.get("sections", {})
        beh_ai   = sections.get("behavior",   {}).get("ai_summary", {})
        sig_ai   = sections.get("signatures", {}).get("ai_summary", {})
        net_ai   = sections.get("network",    {}).get("ai_summary", {})
        mem_ai   = sections.get("memory",     {}).get("ai_summary", {})

        # ── Stat Cards ──
        elems.append(Paragraph("At a Glance", self.styles["h2"]))
        elems.append(self._stat_cards([
            ("Overall Malscore",   f"{score_val:.1f}",  "Out of 10"),
            ("Signatures",         str(sig_ai.get("total_signatures", 0)),    "Total fired"),
            ("Network Connections", str(net_ai.get("total_tcp_connections", 0)), "TCP"),
            ("Memory Dumps",       str(mem_ai.get("total_memory_dumps", 0)),  "Analysed"),
        ]))
        elems.append(Spacer(1, 14))

        # ── Threat Gauge ──
        elems.append(Paragraph("Threat Score Gauge", self.styles["h2"]))
        gauge = self._threat_gauge_drawing(score_val, width=CONTENT_W * 0.80, height=70)
        gauge_tbl = Table([[gauge]], colWidths=[CONTENT_W])
        gauge_tbl.setStyle(TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("BACKGROUND",    (0, 0), (-1, -1), SURFACE_WHITE),
            ("BOX",           (0, 0), (-1, -1), 0.5, SURFACE_RULE),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))
        elems.append(gauge_tbl)
        elems.append(Spacer(1, 14))

        # ── Component Scores (Horizontal Bar) ──
        comp_labels = ["Behavioral", "Signatures", "Network", "Memory"]
        comp_values = [
            min(10, len(beh_ai.get("suspicious_processes", [])) * 2),
            min(10, sig_ai.get("critical_signatures", 0) * 2),
            min(10, len(net_ai.get("domains", [])) * 1.5),
            min(10, mem_ai.get("total_memory_dumps", 0)),
        ]
        elems.append(Paragraph("Component Risk Scores", self.styles["h2"]))
        elems.append(Paragraph(
            "Derived sub-scores (0–10) per analysis component.",
            self.styles["body_small"]))
        comp_chart = self._horizontal_bar_chart(
            comp_labels, comp_values,
            width=CONTENT_W, height=110,
            max_val=10,
            colors_list=CHART_PALETTE,
        )
        chart_wrapper = Table([[comp_chart]], colWidths=[CONTENT_W])
        chart_wrapper.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_WHITE),
            ("BOX",        (0, 0), (-1, -1), 0.5, SURFACE_RULE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elems.append(chart_wrapper)
        elems.append(Spacer(1, 14))

        # ── Signature Severity Donut ──
        if sig_ai:
            critical_n   = sig_ai.get("critical_signatures",   0)
            suspicious_n = sig_ai.get("suspicious_signatures", 0)
            low_n        = sig_ai.get("low_severity_signatures", 0)
            total_n      = sig_ai.get("total_signatures", 0)
            medium_n     = max(0, total_n - critical_n - suspicious_n - low_n)

            if total_n > 0:
                elems.append(Paragraph("Signature Severity Distribution", self.styles["h2"]))
                donut = self._donut_chart(
                    [critical_n, suspicious_n, medium_n, low_n],
                    ["Critical", "High", "Medium", "Low"],
                    [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW],
                    width=CONTENT_W * 0.65, height=160,
                )
                donut_wrapper = Table([[donut]], colWidths=[CONTENT_W])
                donut_wrapper.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), SURFACE_WHITE),
                    ("BOX",        (0, 0), (-1, -1), 0.5, SURFACE_RULE),
                    ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]))
                elems.append(donut_wrapper)
                elems.append(Paragraph(
                    "Figure 2.1 — Distribution of detected signatures by severity level.",
                    self.styles["caption"]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 3 — ANALYSIS OVERVIEW
    # ─────────────────────────────────────────────────────────────────────────

    def _build_analysis_overview(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("3", "ANALYSIS OVERVIEW"))

        analysis = data.get("analysis", {})
        parsed   = data.get("parsed", {})
        sections = parsed.get("sections", {})
        info_sec = sections.get("info", {})
        raw_info = info_sec.get("raw", {})
        machine  = raw_info.get("machine", {})
        sum_info = info_sec.get("summary", {})

        elems.append(Paragraph("Submission Details", self.styles["h2"]))
        elems.append(self._kv_table([
            ("Analysis ID",    analysis.get("analysis_id", "—")),
            ("Filename",       analysis.get("filename",    "—")),
            ("Analysis Type",  analysis.get("analysis_type", "—")),
            ("AI Model",       analysis.get("model_name",  "—")),
            ("Status",         analysis.get("status",      "—")),
            ("Started",        self._fmt_ts(analysis.get("created_at",   ""))),
            ("Completed",      self._fmt_ts(analysis.get("completed_at", ""))),
        ]))
        elems.append(Spacer(1, 8))

        elems.append(Paragraph("Sandbox Environment", self.styles["h2"]))
        elems.append(self._kv_table([
            ("CAPE Version",        raw_info.get("version",  "—")),
            ("Machine Name",        machine.get("name",      "—")),
            ("Platform",            machine.get("platform",  "—")),
            ("Package",             raw_info.get("package",  "—")),
            ("Duration",            f"{sum_info.get('total_duration_seconds', '—')} seconds"),
            ("Completion Status",   sum_info.get("execution_completion_status", "—")),
            ("Timeout",             str(sum_info.get("timeout", "—"))),
        ]))
        elems.append(Spacer(1, 8))

        components = analysis.get("components", {})
        if components:
            elems.append(Paragraph("Analysis Components", self.styles["h2"]))
            comp_rows = [
                (k.replace("_", " ").title(),
                 "✔  Enabled" if v else "✘  Disabled")
                for k, v in components.items()
            ]
            elems.append(self._kv_table(comp_rows))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 4 — FILE ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────

    def _build_file_analysis(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("4", "FILE / TARGET ANALYSIS"))

        target_sec = (data.get("parsed", {}).get("sections", {})
                         .get("target", {}).get("ai_summary", {}))

        elems.append(Paragraph("File Identity & Hashes", self.styles["h2"]))
        elems.append(self._kv_table([
            ("File Name",    target_sec.get("file_name",  "—")),
            ("File Size",    f"{target_sec.get('file_size', '—')} bytes"
                             if target_sec.get("file_size") else "—"),
            ("File Type",    (target_sec.get("file_type", "—") or "—")[:120]),
            ("CAPE Type",    target_sec.get("cape_type",  "—")),
            ("SHA-256",      target_sec.get("sha256",     "—")),
            ("MD5",          target_sec.get("md5",        "—")),
            ("Import Hash",  target_sec.get("imphash",    "—")),
            ("Compile Time", target_sec.get("compile_timestamp", "—")),
        ]))
        elems.append(Spacer(1, 8))

        elems.append(Paragraph("Attributes", self.styles["h2"]))
        elems.append(self._kv_table([
            (".NET Assembly", str(target_sec.get("is_dotnet",    "—"))),
            ("Obfuscated",   str(target_sec.get("is_obfuscated", "—"))),
            ("Packed",       str(target_sec.get("is_packed",     "—"))),
            ("Signed",       str(target_sec.get("is_signed",     "—"))),
        ]))
        elems.append(Spacer(1, 8))

        elems.append(Paragraph("Version / Masquerading Info", self.styles["h2"]))
        elems.append(self._kv_table([
            ("Company Name",       target_sec.get("company_name",       "—")),
            ("Product Name",       target_sec.get("product_name",       "—")),
            ("Original Filename",  target_sec.get("original_filename",  "—")),
            ("Legal Copyright",    target_sec.get("legal_copyright",    "—")),
        ]))

        if target_sec.get("has_self_extract"):
            elems.append(Spacer(1, 8))
            elems.append(Paragraph("Self-Extraction Details", self.styles["h2"]))
            elems.append(self._kv_table([
                ("Method",          target_sec.get("self_extract_method",    "—")),
                ("Extracted Count", str(target_sec.get("extracted_files_count", "—"))),
                ("Extracted Types", ", ".join(target_sec.get("extracted_file_types", []))),
            ]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 5 — CAPE FINDINGS
    # ─────────────────────────────────────────────────────────────────────────

    def _build_cape_findings(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("5", "CAPE SANDBOX FINDINGS"))

        cape_ai = (data.get("parsed", {}).get("sections", {})
                      .get("cape", {}).get("ai_summary", {}))

        elems.append(Paragraph("Detection Summary", self.styles["h2"]))
        elems.append(self._kv_table([
            ("Detected Families",  ", ".join(cape_ai.get("detected_families", [])) or "—"),
            ("Total Payloads",     str(cape_ai.get("total_payloads",    "—"))),
            ("Total Configs",      str(cape_ai.get("total_configs",     "—"))),
            ("Has Malware Config", str(cape_ai.get("has_malware_config","—"))),
            ("Primary Injection",  cape_ai.get("primary_injection_method", "—")),
        ]))
        elems.append(Spacer(1, 8))

        crit_yara = cape_ai.get("critical_yara_rules", [])
        if crit_yara:
            elems.append(Paragraph("Critical YARA Rules Matched", self.styles["h2"]))
            elems.extend(self._bullet_list(crit_yara))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 6 — SIGNATURES
    # ─────────────────────────────────────────────────────────────────────────

    def _build_signatures(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("6", "SIGNATURES ANALYSIS"))

        sig_ai = (data.get("parsed", {}).get("sections", {})
                     .get("signatures", {}).get("ai_summary", {}))

        if not sig_ai:
            elems.append(Paragraph("No signatures data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        elems.append(Paragraph("Signature Statistics", self.styles["h2"]))
        elems.append(self._kv_table([
            ("MalScore",              str(sig_ai.get("malscore",              "—"))),
            ("MalStatus",             sig_ai.get("malstatus",                 "—")),
            ("Total Signatures Fired", str(sig_ai.get("total_signatures",     "—"))),
            ("Critical",              str(sig_ai.get("critical_signatures",   "—"))),
            ("High / Suspicious",     str(sig_ai.get("suspicious_signatures", "—"))),
        ]))
        elems.append(Spacer(1, 8))

        high_sigs = sig_ai.get("high_severity_signatures", [])
        if high_sigs:
            elems.append(Paragraph("High-Severity Signatures", self.styles["h2"]))
            for sig in high_sigs[:15]:
                name = sig.get("name", "Unknown")
                desc = sig.get("description", "")
                elems.append(Paragraph(f"· <b>{name}</b>", self.styles["bullet"]))
                if desc:
                    elems.append(Paragraph(f"  {desc[:200]}", self.styles["body_small"]))

        capabilities = []
        if sig_ai.get("has_anti_vm"):      capabilities.append("Anti-VM / Anti-Sandbox Evasion")
        if sig_ai.get("has_persistence"):  capabilities.append("Persistence Mechanism")
        if sig_ai.get("has_injection"):    capabilities.append("Process Injection")

        if capabilities:
            elems.append(Spacer(1, 8))
            elems.append(Paragraph("Detected Capabilities", self.styles["h2"]))
            elems.extend(self._bullet_list(capabilities))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 7 — BEHAVIORAL
    # ─────────────────────────────────────────────────────────────────────────

    def _build_behavioral(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("7", "BEHAVIORAL ANALYSIS"))

        beh_ai = (data.get("parsed", {}).get("sections", {})
                     .get("behavior", {}).get("ai_summary", {}))

        if not beh_ai:
            elems.append(Paragraph("No behavior data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        elems.append(Paragraph("Execution Summary", self.styles["h2"]))
        elems.append(self._stat_cards([
            ("Processes",       str(beh_ai.get("total_processes", 0)),                "Spawned"),
            ("Files Written",   str(len(beh_ai.get("files_written", []))),            "Paths"),
            ("Mutexes",         str(len(beh_ai.get("mutexes", []))),                  "Created"),
            ("Commands",        str(len(beh_ai.get("executed_commands", []))),        "Executed"),
        ]))
        elems.append(Spacer(1, 12))

        # API call distribution chart
        call_stats = beh_ai.get("call_stats", [])
        if call_stats:
            cat_totals: Dict[str, int] = {}
            for stat in call_stats[:3]:
                for cat, count in stat.get("category_stats", {}).items():
                    cat_totals[cat] = cat_totals.get(cat, 0) + count
            if cat_totals:
                # Take top 8
                sorted_cats = sorted(cat_totals.items(), key=lambda x: x[1], reverse=True)[:8]
                labels = [k for k, _ in sorted_cats]
                values = [v for _, v in sorted_cats]
                elems.append(Paragraph("API Call Distribution", self.styles["h2"]))
                elems.append(Paragraph(
                    "Aggregate API call counts across the top 3 monitored processes.",
                    self.styles["body_small"]))
                chart = self._horizontal_bar_chart(
                    labels, values,
                    width=CONTENT_W, height=max(100, len(labels) * 18 + 40),
                    colors_list=[CHART_PALETTE[1]] * len(labels),
                )
                chart_wrapper = Table([[chart]], colWidths=[CONTENT_W])
                chart_wrapper.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), SURFACE_WHITE),
                    ("BOX",        (0, 0), (-1, -1), 0.5, SURFACE_RULE),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]))
                elems.append(chart_wrapper)
                elems.append(Paragraph(
                    "Figure 7.1 — API categories by call volume.",
                    self.styles["caption"]))
                elems.append(Spacer(1, 8))

        suspicious = beh_ai.get("suspicious_processes", [])
        if suspicious:
            elems.append(Paragraph("Suspicious Processes", self.styles["h2"]))
            for proc in suspicious[:10]:
                name = proc.get("name", "Unknown")
                pid  = proc.get("pid",  "—")
                elems.append(Paragraph(f"· <b>{name}</b>  (PID {pid})", self.styles["bullet"]))

        commands = beh_ai.get("executed_commands", [])
        if commands:
            elems.append(Spacer(1, 8))
            elems.append(Paragraph("Executed Commands", self.styles["h2"]))
            for cmd in commands[:10]:
                elems.append(Paragraph(str(cmd)[:160], self.styles["mono"]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 8 — MEMORY
    # ─────────────────────────────────────────────────────────────────────────

    def _build_memory(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("8", "MEMORY ANALYSIS"))

        mem_ai = (data.get("parsed", {}).get("sections", {})
                     .get("memory", {}).get("ai_summary", {}))

        if not mem_ai:
            elems.append(Paragraph("No memory analysis data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        elems.append(Paragraph("Memory Scan Results", self.styles["h2"]))
        elems.append(self._kv_table([
            ("Memory Dumps",          str(mem_ai.get("total_memory_dumps",             "—"))),
            ("Dumps with YARA Hits",  str(mem_ai.get("memory_dumps_with_yara",         "—"))),
            ("Shellcode Detected",    str(mem_ai.get("memory_shellcode_detected",       "—"))),
            ("Injection Detected",    str(mem_ai.get("memory_injection_detected",       "—"))),
            ("Extracted PE Files",    str(mem_ai.get("extracted_pe_from_memory_count",  "—"))),
        ]))
        elems.append(Spacer(1, 8))

        critical = mem_ai.get("critical_malware_rules", [])
        if critical:
            elems.append(Paragraph("Critical YARA Rules (Memory)", self.styles["h2"]))
            elems.extend(self._bullet_list(critical))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 9 — NETWORK
    # ─────────────────────────────────────────────────────────────────────────

    def _build_network(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("9", "NETWORK ANALYSIS"))

        net_ai = (data.get("parsed", {}).get("sections", {})
                     .get("network", {}).get("ai_summary", {}))

        if not net_ai:
            elems.append(Paragraph("No network analysis data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        elems.append(Paragraph("Connection Overview", self.styles["h2"]))
        elems.append(self._stat_cards([
            ("DNS Queries",     str(net_ai.get("total_dns_queries",    0)), "Lookups"),
            ("TCP",             str(net_ai.get("total_tcp_connections", 0)), "Connections"),
            ("UDP",             str(net_ai.get("total_udp_connections", 0)), "Connections"),
            ("Suspicious",      str(net_ai.get("has_suspicious_domains", "—")), "Domains"),
        ]))
        elems.append(Spacer(1, 10))

        domains = net_ai.get("domains", [])
        if domains:
            elems.append(Paragraph("Domains Contacted", self.styles["h2"]))
            elems.extend(self._mono_list(domains[:25]))

        ips = net_ai.get("ips", [])
        if ips:
            elems.append(Spacer(1, 8))
            elems.append(Paragraph("IP Addresses Contacted", self.styles["h2"]))
            elems.extend(self._mono_list(ips[:25]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 10 — THREAT INTEL
    # ─────────────────────────────────────────────────────────────────────────

    def _build_threat_intel(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("10", "THREAT INTELLIGENCE"))

        threat_intel = data.get("threat_intel", {})
        if not threat_intel:
            elems.append(Paragraph("No threat intelligence data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        results = threat_intel.get("results", {})

        # VirusTotal
        vt = results.get("virustotal", {})
        if vt and vt.get("success"):
            vd = vt.get("data", {})
            stats = vd.get("detection_stats", {})
            elems.append(Paragraph("VirusTotal", self.styles["h2"]))
            elems.append(self._severity_row("Threat Level",
                                            vd.get("threat_level", "UNKNOWN").upper()))
            elems.append(self._kv_table([
                ("Found",             str(vd.get("found", "—"))),
                ("Detection Ratio",   stats.get("detection_ratio", "—")),
                ("Threat Score",      str(vd.get("threat_score", "—"))),
                ("Popular Label",     vd.get("popular_threat_label", "—")),
            ]))
            elems.append(Spacer(1, 8))

        # MalwareBazaar
        mb = results.get("malwarebazaar", {})
        if mb and mb.get("success"):
            md = mb.get("data", {})
            first_s = (md.get("samples") or [{}])[0]
            elems.append(Paragraph("MalwareBazaar", self.styles["h2"]))
            elems.append(self._kv_table([
                ("Found",      str(md.get("found", "—"))),
                ("Signature",  first_s.get("signature",  "—")),
                ("Tags",       ", ".join(first_s.get("tags", []))),
                ("First Seen", first_s.get("first_seen", "—")),
            ]))
            elems.append(Spacer(1, 8))

        # Hybrid Analysis
        ha = results.get("hybrid_analysis", {})
        if ha and ha.get("success"):
            hd = ha.get("data", {})
            elems.append(Paragraph("Hybrid Analysis", self.styles["h2"]))
            elems.append(self._severity_row("Verdict",
                                            hd.get("verdict", "UNKNOWN").upper()))
            elems.append(self._kv_table([
                ("Found",       str(hd.get("found",       "—"))),
                ("Threat Score", str(hd.get("threat_score","—"))),
                ("VX Family",   hd.get("vx_family",       "—")),
            ]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 11 — MITRE
    # ─────────────────────────────────────────────────────────────────────────

    def _build_mitre(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("11", "MITRE ATT&CK MAPPING"))

        ai    = data.get("ai_analysis", {}).get("results", {})
        fs    = ai.get("final_synthesis", {}).get("analysis", {})
        mitre = fs.get("mitre_attack", {})

        if not mitre:
            sig_ai = (data.get("parsed", {}).get("sections", {})
                         .get("signatures", {}).get("ai_summary", {}))
            ttps = sig_ai.get("detected_ttps", [])
            if ttps:
                elems.append(Paragraph("Detected Techniques", self.styles["h2"]))
                elems.extend(self._bullet_list(ttps[:20]))
            else:
                elems.append(Paragraph("No MITRE ATT&CK data available.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        tactics = mitre.get("tactics", [])
        if tactics:
            elems.append(Paragraph("Observed Tactics", self.styles["h2"]))
            elems.extend(self._bullet_list(tactics[:15]))
            elems.append(Spacer(1, 8))

        techniques = mitre.get("techniques", [])
        if techniques:
            elems.append(Paragraph("Techniques", self.styles["h2"]))
            elems.extend(self._bullet_list(techniques[:25]))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 12 — IOCs
    # ─────────────────────────────────────────────────────────────────────────

    def _build_iocs(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("12", "INDICATORS OF COMPROMISE (IOCs)"))

        ai   = data.get("ai_analysis", {}).get("results", {})
        fs   = ai.get("final_synthesis", {}).get("analysis", {})
        iocs = fs.get("iocs_consolidated", {})

        if not iocs:
            elems.append(Paragraph("No IOCs identified.", self.styles["body"]))
            elems.append(PageBreak())
            return elems

        sections_map = [
            ("SHA-256 Hashes",  "sha256"),
            ("MD5 Hashes",      "md5"),
            ("Domains",         "domains"),
            ("IP Addresses",    "ip_addresses"),
            ("File Paths",      "file_paths"),
            ("Mutexes",         "mutexes"),
            ("YARA Rules",      "yara_rules"),
        ]
        for title, key in sections_map:
            items = iocs.get(key, [])
            if items:
                elems.append(Paragraph(title, self.styles["h2"]))
                elems.extend(self._mono_list(items[:25]))
                elems.append(Spacer(1, 4))

        elems.append(PageBreak())
        return elems

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 13 — INCIDENT RESPONSE
    # ─────────────────────────────────────────────────────────────────────────

    def _build_incident_response(self, data: Dict) -> list:
        elems = []
        elems.extend(self._section_header("13", "INCIDENT RESPONSE GUIDANCE"))

        ai  = data.get("ai_analysis", {}).get("results", {})
        fs  = ai.get("final_synthesis", {}).get("analysis", {})
        ir  = fs.get("incident_response",       {})
        inv = fs.get("investigation_priority",  {})

        priority = inv.get("priority_level", "")
        if priority:
            elems.append(self._severity_row("Investigation Priority", priority.upper()))
            elems.append(Spacer(1, 8))

        ir_sections = [
            ("Immediate Actions",  "immediate_actions"),
            ("Containment Steps",  "containment_steps"),
            ("Eradication Steps",  "eradication_steps"),
            ("Recovery Steps",     "recovery_steps"),
        ]
        for title, key in ir_sections:
            items = ir.get(key, [])
            if items:
                elems.append(Paragraph(title, self.styles["h2"]))
                elems.extend(self._bullet_list(items[:10]))
                elems.append(Spacer(1, 6))

        queries = inv.get("suggested_hunting_queries", [])
        if queries:
            elems.append(self._divider())
            elems.append(Paragraph("Suggested Threat Hunting Queries", self.styles["h2"]))
            for q in queries[:10]:
                elems.append(Paragraph(str(q), self.styles["mono"]))
                elems.append(Spacer(1, 3))

        return elems


# ── Singleton ─────────────────────────────────────────────────────────────────
pdf_report_service = PDFReportService()
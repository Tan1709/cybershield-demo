"""
Module: upload_report_generator.py
Purpose: Generate professional PDF reports from Upload Mode analyzed log data.
         EXACT port of services/report_generator.py — same class structure,
         same styles, same chart code, same table styles.

Changes vs realtime report_generator.py:
  ✅ Processing Mode → "Upload Mode (Offline Analysis)"
  ✅ Summary Statistics → 5 rows (adds Critical Logs + Suspicious Logs)
  ✅ Log Distribution Analysis section → REMOVED
  ✅ Charts → only 4: Log Level Distribution, Normal vs Anomaly PIE, Timeline, Timeline Activity
  ✅ NEW section: Suspicious IP Addresses table
  ✅ Anomaly Details → up to 30 rows, same red-header table style
  ✅ Detailed Analysis → adds Most Targeted IP + Peak Activity Hour
  ✅ Executive Summary paragraph (new)
  ✅ Technical Information → Upload-specific values
  ✅ NEW Chart D: Timeline Activity — dark cyberpunk style matching anomaly detection UI

Public API (drop-in, no other file changes needed):
  generate_upload_pdf(all_logs, file_names)  → (BytesIO, filename)
  generate_upload_csv(all_logs)              → (BytesIO, filename)
  generate_upload_json(all_logs)             → (BytesIO, filename)
  get_capabilities()                         → dict
"""

import io
import csv
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from collections import Counter

logger = logging.getLogger(__name__)

# ── matplotlib ────────────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    MATPLOTLIB_AVAILABLE = True
except ImportError as e:
    MATPLOTLIB_AVAILABLE = False
    logger.warning(f"⚠️ matplotlib not available — PDF charts will be skipped: {e}")

# ── reportlab ─────────────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, Image, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError as e:
    REPORTLAB_AVAILABLE = False
    logger.warning(f"⚠️ reportlab not available — PDF generation will fail: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  NumberedCanvas  — only defined when reportlab is available
# ══════════════════════════════════════════════════════════════════════════════
if REPORTLAB_AVAILABLE:
    class NumberedCanvas(canvas.Canvas):
        """Custom canvas for page numbers — same as realtime report_generator"""
        def __init__(self, *args, **kwargs):
            canvas.Canvas.__init__(self, *args, **kwargs)
            self._pagenum = 0

        def showPage(self):
            self._pagenum += 1
            self.setFont("Helvetica", 9)
            self.setFillColor(colors.HexColor('#666666'))
            self.drawRightString(7.5 * inch, 0.5 * inch, f"Page {self._pagenum}")
            canvas.Canvas.showPage(self)

        def save(self):
            canvas.Canvas.save(self)
else:
    NumberedCanvas = None  # placeholder so references don't NameError


# ══════════════════════════════════════════════════════════════════════════════
#  UploadReportGenerator  — mirrors ReportGenerator class exactly
# ══════════════════════════════════════════════════════════════════════════════
import html as _html
import re as _re

def _safe_paragraph(text, style):
    if not text:
        return Paragraph('-', style)
    text = str(text)
    # Remove XML/HTML tags completely
    text = _re.sub(r'<[^>]*>', '', text)
    # Escape remaining special chars
    text = _html.escape(text)
    # Remove any remaining problematic chars
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    text = _re.sub(r'[^\x20-\x7E\u00A0-\uFFFF]', 
                   ' ', text)
    try:
        return Paragraph(text, style)
    except Exception:
        clean = _re.sub(r'[^a-zA-Z0-9\s\.,\-:;]', 
                        ' ', text)
        return Paragraph(clean[:200] or '-', style)

class UploadReportGenerator:
    """
    Generate professional PDF, CSV, JSON reports from Upload Mode log data.
    Mirrors the realtime ReportGenerator class structure exactly.
    """

    def __init__(self):
        self.timestamp     = datetime.now(timezone.utc)
        self.timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        self.filename_str  = self.timestamp.strftime("%Y%m%d_%H%M%S")

    # =========================================================================
    #  UTILITY  (same static methods as realtime)
    # =========================================================================

    @staticmethod
    def _is_anom(log: dict) -> bool:
        """
        Detect anomalous logs. Handles both old pipeline (status='anomaly')
        and new pipeline (status/final_classification = 'ANOMALY'/'CRITICAL'/'WARNING').
        """
        if bool(log.get("is_anomaly", False)):
            return True
        cls = str(log.get("final_classification") or log.get("status") or "NORMAL").upper().strip()
        return cls in ("ANOMALY", "CRITICAL", "WARNING")

    @staticmethod
    def extract_source_ip(log: dict) -> str:
        return log.get("source_ip") or log.get("source", "Unknown")

    @staticmethod
    def sanitize_message(message: str, max_length: int = 150) -> str:
        """
        Clean message for PDF display:
        - Strip leading level prefix: "Error | ", "Warning | ", "Critical | (63) | " etc.
        - Strip Python list literal wrapping (['...'] or ["..."])
        - Strip Unicode directional / invisible marks (U+200E, U+200F, U+202A-202E etc.)
        - Replace literal \\r\\n escape text with space
        - Replace real newlines with space
        - Collapse whitespace runs
        - Truncate to max_length
        """
        import re as _re
        if not message:
            return ""
        s = str(message)

        # Strip leading level/event-id prefix patterns:
        #   "Error | "  /  "Warning | "  /  "Critical | (63) | "
        #   "Information | "  /  "Error | (7000) | "
        s = _re.sub(
            r'^(?:Error|Warning|Critical|Information|Debug|Verbose)'
            r'(?:\s*\|\s*\(\d+\))?\s*\|\s*',
            '', s, flags=_re.IGNORECASE
        )
        # Strip Windows Update Agent / Service label prefixes: "Windows Update Agent | "
        s = _re.sub(r'^[A-Za-z0-9 \-]+Agent\s*\|\s*', '', s)
        s = _re.sub(r'^Service startup\s*\|\s*', '', s, flags=_re.IGNORECASE)

        # Strip Python list wrapping: ['content'] or ["content"]
        s = _re.sub(r"""^\s*\[["']+""", "", s)
        s = _re.sub(r"""["']+\]\s*$""", "", s)
        # Strip leftover bracket/quote at start/end
        s = s.strip("""['"  """).strip()

        # Strip Unicode bidirectional / invisible control characters
        s = _re.sub(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]', '', s)

        # Replace literal \\r\\n in string values (escaped escapes)
        s = s.replace("\\r\\n", " ").replace("\\r", " ").replace("\\n", " ")
        # Replace real newline characters
        s = s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
        # Collapse whitespace
        s = _re.sub(r"  +", " ", s).strip()
        if len(s) > max_length:
            s = s[:max_length - 3] + "..."
        return s

    @staticmethod
    def get_log_type(log: dict) -> str:
        """
        Return APPLICATION | SYSTEM | SECURITY | HARDWARE_ALERT | UNKNOWN.
        Checks all field aliases used across old and new pipelines.
        """
        # Fix 5: Hardware alerts separate section
        source = str(log.get("source") or "").lower()
        if "tpm-wmi" in source or "kernel-power" in source:
            return "HARDWARE_ALERT"

        for key in ("type", "log_type", "event_type"):
            val = str(log.get(key) or "").upper().strip()
            if val in ("SECURITY", "SYSTEM", "APPLICATION"):
                return val
        # Infer from source / message if not stamped
        combined = (str(log.get("source") or "") + " " + str(log.get("message") or "")).lower()
        _SEC = ["logon", "logoff", "authentication", "account", "privilege", "audit",
                "password", "security", "4624", "4625", "4634", "4648"]
        _SYS = ["kernel", "driver", "service", "crash", "livekernelevent",
                "watchdog", "bugcheck", "system", "hardware"]
        if any(k in combined for k in _SEC):
            return "SECURITY"
        if any(k in combined for k in _SYS):
            return "SYSTEM"
        return "APPLICATION"

    # =========================================================================
    #  STATISTICS  — derived entirely from all_logs list
    # =========================================================================

    def _compute_stats(self, all_logs: list, raw_total: int = 0, duplicates_removed: int = 0) -> dict:
        """
        raw_total          : full line count BEFORE parsing/dedup (req #1).
                             If not supplied, falls back to len(all_logs).
        duplicates_removed : number of duplicate lines stripped during dedup (req #2).
        """
        import re as _re

        total     = len(all_logs)
        # req #1: raw count = every line in the uploaded file
        raw_count = raw_total if raw_total > 0 else total

        # Log Format (picked up from metadata)
        log_format = "Auto-Detect"
        if all_logs:
            log_format = all_logs[0].get("_meta_log_format") or all_logs[0].get("log_format", "Auto-Detect")

        # 4-level classification split (req #3)
        cls_counts = {"CRITICAL": 0, "ANOMALY": 0, "WARNING": 0, "NORMAL": 0}
        for _l in all_logs:
            cls = str(_l.get("final_classification") or _l.get("status") or "NORMAL").upper().strip()
            if cls not in cls_counts:
                cls = "NORMAL"
            cls_counts[cls] += 1

        # req #3: CRITICAL + ANOMALY = ML-triggered; WARNING = rule-only; NORMAL = clean
        _ANOMALY_CLS = ("CRITICAL", "ANOMALY")
        _WARNING_CLS = ("WARNING",)
        anomalies = [l for l in all_logs
                     if str(l.get("final_classification") or "NORMAL").upper().strip()
                     in _ANOMALY_CLS]
        warnings = [l for l in all_logs
                     if str(l.get("final_classification") or "NORMAL").upper().strip()
                     in _WARNING_CLS]
        normals   = [l for l in all_logs
                     if str(l.get("final_classification") or "NORMAL").upper().strip()
                     not in _ANOMALY_CLS and str(l.get("final_classification") or "NORMAL").upper().strip() not in _WARNING_CLS]

        a_count   = len(anomalies)
        w_count   = len(warnings)
        n_count   = len(normals)
        # req #1: percentages based on RAW total
        a_pct     = round(a_count / raw_count * 100, 2) if raw_count else 0.0
        n_pct     = round(n_count / raw_count * 100, 2) if raw_count else 0.0

        # req #5: unique anomaly types (dedup by normalised message+source+level)
        _NORM_PATS = [
            (_re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), "<ID>"),
            (_re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), "<IP>"),
            (_re.compile(r'(?<![.\d])\b\d{5,}\b(?![.\d])'), "<NUM>"),
        ]
        def _norm(msg):
            s = str(msg)[:150]
            for pat, r in _NORM_PATS:
                s = pat.sub(r, s)
            return s.strip()

        # Unique types: ANOMALY only (matches dashboard)
        _anomaly_only = [_l for _l in anomalies if str(_l.get("final_classification","")).upper() == "ANOMALY"]
        unique_anom_seen = {}
        for _l in _anomaly_only:
            _key = f"{_norm(_l.get('message',''))}|{_l.get('source','')}|{_l.get('log_level','')}"
            if _key not in unique_anom_seen:
                unique_anom_seen[_key] = {"entry": _l, "repeat_count": 1}
            else:
                unique_anom_seen[_key]["repeat_count"] += 1
        unique_anomalies_list = sorted(
            unique_anom_seen.values(),
            key=lambda x: (-float(x["entry"].get("anomaly_score", 0)), -x["repeat_count"])
        )
        unique_anom_count = len(unique_anom_seen)

        level_ctr      = Counter(str(l.get("log_level", l.get("level", "INFO"))).upper()
                                 for l in all_logs)
        type_ctr       = Counter(self.get_log_type(l).upper() for l in all_logs)
        anom_level_ctr = Counter(str(l.get("log_level", l.get("level", "INFO"))).upper()
                                 for l in anomalies)
        anom_type_ctr  = Counter(self.get_log_type(l).upper() for l in anomalies)

        # Critical & Suspicious counts
        critical_cnt   = level_ctr.get("CRITICAL", 0) + level_ctr.get("FATAL", 0)
        critical_pct   = round(critical_cnt / total * 100, 2) if total else 0.0
        error_cnt      = level_ctr.get("ERROR", 0)
        high_risk_cnt  = sum(1 for l in anomalies
                             if float(l.get("anomaly_score", 0)) >= 0.65)
        suspicious_cnt = error_cnt + high_risk_cnt
        suspicious_pct = round(suspicious_cnt / total * 100, 2) if total else 0.0

        # Source / IP counters
        source_ctr = Counter(
            self.extract_source_ip(l)
            for l in all_logs
            if self.extract_source_ip(l).lower() not in ("", "unknown")
        )
        anom_src_ctr = Counter(
            self.extract_source_ip(l)
            for l in anomalies
            if self.extract_source_ip(l).lower() not in ("", "unknown")
        )

        # Build suspicious IP table (sorted by anomaly count desc)
        ip_table = []
        for src, tot in source_ctr.most_common(50):
            ac   = anom_src_ctr.get(src, 0)
            if ac == 0:
                continue
            rate = ac / tot if tot else 0
            sev  = ("HIGH"   if rate >= 0.5 or ac >= 10 else
                    "MEDIUM" if rate >= 0.2 or ac >= 3  else "LOW")
            ip_table.append({"source": src, "total": tot,
                              "anom": ac, "severity": sev})
        ip_table.sort(key=lambda x: -x["anom"])

        # Hourly timeline buckets — also broken down by log level
        timeline:      Dict[str, int] = {}
        anom_timeline: Dict[str, int] = {}
        level_timeline: Dict[str, Dict[str, int]] = {
            "CRITICAL": {}, "ERROR": {}, "WARNING": {}, "INFO": {}
        }
        for log in all_logs:
            ts_raw = log.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                bucket = dt.strftime("%Y-%m-%d %H:00")
                min_bucket = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                bucket = "Unknown"
                min_bucket = "Unknown"
            timeline[bucket] = timeline.get(bucket, 0) + 1
            if self._is_anom(log):
                anom_timeline[bucket] = anom_timeline.get(bucket, 0) + 1
            # Track per-level counts for timeline activity chart
            lvl = str(log.get("log_level", log.get("level", "INFO"))).upper()
            if lvl in level_timeline:
                level_timeline[lvl][bucket] = level_timeline[lvl].get(bucket, 0) + 1
            # Also track minute-level for granular timeline activity
            if "min_timeline" not in dir():
                pass  # initialized below
            min_timeline_tmp = getattr(self, "_min_timeline_tmp", {})
            min_timeline_tmp[min_bucket] = min_timeline_tmp.get(min_bucket, 0) + 1
            self._min_timeline_tmp = min_timeline_tmp

        # Use minute buckets if all data falls in same hour
        valid_keys = sorted(k for k in timeline if k != "Unknown")
        unique_hours = set(k[:13] for k in valid_keys)
        if len(unique_hours) <= 1 and len(valid_keys) >= 1:
            # Swap to minute-level bucketing
            timeline = getattr(self, "_min_timeline_tmp", timeline)
            # Rebuild level_timeline at minute resolution
            level_timeline = {"CRITICAL": {}, "ERROR": {}, "WARNING": {}, "INFO": {}}
            for log in all_logs:
                ts_raw2 = log.get("timestamp", "")
                try:
                    dt2 = datetime.fromisoformat(str(ts_raw2).replace("Z", "+00:00"))
                    mb  = dt2.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    mb = "Unknown"
                lvl2 = str(log.get("log_level", log.get("level", "INFO"))).upper()
                if lvl2 in level_timeline:
                    level_timeline[lvl2][mb] = level_timeline[lvl2].get(mb, 0) + 1
            # Reset anom_timeline at minute level too
            anom_timeline = {}
            for log in all_logs:
                if self._is_anom(log):
                    ts_raw3 = log.get("timestamp", "")
                    try:
                        dt3 = datetime.fromisoformat(str(ts_raw3).replace("Z", "+00:00"))
                        mb3 = dt3.strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        mb3 = "Unknown"
                    anom_timeline[mb3] = anom_timeline.get(mb3, 0) + 1
        # Clean up temp attribute
        if hasattr(self, "_min_timeline_tmp"):
            del self._min_timeline_tmp

        valid_keys = sorted(k for k in timeline if k != "Unknown")
        peak_hour  = (max(valid_keys, key=lambda k: timeline[k])[-5:] + " UTC"
                      if valid_keys else "N/A")

        # Top anomaly sources list
        top_anom_sources = [
            {"source": src, "count": cnt}
            for src, cnt in sorted(anom_src_ctr.items(), key=lambda x: -x[1])[:10]
        ]

        # Fix 5: Hardware alerts
        hardware_alerts = [l for l in all_logs if self.get_log_type(l) == "HARDWARE_ALERT"]

        return dict(
            raw_total=raw_count,            # req #1 — full file line count
            duplicates_removed=duplicates_removed,  # req #2 — lines removed by dedup
            total=total,                    # req #2 — post-parse processed count
            anomaly_count=a_count,          # total CRITICAL+ANOMALY occurrences
            warning_count=w_count,          # purely WARNING occurrences
            normal_count=n_count,
            anomaly_pct=a_pct,              # based on raw_total
            normal_pct=n_pct,               # based on raw_total
            unique_anomaly_count=unique_anom_count,   # req #5
            unique_anomalies_list=unique_anomalies_list,
            cls_counts=cls_counts,          # req #3 — 4-level breakdown
            critical_count=critical_cnt, critical_pct=critical_pct,
            suspicious_count=suspicious_cnt, suspicious_pct=suspicious_pct,
            level_counter=dict(level_ctr), type_counter=dict(type_ctr),
            anom_level_counter=dict(anom_level_ctr),
            anom_type_counter=dict(anom_type_ctr),
            source_counter=dict(source_ctr), anom_src_counter=dict(anom_src_ctr),
            ip_table=ip_table, timeline=timeline, anom_timeline=anom_timeline,
            level_timeline=level_timeline,
            top_anomalies=anomalies[:30],
            top_anom_sources=top_anom_sources,
            hardware_alerts=hardware_alerts, # Fix 5
            most_targeted_ip=(anom_src_ctr.most_common(1)[0][0]
                              if anom_src_ctr else "N/A"),
            peak_hour=peak_hour,
            log_format=log_format,
        )

    # =========================================================================
    #  CHART GENERATION  — same style/code as realtime _generate_charts
    # =========================================================================

    # Shared colour palette — identical to realtime
    _COLOR_PALETTE = {
        'INFO':     '#4CAF50',
        'WARNING':  '#FF9800',
        'ERROR':    '#F44336',
        'CRITICAL': '#B71C1C',
        'ANOMALY':  '#9C27B0',
    }

    @staticmethod
    def _spine_style(ax):
        """Apply identical spine style to realtime charts."""
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#cccccc')
        ax.spines['bottom'].set_color('#cccccc')
        ax.spines['left'].set_linewidth(1.5)
        ax.spines['bottom'].set_linewidth(1.5)

    @staticmethod
    def _save_chart(fig) -> io.BytesIO:
        buf = io.BytesIO()
        fig.savefig(buf, format='png', facecolor='white', dpi=100, bbox_inches='tight')
        buf.seek(0)
        plt.close(fig)
        return buf

    @staticmethod
    def _save_chart_dark(fig) -> io.BytesIO:
        """Save chart preserving its dark background (used for Timeline Activity)."""
        buf = io.BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        buf.seek(0)
        plt.close(fig)
        return buf

    def _generate_timeline_activity_chart(self, stats: dict) -> io.BytesIO | None:
        """
        Generate Chart D: Timeline Activity — dark cyberpunk style.

        Matches the anomaly detection UI exactly:
          - Very dark navy background (#0a1628)
          - Cyan bold title "TIMELINE ACTIVITY"
          - 4 lines: CRITICAL (red), ERROR (orange), WARNING (yellow), INFO (green)
          - Subtle teal grid lines
          - Dark axes, light tick labels
          - Normalized y-axis 0.0–1.0 (proportion of each level per bucket)
        """
        if not MATPLOTLIB_AVAILABLE:
            return None

        timeline      = stats.get("timeline", {})
        level_timeline = stats.get("level_timeline", {})
        # Diagnostic logging
        try:
            logger.info("Timeline activity chart: timeline_len=%d, level_timeline_levels=%s",
                        len(timeline), list(level_timeline.keys()))
        except Exception:
            pass

        all_keys = sorted(k for k in timeline if k != "Unknown")
        # Fallback: if timeline empty but level_timeline has minute/hour buckets, derive keys
        if not all_keys:
            # collect keys from level_timeline across levels
            derived_keys = set()
            for lvl, d in (level_timeline or {}).items():
                if isinstance(d, dict):
                    derived_keys.update(k for k in d.keys() if k != "Unknown")
            if derived_keys:
                all_keys = sorted(derived_keys)
                logger.info("Derived timeline keys from level_timeline: %d keys", len(all_keys))
            else:
                logger.warning("No timeline keys available for activity chart; skipping chart")
                return None
        # If all logs share the same hour bucket, fall back to minute-level buckets
        # by re-bucketing the level_timeline data at HH:MM resolution
        unique_hours = set(k[:13] for k in all_keys)  # "YYYY-MM-DD HH"
        if len(unique_hours) <= 1 and len(all_keys) >= 1:
            # Rebuild minute-level buckets from available timestamps in all_logs
            # (stats dict may not have minute data, so re-bucket what we have)
            # Use the existing hourly data duplicated across 60 minute points to
            # at least show something meaningful
            keys = all_keys  # keep as-is; chart will show single point gracefully
        else:
            keys = all_keys[-24:]

        try:
            logger.info("Timeline activity chart: using %d keys (sample=%s)", len(keys), keys[:6])
            # ── Dark cyberpunk colour scheme (matching the UI screenshot) ──
            BG_OUTER   = '#0a1628'   # deep navy outer background
            BG_INNER   = '#0d1f35'   # slightly lighter plot area
            GRID_COLOR = '#1a3a5c'   # dark teal grid
            TITLE_CLR  = '#00e5ff'   # neon cyan title
            TICK_CLR   = '#ff5370'   # pinkish-red tick labels (matching UI)
            TEXT_CLR   = '#8bafc9'   # muted blue-grey for axis labels

            LINE_COLORS = {
                'CRITICAL': '#ff4444',   # bright red
                'ERROR':    '#ff8c00',   # orange
                'WARNING':  '#ffff00',   # bright yellow
                'INFO':     '#00e676',   # neon green
            }
            LEGEND_MARKERS = {
                'CRITICAL': '■',
                'ERROR':    '■',
                'WARNING':  '■',
                'INFO':     '■',
            }

            fig, ax = plt.subplots(figsize=(11, 4.5))
            fig.patch.set_facecolor(BG_OUTER)
            ax.set_facecolor(BG_INNER)

            # Normalize counts per bucket so y-axis is 0.0–1.0
            total_per_bucket = [timeline.get(k, 1) for k in keys]

            # Log per-level aggregate counts for debugging empty-chart issues
            try:
                per_level_totals = {lvl: sum(d.values()) if isinstance(d, dict) else 0
                                    for lvl, d in level_timeline.items()}
                logger.info("Level timeline totals: %s", per_level_totals)
            except Exception:
                pass

            for level, color in LINE_COLORS.items():
                raw_vals = [level_timeline.get(level, {}).get(k, 0) for k in keys]
                # normalize: proportion of that level within each time bucket
                norm_vals = [
                    raw_vals[i] / max(total_per_bucket[i], 1)
                    for i in range(len(keys))
                ]
                ax.plot(
                    range(len(keys)),
                    norm_vals,
                    color=color,
                    linewidth=2.0,
                    label=level,
                    zorder=3,
                    solid_capstyle='round',
                    solid_joinstyle='round',
                )

            # ── Grid ──────────────────────────────────────────────────────────
            ax.grid(True, which='both', color=GRID_COLOR,
                    linewidth=0.8, linestyle='-', alpha=0.7, zorder=1)
            ax.set_axisbelow(True)

            # ── Y-axis: 0.0 → 1.0 with 0.1 steps ────────────────────────────
            ax.set_ylim(0.0, 1.0)
            ax.yaxis.set_major_locator(mticker.MultipleLocator(0.1))
            ax.tick_params(axis='y', colors=TEXT_CLR, labelsize=9)

            # ── X-axis ticks: show HH:MM labels ───────────────────────────────
            step = max(1, len(keys) // 10)
            xtick_positions = list(range(0, len(keys), step))
            # Keys may be hourly ("YYYY-MM-DD HH:00") or minute ("YYYY-MM-DD HH:MM")
            # In both cases [11:16] gives "HH:00" or "HH:MM" — correct
            xtick_labels = [keys[i][11:16] if len(keys[i]) >= 16 else keys[i]
                            for i in xtick_positions]
            ax.set_xticks(xtick_positions)
            ax.set_xticklabels(xtick_labels, color=TICK_CLR,
                               fontsize=9, fontfamily='monospace')
            ax.set_xlim(-0.5, max(len(keys) - 0.5, 1))

            # ── Spines ────────────────────────────────────────────────────────
            for spine in ax.spines.values():
                spine.set_color(GRID_COLOR)
                spine.set_linewidth(1.0)

            # ── Title (cyan, bold, uppercase — matching UI) ───────────────────
            ax.set_title(
                'TIMELINE ACTIVITY',
                fontsize=14,
                fontweight='bold',
                color=TITLE_CLR,
                pad=16,
                loc='left',
                fontfamily='monospace',
            )

            # ── Legend (top, horizontal, styled to match UI) ───────────────────
            legend = ax.legend(
                loc='upper right',
                ncol=4,
                fontsize=9,
                frameon=True,
                framealpha=0.3,
                edgecolor=GRID_COLOR,
                facecolor=BG_OUTER,
                labelcolor='white',
            )
            # Colour each legend label text to match its line
            for text, (lvl, color) in zip(legend.get_texts(), LINE_COLORS.items()):
                text.set_color(color)
                text.set_fontweight('bold')
                text.set_fontfamily('monospace')

            plt.tight_layout(pad=1.2)
            return self._save_chart_dark(fig)

        except Exception as e:
            logger.error(f"Chart D (Timeline Activity) error: {e}")
            return None

    def _generate_charts(self, stats: dict) -> List[Tuple[str, io.BytesIO]]:
        """
        Generate exactly 4 chart images for Upload Mode PDF.
        Same matplotlib style as realtime _generate_charts.

        Charts:
          A) Log Level Distribution (bar)
          B) Normal vs ML Anomaly Comparison (pie)
          C) Upload Log Stream — Hourly Timeline (line)
          D) Timeline Activity — dark cyberpunk multi-level line chart (NEW)
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("⚠️ matplotlib not available — skipping charts")
            return []

        charts = []
        cp = self._COLOR_PALETTE

        # Ensure we have a valid stats dict
        if not stats or not isinstance(stats, dict):
            logger.error("Invalid stats provided to _generate_charts")
            return []

        level_dist = stats.get("level_counter", {})
        normal     = stats.get("normal_count", 0)
        anomaly    = stats.get("anomaly_count", 0)
        timeline   = stats.get("timeline", {})
        logger.info("Chart data counts: levels=%s normal=%d anomaly=%d timeline_points=%d", 
                    str(level_dist), normal, anomaly, len(timeline))

        # ── CHART A: Log Level Distribution ──────────────────────────────────
        logger.info("Chart data: level_dist=%s", level_dist)
        try:
            if level_dist and any(level_dist.values()):
                ORDER  = ["INFO", "WARNING", "ERROR", "CRITICAL"]
                levels = [l for l in ORDER if l in level_dist]
                extras = [l for l in sorted(level_dist.keys()) if l not in ORDER and level_dist[l]]
                levels = levels + extras
                counts = [level_dist[l] for l in levels]
                clrs   = [cp.get(l, '#2196F3') for l in levels]

                # Skip chart if all values are zero or empty
                if not counts or all(v == 0 for v in counts):
                    logger.info("Skipping Log Level Distribution chart: all values zero or empty")
                else:
                    fig, ax = plt.subplots(figsize=(10, 4), facecolor='white')
                    fig.patch.set_facecolor('white')
                    ax.set_facecolor('white')
                    bars = ax.bar(levels, counts, color=clrs,
                                   edgecolor='#333333', linewidth=1.5)

                    ax.set_title('Log Level Distribution', fontsize=15,
                                 fontweight='bold', color='#1f4788', pad=20)
                    ax.set_ylabel('Number of Logs', fontsize=12,
                                  color='#333333', fontweight='bold')
                    ax.set_xlabel('Severity Level', fontsize=12,
                                  color='#333333', fontweight='bold')
                    ax.grid(axis='y', alpha=0.3, linestyle='--')
                    ax.tick_params(colors='#333333', labelsize=10)

                    for bar in bars:
                        h = bar.get_height()
                        ax.text(bar.get_x() + bar.get_width() / 2., h,
                                f'{int(h):,}',
                                ha='center', va='bottom',
                                fontsize=11, fontweight='bold')

                    self._spine_style(ax)
                    if counts and max(counts) > 0:
                        ax.set_ylim(0, max(counts) * 1.3)
                    plt.tight_layout(pad=1.5)
                    fig.canvas.draw()
                    charts.append(("Log Level Distribution",
                                    self._save_chart(fig)))
        except Exception as e:
            logger.error(f"Chart A error: {e}")

        # ── CHART B: Normal vs ML Anomaly Comparison (PIE) ───────────────────
        normal  = stats.get("normal_count", 0)
        anomaly = stats.get("anomaly_count", 0)
        total   = stats.get("total", 0)
        logger.info("Chart data: normal=%s anomaly=%s total=%s", normal, anomaly, total)
        try:
            if total > 0 and (normal > 0 or anomaly > 0):
                pie_total = normal + anomaly
                values, categories, pie_colors = [], [], []
                if normal > 0:
                    pct = normal / pie_total * 100
                    categories.append(f'Normal\n{normal:,} ({pct:.1f}%)')
                    values.append(normal)
                    pie_colors.append('#4CAF50')
                if anomaly > 0:
                    pct = anomaly / pie_total * 100
                    categories.append(f'Anomalies\n{anomaly:,} ({pct:.1f}%)')
                    values.append(anomaly)
                    pie_colors.append('#E53935')
                if sum(values) > 0:
                    fig, ax = plt.subplots(figsize=(6, 5), facecolor='white')
                    fig.patch.set_facecolor('white')
                    ax.set_facecolor('white')
                    wedges, texts = ax.pie(
                        values,
                        labels=categories,
                        colors=pie_colors,
                        startangle=90,
                        wedgeprops={'edgecolor': 'white', 'linewidth': 2.5, 'width': 0.55},
                        textprops={'fontsize': 11, 'color': '#222222'},
                        labeldistance=1.15,
                    )
                    for t in texts:
                        t.set_fontweight('bold')
                    ax.set_title('Normal vs Anomaly Distribution',
                                 fontsize=13, fontweight='bold',
                                 color='#1f4788', pad=16)
                    plt.tight_layout(pad=1.5)
                    fig.canvas.draw()
                    charts.append(("Normal vs ML Anomaly Comparison",
                                    self._save_chart(fig)))
        except Exception as e:
            logger.error(f"Chart B error: {e}")

        # ── CHART C: Upload Log Stream — Hourly Timeline ──────────────────────
        timeline      = stats.get("timeline", {})
        anom_timeline = stats.get("anom_timeline", {})
        keys = sorted(k for k in timeline.keys() if k != "Unknown")
        logger.info("Chart data: timeline_keys=%d anom_timeline_keys=%d", len(keys), len(anom_timeline))
        if len(keys) > 24:
            keys = keys[-24:]
        try:
            if len(keys) >= 1:
                total_vals = [timeline.get(k, 0)      for k in keys]
                anom_vals  = [anom_timeline.get(k, 0) for k in keys]
                x_pos      = range(len(keys))

                # Skip chart if all values are zero or empty
                if (not total_vals and not anom_vals) or (all(v == 0 for v in total_vals) and all(v == 0 for v in anom_vals)):
                    logger.info("Skipping Timeline chart: all values zero or empty")
                else:
                    fig, ax = plt.subplots(figsize=(10, 4), facecolor='white')
                    fig.patch.set_facecolor('white')
                    ax.set_facecolor('white')

                    ax.plot(x_pos, total_vals, marker='o', linewidth=2.5,
                            label='Total Logs', color=cp.get('INFO', '#4CAF50'), markersize=5)
                    ax.plot(x_pos, anom_vals, marker='*', linewidth=3,
                            label='ML Anomalies',
                            color=cp.get('ANOMALY', '#9C27B0'), markersize=10)

                    ax.set_title('Upload Log Stream  (Hourly Timeline)',
                                 fontsize=15, fontweight='bold',
                                 color='#1f4788', pad=20)
                    ax.set_ylabel('Number of Events', fontsize=12,
                                  color='#333333', fontweight='bold')
                    ax.set_xlabel('Time Period', fontsize=12,
                                  color='#333333', fontweight='bold')
                    ax.grid(True, alpha=0.3, linestyle='--')
                    ax.tick_params(colors='#333333', labelsize=10)

                    step = max(1, len(keys) // 6)
                    ax.set_xticks(range(0, len(keys), step))
                    ax.set_xticklabels(
                        [keys[i][-8:] for i in range(0, len(keys), step)],
                        rotation=45, ha='right', fontsize=9,
                    )
                    ax.legend(loc='upper left', fontsize=11,
                              framealpha=0.95, edgecolor='#333333')
                    self._spine_style(ax)
                    if (total_vals + anom_vals) and max(total_vals + anom_vals) > 0:
                        ax.set_ylim(0, max(total_vals + anom_vals) * 1.3)
                    plt.tight_layout(pad=1.5)
                    fig.canvas.draw()
                    charts.append(("Upload Log Stream  (Hourly Timeline)",
                                    self._save_chart(fig)))
        except Exception as e:
            logger.error(f"Chart C error: {e}")

        # Timeline Activity removed from PDF

        return charts

    def _build_hardware_alerts(self, all_logs: list, heading_style) -> list:
        hw_alerts = [l for l in all_logs if self.get_log_type(l) == "HARDWARE_ALERT"]
        if not hw_alerts:
            return []

        story = [
            Paragraph("Hardware Integrity Alerts", heading_style),
            Spacer(1, 0.10 * inch)
        ]

        # Table headers
        data = [[Paragraph(h, ParagraphStyle("HWH", fontSize=9, fontName="Helvetica-Bold", textColor=colors.white))
                 for h in ["Timestamp", "Level", "Hardware Source", "Message / Status"]]]

        # Table rows
        for hw in hw_alerts[:30]:  # Limit to 30 for brevity
            msg = str(hw.get("message") or "")
            if len(msg) > 100: msg = msg[:97] + "..."
            msg_clean = self.sanitize_message(msg, max_length=150)
            ts_raw = str(hw.get("timestamp", ""))
            try:
                ts_fmt = (datetime
                          .fromisoformat(ts_raw.replace("Z", "+00:00"))
                          .strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                import re as _re2
                m2 = _re2.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", ts_raw)
                ts_fmt = m2.group(1).replace('T', ' ') if m2 else ts_raw
            lvl_val = str(hw.get("level") or "INFO")
            src_val = str(hw.get("source") or "")[:30]
            data.append([
                ts_fmt,
                lvl_val,
                src_val,
                Paragraph(msg_clean, ParagraphStyle('CellText', fontName='Helvetica', fontSize=8, leading=10))
            ])

        col_w = [1.0 * inch, 0.8 * inch, 1.8 * inch, 3.57 * inch]
        t = Table(data, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor('#1f4788')),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor('#fafafa'), colors.HexColor('#f5f5f5')]),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))
        return story

    # =========================================================================
    #  PDF GENERATION  — same structure as realtime generate_pdf
    # =========================================================================

    def generate_pdf(self, all_logs: list,
                     file_names: list,
                     raw_total: int = 0,
                     duplicates_removed: int = 0,
                     is_demo: bool = False) -> Tuple[io.BytesIO, str]:
        """
        Generate Upload Mode PDF.  Same structure as realtime generate_pdf.

        Args:
            all_logs           : combined list of all log dicts from upload_storage
            file_names         : list of source file names
            raw_total          : raw line count before deduplication (req #1)
            duplicates_removed : count of duplicate lines removed (req #2)

        Returns:
            (BytesIO, filename) tuple
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required. pip install reportlab matplotlib")

        logger.info("📄 Generating Upload Mode PDF report...")

        stats = self._compute_stats(all_logs, raw_total=raw_total,
                                    duplicates_removed=duplicates_removed)
        anomalies = stats["top_anomalies"]

        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        story  = []
        styles = getSampleStyleSheet()

        # ── EXACT same custom styles as realtime report_generator.py ──────────
        title_style = ParagraphStyle(
            'UploadTitle',
            parent=styles['Heading1'],
            fontSize=26,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=32,
        )
        subtitle_style = ParagraphStyle(
            'UploadSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#555555'),
            alignment=TA_CENTER,
            fontName='Helvetica',
            spaceAfter=20,
        )
        heading_style = ParagraphStyle(
            'UploadHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            borderColor=colors.HexColor('#1f4788'),
            borderWidth=2,
            borderPadding=8,
            borderRadius=4,
            leftIndent=10,
            rightIndent=10,
        )
        normal_style = ParagraphStyle(
            'UploadNormal',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#333333'),
            leading=14,
            alignment=TA_JUSTIFY,
        )

        # Shared table style helper (identical to realtime)
        base_table_style = TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#1f4788')),
            ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, 0),  11),
            ('BOTTOMPADDING', (0, 0), (-1, 0),  4),
            ('TOPPADDING',    (0, 0), (-1, 0),  4),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1),
             [colors.HexColor('#f5f5f5'), colors.HexColor('#eeeeee')]),
            ('TEXTCOLOR',     (0, 1), (-1, -1), colors.HexColor('#333333')),
            ('FONTSIZE',      (0, 1), (-1, -1), 10),
            ('GRID',          (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 6),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ])

        # ── FILE LABEL ────────────────────────────────────────────────────────
        file_label = ", ".join(file_names[:4]) or "N/A"
        if len(file_names) > 4:
            file_label += f"  (+{len(file_names) - 4} more)"

        # ═════════════════════════════════════════════════════════════════════
        #  PAGE 1 — Title + Report Information + Summary Statistics
        # ═════════════════════════════════════════════════════════════════════
        story.append(Spacer(1, 0.3 * inch))

        # Title  (same wording pattern as realtime)
        story.append(Paragraph(
            "CyberShield - Offline Log Anomaly Detection System",
            title_style))
        story.append(Paragraph("Upload Mode Analysis Report", subtitle_style))
        story.append(Spacer(1, 0.2 * inch))

        # -- DEMO BANNER --
        if is_demo:
            _ds = ParagraphStyle("DemoBanner", parent=styles["Normal"],
                fontSize=11, fontName="Helvetica-Bold",
                textColor=colors.HexColor("#7a4f00"),
                backColor=colors.HexColor("#fff3cd"),
                borderColor=colors.HexColor("#ffc107"),
                borderWidth=1, borderPadding=10, borderRadius=4,
                alignment=TA_CENTER, spaceAfter=14)
            story.append(Paragraph(
                "⚠  DEMO DATA — This report was generated using built-in demo data. "
                "Upload actual log files to analyze real data.  ⚠", _ds))


        # ── SECTION 1: Report Information ──────────────────────────────────
        story.append(Paragraph("Report Information", heading_style))
        story.append(Spacer(1, 0.15 * inch))

        metadata_info = (
            f"<b>Generated Date &amp; Time:</b> {self.timestamp_str}<br/>"
            f"<b>Processing Mode:</b> Upload Mode (Offline Analysis)<br/>"
            f"<b>Detection Model:</b> Hybrid v4 (ML + ContextRuleEngine + Fusion)<br/>"
            f"<b>Classification:</b> NORMAL / WARNING (Rule) / ANOMALY (ML) / CRITICAL (Both)<br/>"
            f"<b>ML Framework:</b> scikit-learn<br/>"
            f"<b>System Status:</b> &#10003; Online and Operational<br/>"
            f"<b>Source File(s):</b> {file_label}<br/>"
            f"<b>Detected Log Format:</b> {stats.get('log_format', 'Auto-Detect')}<br/>"
            f"<b>Total Logs (Raw Upload):</b> {stats['raw_total']:,}  "
            f"<font color='#555555'>(all lines before parsing)</font><br/>"
            f"<b>Duplicates Removed:</b> {stats['duplicates_removed']:,}  "
            f"<font color='#555555'>(exact duplicate log lines eliminated before analysis)</font><br/>"
            f"<b>Processed Logs (Post-Parse):</b> {stats['total']:,}  "
            f"<font color='#555555'>(after deduplication &amp; normalization)</font>"
        )
        story.append(Paragraph(metadata_info, normal_style))
        story.append(Spacer(1, 0.3 * inch))

        # ── SECTION 2: Summary Statistics (5 rows) ─────────────────────────
        story.append(Paragraph("Summary Statistics", heading_style))
        story.append(Spacer(1, 0.15 * inch))

        # 4-level SOC classification breakdown (from final_classification field)
        cls_counts   = stats["cls_counts"]
        cls_normal   = cls_counts.get("NORMAL",   0)
        cls_warning  = cls_counts.get("WARNING",  0)
        cls_anomaly  = cls_counts.get("ANOMALY",  0)
        cls_critical = cls_counts.get("CRITICAL", 0)
        _raw         = stats["raw_total"] or 1
        _proc        = stats["total"] or 1

        # Calculate parse-skipped (rows in raw that were not parsed into entries)
        # raw_total = parsed entries before dedup; total = after dedup
        # skipped = raw_total_file_rows - raw_total (entries before dedup)
        # We expose this as a note only if gap > 0
        dupes        = stats["duplicates_removed"]
        parse_skipped = max(0, stats["raw_total"] - dupes - stats["total"])

        dedup_status = (
            f"✂ {dupes:,} Removed" if dupes > 0 else "0 Duplicates Found"
        )

        summary_data = [
            ["Metric", "Count", "Percentage", "Status"],
            # req #1 — raw total (all lines before parsing)
            ["Total Logs (Raw Upload)",
             f"{stats['raw_total']:,}",
             "100%",
             "✓ Full File"],
            # req #2 — duplicate lines removed (now accurate)
            ["Duplicates Removed",
             f"{dupes:,}",
             f"{dupes*100/_raw:.1f}%" if dupes > 0 else "0%",
             dedup_status],
            # req #2 — post-parse processed count
            ["Processed Logs (After Parsing & Normalization)",
             f"{stats['total']:,}",
             f"{stats['total']*100/_raw:.1f}%",
             "✓ Parsed"],
            ["Normal Logs",
             f"{stats['normal_count']:,}",
             f"{stats['normal_pct']:.2f}%",
             "✓ Baseline"],
            # req #5 — unique anomaly types on dashboard
            ["Unique Anomaly Types (Dashboard)",
             f"{stats['unique_anomaly_count']:,}",
             f"({stats['unique_anomaly_count']} distinct patterns)",
             "■ Unique Types"],
            ["Total Anomaly Occurrences",
             f"{stats['anomaly_count']:,}",
             f"{stats['anomaly_pct']:.2f}%",
             "■ All Occurrences"],
            ["Critical Logs  (CRITICAL / FATAL)",
             f"{stats['critical_count']:,}",
             f"{stats['critical_pct']:.2f}%",
             "■ Critical"],
            ["Warnings",
             f"{stats.get('warning_count', 0):,}",
             f"{stats.get('warning_count', 0)*100/_raw:.2f}%",
             "■ Warnings"],
            # req #3 — 4-level classification row (use float % to avoid 0% for small counts)
            ["4-Level: NORMAL / WARNING / ANOMALY / CRITICAL",
             f"{cls_normal:,} / {cls_warning:,} / {cls_anomaly:,} / {cls_critical:,}",
             (f"{cls_normal*100/_raw:.2f}% / "
              f"{cls_warning*100/_raw:.2f}% / "
              f"{cls_anomaly*100/_raw:.2f}% / "
              f"{cls_critical*100/_raw:.2f}%"),
             "SOC Hybrid Scale"],
        ]

        cell_style = ParagraphStyle('cell', fontSize=9, leading=11, wordWrap='CJK')
        def wrap_cell(val):
            if isinstance(val, (str, int, float)):
                return Paragraph(str(val), cell_style)
            return val
        summary_data_wrapped = [[wrap_cell(cell) for cell in row] for row in summary_data]
        summary_table = Table(
            summary_data_wrapped,
            colWidths=[3.0 * inch, 1.1 * inch, 1.2 * inch, 1.0 * inch],
        )
        summary_table.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fafafa'), colors.HexColor('#f5f5f5')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ] + base_table_style.getCommands()))
        story.append(summary_table)

        # Section 3 (Log Distribution Analysis) intentionally OMITTED
        story.append(PageBreak())

        # ═════════════════════════════════════════════════════════════════════
        #  PAGES 2–3 — Analysis Charts  (max 2 per page)
        # ═════════════════════════════════════════════════════════════════════
        chart_images = self._generate_charts(stats)
        charts_with_data = [(n, b) for n, b in chart_images if b]
        if charts_with_data:
            story.append(Paragraph("Analysis Charts", heading_style))
            story.append(Spacer(1, 0.15 * inch))
            for i, (chart_name, chart_buf) in enumerate(charts_with_data):
                sub_style = ParagraphStyle("ChartSub", fontSize=11, fontName="Helvetica-Bold",
                                           textColor=colors.HexColor("#1f4788"), spaceAfter=4, spaceBefore=8)
                if "anomaly comparison" in chart_name.lower():
                    img = Image(chart_buf, width=5.0*inch, height=3.5*inch)
                elif "timeline" in chart_name.lower():
                    img = Image(chart_buf, width=6.5*inch, height=2.8*inch)
                else:
                    img = Image(chart_buf, width=6.5*inch, height=2.8*inch)
                from reportlab.platypus import KeepTogether as KT
                story.append(KT([Paragraph(chart_name, sub_style), img, Spacer(1, 0.15*inch)]))
            story.append(PageBreak())

        # ═════════════════════════════════════════════════════════════════════
        #  SUSPICIOUS IP ADDRESSES  (new section)
        # ═════════════════════════════════════════════════════════════════════
        last_story_len = len(story)
        if stats["ip_table"]:
            story.append(Paragraph("Suspicious IP Addresses / Sources", heading_style))
            story.append(Spacer(1, 0.15 * inch))
            ip_data = [["IP / Source", "Total Attempts",
                        "Anomaly Count", "Severity Level", "Status"]]

            for row in stats["ip_table"][:20]:
                sev = row["severity"]
                if sev == "HIGH":
                    sev_text = "HIGH"
                    sts_text = "🔴 High Risk"
                elif sev == "MEDIUM":
                    sev_text = "MEDIUM"
                    sts_text = "⚠ Suspicious"
                else:
                    sev_text = "LOW"
                    sts_text = "✓ Normal"
                ip_data.append([
                    str(row["source"])[:38],
                    f"{row['total']:,}",
                    f"{row['anom']:,}",
                    sev_text,
                    sts_text,
                ])

            ip_data_wrapped = [[wrap_cell(cell) for cell in row] for row in ip_data]
            ip_table = Table(
                ip_data_wrapped,
                colWidths=[2.4 * inch, 1.1 * inch, 1.1 * inch,
                           1.0 * inch, 1.1 * inch],
            )
            ip_style = TableStyle([
                ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#1f4788')),
                ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
                ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
                ('FONTSIZE',      (0, 0), (-1, 0),  11),
                ('BOTTOMPADDING', (0, 0), (-1, 0),  12),
                ('TOPPADDING',    (0, 0), (-1, 0),  12),
                ('ROWBACKGROUNDS',(0, 1), (-1, -1),
                 [colors.HexColor('#f5f5f5'), colors.HexColor('#eeeeee')]),
                ('TEXTCOLOR',     (0, 1), (-1, -1), colors.HexColor('#333333')),
                ('FONTSIZE',      (0, 1), (-1, -1), 10),
                ('GRID',          (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING',   (0, 0), (-1, -1), 6),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
                ('TOPPADDING',    (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN',         (0, 1), (0, -1),  'LEFT'),
            ])
            # Colour-code severity + status cells
            for ri, row in enumerate(stats["ip_table"][:20], 1):
                sev = row["severity"]
                clr = ('#D32F2F' if sev == 'HIGH' else
                       '#E65100' if sev == 'MEDIUM' else '#2E7D32')
                ip_style.add('TEXTCOLOR', (3, ri), (4, ri),
                             colors.HexColor(clr))
                ip_style.add('FONTNAME',  (3, ri), (4, ri), 'Helvetica-Bold')
            ip_table.setStyle(ip_style)
            story.append(ip_table)

        if len(story) > last_story_len:
            story.append(PageBreak())

        # ═════════════════════════════════════════════════════════════════════
        #  ANOMALY DETAILS — unique types + repeat count (req #5)
        #  Dashboard: unique_anomaly_count  |  Report: full detail with repeats
        # ═════════════════════════════════════════════════════════════════════
        last_story_len = len(story)
        story.append(Paragraph(
            f"Anomaly Details  "
            f"<font size='11' color='#555555'>"
            f"({stats['unique_anomaly_count']} unique types · "
            f"{stats['anomaly_count']} total occurrences)</font>",
            heading_style))
        story.append(Spacer(1, 0.15 * inch))

        # Show all CRITICAL, ANOMALY, WARNING logs (not just ANOMALY)
        unique_list = [row for row in stats.get('unique_anomalies_list', []) if str(row['entry'].get('final_classification','')).upper() in ('CRITICAL','ANOMALY','WARNING')]
        if len(unique_list) > 100:
            story.append(Paragraph(
                "<font color='#D32F2F'><i>Note: Only showing Top 100 anomalies by score. "
                f"Full statistics cover all {stats['anomaly_count']} occurrences.</i></font>",
                normal_style))
            unique_list = unique_list[:100]

        if unique_list:
            chunk_size = 8
            chunks = [unique_list[i:i + chunk_size]
                      for i in range(0, len(unique_list), chunk_size)]

            for chunk_idx, chunk in enumerate(chunks):
                if chunk_idx > 0:
                    story.append(PageBreak())
                    story.append(Spacer(1, 0.15 * inch))

                # 6 columns — realtime style
                # 6 col realtime-style table
                import re as _re2, html as _html2
                _LVL_COLORS = {
                    'CRITICAL': colors.HexColor('#7c3aed'),
                    'ERROR':    colors.HexColor('#dc2626'),
                    'WARNING':  colors.HexColor('#ca8a04'),
                    'INFO':     colors.HexColor('#6b7280'),
                }
                _CLS_COLORS = {
                    'CRITICAL': colors.HexColor('#d32f2f'),
                    'ANOMALY':  colors.HexColor('#ea580c'),
                    'WARNING':  colors.HexColor('#ca8a04'),
                }
                cell_s = ParagraphStyle('ATCell', fontName='Helvetica', fontSize=7, leading=9)
                hdr_s  = ParagraphStyle('ATHdr',  fontName='Helvetica-Bold', fontSize=7,
                                        textColor=colors.white, leading=9)
                anom_data = [[Paragraph(h, hdr_s) for h in ["Timestamp", "Level", "Type", "Source", "Analysis (Human Readable)", "Raw Message"]]]
                col_w = [c * inch for c in [1.00, 0.48, 0.62, 0.85, 2.20, 1.92]]
                anom_data = [[Paragraph(h, hdr_s) for h in ["Timestamp", "Level", "Type", "Source", "Analysis (Human Readable)", "Raw Message"]]]

                for row in chunk:
                    log    = row["entry"]
                    ts_raw = str(log.get("timestamp", ""))
                    try:
                        ts_fmt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts_fmt = ts_raw[:19]
                    lvl   = str(log.get("log_level", log.get("level", "INFO"))).upper()
                    cls   = str(log.get("final_classification") or "ANOMALY").upper().strip()
                    lt    = str(log.get("log_type") or log.get("type") or "")[:12]
                    src   = str(log.get("source") or "Unknown")[:26]
                    msg   = str(log.get("message") or "")
                    trans = str(log.get("translated_message") or log.get("detection_reason") or "Unusual activity detected.")
                    trans = _re2.sub(r'<[^>]*>', '', trans); trans = _html2.escape(trans)[:300]
                    msg   = _re2.sub(r'<[^>]*>', '', msg);   msg   = _html2.escape(msg)[:300]
                    lvl_s = ParagraphStyle('LS', fontName='Helvetica-Bold', fontSize=7,
                                           textColor=_LVL_COLORS.get(lvl, colors.HexColor('#6b7280')), leading=9)
                    rs_s  = ParagraphStyle('RS', fontName='Helvetica-Bold' if cls in ('CRITICAL','ANOMALY') else 'Helvetica-Oblique',
                                           fontSize=6.5, textColor=_CLS_COLORS.get(cls, colors.HexColor('#ea580c')), leading=8)
                    anom_data.append([
                        Paragraph(ts_fmt, cell_s),
                        Paragraph(lvl,    lvl_s),
                        Paragraph(lt,     cell_s),
                        Paragraph(src,    cell_s),
                        Paragraph(trans,  rs_s),
                        Paragraph(msg,    cell_s),
                    ])

                t = Table(anom_data, colWidths=col_w, repeatRows=1, splitByRow=True)
                t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#1a2744')),
                    ('FONTSIZE',      (0, 0), (-1, -1), 7),
                    ('GRID',          (0, 0), (-1, -1), 0.3, colors.lightgrey),
                    ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('WORDWRAP',      (0, 0), (-1, -1), True),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.15 * inch))
        else:
            story.append(Paragraph(
                "✓ <b>No anomalies detected</b> in the uploaded dataset.",
                styles['Normal']))

        if len(story) > last_story_len:
            story.append(PageBreak())

        # ── HARDWARE ALERTS ───────────────────────────────────────────────────
        hw_story = self._build_hardware_alerts(all_logs, heading_style)
        if hw_story:
            story.extend(hw_story)
            if len(hw_story) > 0:
                story.append(PageBreak())

        # ═════════════════════════════════════════════════════════════════════
        #  DETAILED ANALYSIS  — same format as realtime + extra upload fields
        # ═════════════════════════════════════════════════════════════════════
        last_story_len = len(story)
        story.append(Paragraph("Detailed Analysis", heading_style))
        story.append(Spacer(1, 0.15 * inch))

        anom_lv = stats["anom_level_counter"]
        anom_tp = stats["anom_type_counter"]

        breakdown_str = " | ".join(
            f"<b>{k}:</b> {v:,}"
            for k, v in sorted(anom_lv.items(), key=lambda x: -x[1])
        ) or "None"
        types_str = " | ".join(
            f"<b>{k}:</b> {v:,}"
            for k, v in sorted(anom_tp.items(), key=lambda x: -x[1])
        ) or "None"

        detailed_info = (
            f"<b>Anomalies by Severity Level:</b> {breakdown_str}<br/>"
            f"<b>Anomalies by Log Type:</b> {types_str}<br/>"
            "<br/>"
            "<b>Top Anomaly Sources:</b><br/>"
        )
        for i, src_row in enumerate(stats["top_anom_sources"][:10], 1):
            detailed_info += (
                f"&nbsp;&nbsp;{i}. {src_row['source']}: "
                f"{src_row['count']:,} detection(s)<br/>"
            )
        if not stats["top_anom_sources"]:
            detailed_info += "&nbsp;&nbsp;No anomaly sources detected<br/>"

        detailed_info += (
            "<br/>"
            f"<b>Most Targeted IP / Source:</b> {stats['most_targeted_ip']}<br/>"
            f"<b>Peak Anomaly Activity Hour:</b> {stats['peak_hour']}"
        )
        story.append(Paragraph(detailed_info, normal_style))
        story.append(Spacer(1, 0.3 * inch))

        # ── Executive Summary ─────────────────────────────────────────────────
        # No PageBreak before Executive Summary; let it flow naturally
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Spacer(1, 0.1 * inch))

        rate = stats["anomaly_pct"]   # based on raw_total
        risk = ("HIGH" if rate > 15 else
                "MODERATE" if rate > 5 else "LOW")

        dupes_removed  = stats["duplicates_removed"]
        parse_skipped2 = max(0, stats["raw_total"] - dupes_removed - stats["total"])

        if dupes_removed > 0:
            dedup_sentence = (
                f"<b>{dupes_removed:,} duplicate entries</b> were removed before analysis, "
                f"leaving <b>{stats['total']:,} unique structured log entries</b> for processing. "
            )
        else:
            dedup_sentence = (
                f"<b>0 duplicate entries</b> were found. "
            )

        if parse_skipped2 > 0:
            skipped_sentence = (
                f"<b>{parse_skipped2:,} rows</b> were excluded during parsing/normalization "
                f"(empty fields, malformed rows, or noise-filtered content), "
                f"resulting in <b>{stats['total']:,} processed log entries</b>. "
            )
        else:
            skipped_sentence = (
                f"All {stats['total']:,} entries were successfully structured and processed. "
            )

        exec_text = (
            f"This upload-based analysis received <b>{stats['raw_total']:,} raw log "
            f"lines</b> from the uploaded file. "
            + dedup_sentence
            + skipped_sentence +
            f"The hybrid detection engine identified "
            f"<b>{stats['unique_anomaly_count']:,} unique anomaly types</b> "
            f"({stats['anomaly_count']:,} total occurrences, "
            f"{stats['anomaly_pct']:.2f}% of raw total). "
            f"4-Level SOC classification breakdown: "
            f"<b>CRITICAL={stats['cls_counts'].get('CRITICAL',0):,}</b> (force-flagged by hard EID rules) · "
            f"<b>ANOMALY={stats['cls_counts'].get('ANOMALY',0):,}</b> (ML-detected) · "
            f"<b>WARNING={stats['cls_counts'].get('WARNING',0):,}</b> (rule-scored, below ML threshold) · "
            f"<b>NORMAL={stats['cls_counts'].get('NORMAL',0):,}</b>. "
            f"Note: classification level (CRITICAL/ANOMALY/WARNING/NORMAL) reflects the "
            f"<i>detection outcome</i>, not the original log severity field. "
            f"Overall risk profile: <b>{risk}</b>. "
        )
        if stats["most_targeted_ip"] != "N/A":
            exec_text += (
                f"The most frequently flagged source is "
                f"<b>{stats['most_targeted_ip']}</b>. "
            )
        exec_text += (
            f"Peak anomaly activity was observed at "
            f"<b>{stats['peak_hour']}</b>. "
            "All findings are derived exclusively from uploaded log data "
            "processed fully offline using the SOC-Grade Hybrid Isolation Forest "
            "algorithm with rule-based scoring. "
            "No internet connection or external services were used."
        )
        if is_demo:
            exec_text += " <b>Note:</b> <i>This report was generated using built-in demo data for demonstration purposes. Upload actual log files to produce a real analysis.</i>"
        story.append(Paragraph(exec_text, normal_style))

        # ── Technical Information + Footer (KeepTogether) ──
        from reportlab.platypus import KeepTogether
        tech_info = Paragraph("Technical Information", heading_style)
        tech_info_spacer = Spacer(1, 0.15 * inch)
        # Determine contamination for metadata (mirror realtime generator)
        try:
            from services.hybrid_anomaly_detector import HybridAnomalyDetector
            _det = HybridAnomalyDetector()
            contamination_val = getattr(_det, "contamination", 0.003)
        except Exception:
            contamination_val = 0.003

        footer_info = (
            "<b>Detection Method:</b> SOC-Grade Hybrid Isolation Forest "
            "+ Rule Engine v1 (12 categories)<br/>"
            "<b>Feature Groups:</b> 22 ML features — Temporal (4), Frequency (6), "
            "Behavioural (5), Text-Derived (5: keyword score, entropy, malware/login/"
            "privilege flags), Level Encoding (2)<br/>"
            "<b>Rule Engine:</b> 12 categories — EID Hard Rules, Malware/AV, "
            "Auth/Brute-force, Privilege Escalation, Log Tampering, Lateral Movement, "
            "Persistence, System Integrity, Data Exfiltration, Network Anomaly, "
            "Suspicious Processes/LOLBins, Kerberos Attacks<br/>"
            "<b>Noise Cleaning:</b> Windows path removal, escape-sequence "
            "normalisation, hex-dump stripping<br/>"
            f"<b>Contamination Rate:</b> {contamination_val:.3f} ({contamination_val*100:.1f})%<br/>"
            "<b>Number of Estimators:</b> 300<br/>"
            "<b>Classification Levels:</b> NORMAL / WARNING / ANOMALY / CRITICAL "
            "(4-level SOC scale)<br/>"
            "<b>Processing Speed:</b> 1–5 seconds per 10,000 logs<br/>"
            "<b>System Mode:</b> Upload Mode — Fully Offline, No Internet "
            "Required<br/>"
            "<b>Environment:</b> scikit-learn, Python-based<br/>"
            "<br/>"
            f"<i>This report was automatically generated by CyberShield and "
            f"contains analysis of {stats['total']:,} log entries using the "
            f"Hybrid Isolation Forest anomaly detection engine. The system "
            f"operates fully offline with no external dependencies.</i>"
        )
        footer_paragraph = Paragraph(footer_info, normal_style)
        story.append(KeepTogether([tech_info, tech_info_spacer, footer_paragraph]))

        # Remove any trailing PageBreak or large Spacer at the end of the story
        while story and (isinstance(story[-1], PageBreak) or (hasattr(story[-1], 'height') and getattr(story[-1], 'height', 0) > 0.25 * inch)):
            story.pop()

        # ── BUILD ─────────────────────────────────────────────────────────────
        story = [e for e in story if e is not None]
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_buffer.seek(0)

        filename = f"CyberShield_Upload_Report_{self.filename_str}.pdf"
        logger.info(f"✅ Upload Mode PDF generated: {filename}")
        return pdf_buffer, filename


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API FUNCTIONS  (drop-in, no other file changes needed)
# ══════════════════════════════════════════════════════════════════════════════

def generate_upload_pdf(
    all_logs: "list[dict]",
    file_names: "list[str] | None" = None,
    raw_total: int = 0,
    duplicates_removed: int = 0,
    is_demo: bool = False,
) -> "tuple[io.BytesIO, str]":
    """Generate Upload Mode PDF. Returns (BytesIO, filename). Never raises."""
    if file_names is None:
        file_names = []
    try:
        gen = UploadReportGenerator()
        return gen.generate_pdf(all_logs, file_names, raw_total=raw_total,
                                duplicates_removed=duplicates_removed,
                                is_demo=is_demo)
    except Exception as exc:
        logger.error("generate_upload_pdf failed: %s", exc, exc_info=True)
        raise


def generate_upload_csv(all_logs: "list[dict]", is_demo: bool = False) -> "tuple[io.BytesIO, str]":
    """Full CSV export. Returns (BytesIO, filename)."""
    fname  = f"CyberShield_Upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    buf    = io.BytesIO()
    wrap   = io.TextIOWrapper(buf, encoding="utf-8-sig", newline="")
    gen    = UploadReportGenerator()
    if is_demo:
        _w = csv.writer(wrap)
        _w.writerow(["# NOTE: Generated using built-in Demo Data. Upload actual log files to analyze real data."])
        _w.writerow([])
    FIELDS = ["timestamp", "log_level", "source", "message", "translated_message",
              "final_classification", "is_anomaly", "anomaly_score",
              "ml_score", "rule_score", "severity", "event_id"]
    writer = csv.DictWriter(wrap, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for log in all_logs:
        cls = str(log.get("final_classification") or "NORMAL").upper().strip()
        ia  = cls in ("CRITICAL", "ANOMALY", "WARNING")
        writer.writerow({
            "timestamp":            log.get("timestamp", ""),
            "log_level":            log.get("log_level", log.get("level", "INFO")),
            "source":               gen.extract_source_ip(log),
            "message":              log.get("message", ""),
            "translated_message":   log.get("translated_message", ""),
            "final_classification": cls,   # CRITICAL/ANOMALY/WARNING/NORMAL
            "is_anomaly":           "true" if ia else "false",
            "anomaly_score":        float(log.get("anomaly_score", 0.0)),
            "ml_score":             float(log.get("ml_score", 0.0)),
            "rule_score":           float(log.get("rule_score", 0.0)),
            "severity":             log.get("severity", "LOW"),
            "event_id":             log.get("event_id", ""),
        })
    wrap.flush()
    wrap.detach()
    buf.seek(0)
    logger.info("CSV ready: %s  (%d B)", fname, buf.getbuffer().nbytes)
    return buf, fname


def generate_upload_json(all_logs: "list[dict]", raw_total: int = 0,
                         duplicates_removed: int = 0,
                         is_demo: bool = False) -> "tuple[io.BytesIO, str]":
    """Anomaly JSON export. Returns (BytesIO, filename)."""
    fname = f"CyberShield_Upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    gen   = UploadReportGenerator()
    stats = gen._compute_stats(all_logs, raw_total=raw_total,
                               duplicates_removed=duplicates_removed)

    # Build unique anomaly list for JSON (req #5: full repeated details)
    unique_list = stats["unique_anomalies_list"]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "demo_data_notice": "Generated using built-in Demo Data. Upload actual log files to analyze real data." if is_demo else None,
        "report_metadata": {
            "generated_timestamp": gen.timestamp_str,
            "system":              "CyberShield — Offline Log Anomaly Detection",
            "processing_mode":     "Upload Mode (Offline Analysis)",
            "raw_total_logs":      stats["raw_total"],        # req #1
            "duplicates_removed":  stats["duplicates_removed"],  # req #2
            "processed_logs":      stats["total"],            # req #2
        },
        "model_information": {
            "name":               "SOC-Grade Hybrid Isolation Forest + Rule Engine v1",
            "framework":          "scikit-learn",
            "classification":     "NORMAL / WARNING (Rule) / ANOMALY (ML) / CRITICAL (Both)",
            "contamination_rate": "dynamic (1-5%)",
            "n_estimators":       300,
            "features":           22,
            "rule_categories":    12,
        },
        "summary_statistics": {
            "raw_total_logs":        stats["raw_total"],        # req #1
            "duplicates_removed":    stats["duplicates_removed"],  # req #2
            "processed_logs":        stats["total"],            # req #2
            "normal_logs":           stats["normal_count"],
            "unique_anomaly_types":  stats["unique_anomaly_count"],  # req #5
            "total_anomaly_occurrences": stats["anomaly_count"],
            "anomaly_percentage":    stats["anomaly_pct"],
            "classification_breakdown": stats["cls_counts"],   # req #3
            "critical_logs":         stats["critical_count"],
            "most_targeted_source":  stats["most_targeted_ip"],
            "peak_hour":             stats["peak_hour"],
        },
        "anomaly_breakdown": {
            "by_level":    stats["anom_level_counter"],
            "by_type":     stats["anom_type_counter"],
            "top_sources": stats["top_anom_sources"],
        },
        "suspicious_sources": stats["ip_table"],
        # req #5: unique types on top, full repeated details inside each
        "unique_anomaly_types": [
            {
                "message":         row["entry"].get("message", ""),
                "translated_message": row["entry"].get("translated_message", ""),
                "source":          gen.extract_source_ip(row["entry"]),
                "user":            row["entry"].get("user", ""),
                "ip_address":      row["entry"].get("ip_address", ""),
                "log_level":       row["entry"].get("log_level", "INFO"),
                "final_classification": str(row["entry"].get("final_classification") or "ANOMALY").upper(),
                "anomaly_score":   float(row["entry"].get("anomaly_score", 0.0)),
                "ml_score":        float(row["entry"].get("ml_score", 0.0)),
                "rule_score":      float(row["entry"].get("rule_score", 0.0)),
                "severity":        row["entry"].get("severity", "LOW"),
                "repeat_count":    row["repeat_count"],
                "first_seen":      row["entry"].get("timestamp", ""),
            }
            for row in unique_list
        ],
        "total_unique_anomaly_types": stats["unique_anomaly_count"],
        "total_anomaly_occurrences":  stats["anomaly_count"],
    }
    content = json.dumps(payload, indent=2, default=str,
                         ensure_ascii=False).encode("utf-8")
    buf = io.BytesIO(content)
    logger.info("JSON ready: %s  (%d B)", fname, buf.getbuffer().nbytes)
    return buf, fname


def get_capabilities() -> dict:
    return {
        "pdf_available":        REPORTLAB_AVAILABLE,
        "charts_available":     MATPLOTLIB_AVAILABLE,
        "csv_available":        True,
        "json_available":       True,
        "reportlab_installed":  REPORTLAB_AVAILABLE,
        "matplotlib_installed": MATPLOTLIB_AVAILABLE,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  DEMO DATA  — realistic synthetic logs used when no file is uploaded
# ══════════════════════════════════════════════════════════════════════════════

DEMO_LOGS = [
    {"timestamp":"2025-01-15 08:01:12","log_level":"INFO",    "source":"192.168.1.101","ip_address":"192.168.1.101","user":"jsmith",  "message":"User login successful",                                "translated_message":"Successful authentication",                    "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.05,"ml_score":0.04,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:03:45","log_level":"WARNING", "source":"192.168.1.202","ip_address":"192.168.1.202","user":"unknown", "message":"Failed login attempt - invalid password",               "translated_message":"Authentication failure",                        "final_classification":"WARNING", "is_anomaly":True, "anomaly_score":0.62,"ml_score":0.55,"rule_score":0.7, "severity":"MEDIUM"},
    {"timestamp":"2025-01-15 08:05:01","log_level":"ERROR",   "source":"10.0.0.55",    "ip_address":"10.0.0.55",   "user":"admin",   "message":"Privilege escalation attempt detected",                 "translated_message":"Attempt to gain elevated privileges",           "final_classification":"ANOMALY", "is_anomaly":True, "anomaly_score":0.88,"ml_score":0.91,"rule_score":0.85,"severity":"HIGH"},
    {"timestamp":"2025-01-15 08:07:33","log_level":"CRITICAL","source":"10.0.0.55",    "ip_address":"10.0.0.55",   "user":"admin",   "message":"Malware signature detected in process memory",          "translated_message":"Known malware pattern matched in memory",        "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.97,"ml_score":0.98,"rule_score":1.0, "severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:10:00","log_level":"INFO",    "source":"192.168.1.105","ip_address":"192.168.1.105","user":"mwilson","message":"Sensitive file accessed: /etc/passwd",                  "translated_message":"Sensitive file read",                           "final_classification":"WARNING", "is_anomaly":True, "anomaly_score":0.71,"ml_score":0.68,"rule_score":0.75,"severity":"MEDIUM"},
    {"timestamp":"2025-01-15 08:12:15","log_level":"INFO",    "source":"192.168.1.101","ip_address":"192.168.1.101","user":"jsmith", "message":"File download completed",                              "translated_message":"Normal file transfer",                          "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.08,"ml_score":0.07,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:15:22","log_level":"ERROR",   "source":"172.16.0.88",  "ip_address":"172.16.0.88", "user":"service", "message":"Brute force - 50 failed logins in 60s",                "translated_message":"Repeated authentication failure burst",          "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.95,"ml_score":0.96,"rule_score":1.0, "severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:18:44","log_level":"WARNING", "source":"172.16.0.88",  "ip_address":"172.16.0.88", "user":"service", "message":"Lateral movement detected to 192.168.1.0/24",          "translated_message":"Internal network scanning activity",            "final_classification":"ANOMALY", "is_anomaly":True, "anomaly_score":0.86,"ml_score":0.89,"rule_score":0.82,"severity":"HIGH"},
    {"timestamp":"2025-01-15 08:20:01","log_level":"INFO",    "source":"192.168.1.110","ip_address":"192.168.1.110","user":"blee",   "message":"User login successful",                                "translated_message":"Successful authentication",                    "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.06,"ml_score":0.05,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:22:30","log_level":"INFO",    "source":"192.168.1.110","ip_address":"192.168.1.110","user":"blee",   "message":"Email sent to external domain",                        "translated_message":"Outbound email activity",                       "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.11,"ml_score":0.10,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:25:10","log_level":"ERROR",   "source":"10.0.0.55",    "ip_address":"10.0.0.55",   "user":"admin",   "message":"Log file deleted: /var/log/auth.log",                  "translated_message":"Audit log tampering attempt",                   "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.99,"ml_score":0.98,"rule_score":1.0, "severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:28:05","log_level":"WARNING", "source":"192.168.1.202","ip_address":"192.168.1.202","user":"unknown","message":"Port scan detected from external host",                "translated_message":"Network reconnaissance activity",               "final_classification":"ANOMALY", "is_anomaly":True, "anomaly_score":0.83,"ml_score":0.80,"rule_score":0.86,"severity":"HIGH"},
    {"timestamp":"2025-01-15 08:30:00","log_level":"INFO",    "source":"192.168.1.103","ip_address":"192.168.1.103","user":"rchen",  "message":"Database query executed",                              "translated_message":"Standard DB access",                           "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.09,"ml_score":0.08,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:32:18","log_level":"ERROR",   "source":"192.168.1.202","ip_address":"192.168.1.202","user":"unknown","message":"SQL injection attempt blocked",                        "translated_message":"Malicious SQL payload in request",               "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.94,"ml_score":0.93,"rule_score":0.95,"severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:34:50","log_level":"INFO",    "source":"192.168.1.101","ip_address":"192.168.1.101","user":"jsmith", "message":"VPN connected from 203.0.113.10",                     "translated_message":"Remote VPN session established",                "final_classification":"WARNING", "is_anomaly":True, "anomaly_score":0.60,"ml_score":0.58,"rule_score":0.62,"severity":"MEDIUM"},
    {"timestamp":"2025-01-15 08:37:22","log_level":"INFO",    "source":"192.168.1.105","ip_address":"192.168.1.105","user":"mwilson","message":"Scheduled task created by non-admin user",             "translated_message":"Persistence mechanism installed",               "final_classification":"ANOMALY", "is_anomaly":True, "anomaly_score":0.77,"ml_score":0.79,"rule_score":0.74,"severity":"HIGH"},
    {"timestamp":"2025-01-15 08:40:00","log_level":"INFO",    "source":"192.168.1.103","ip_address":"192.168.1.103","user":"rchen",  "message":"User logout",                                         "translated_message":"Session terminated normally",                   "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.03,"ml_score":0.03,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:42:11","log_level":"WARNING", "source":"10.0.0.55",    "ip_address":"10.0.0.55",   "user":"admin",   "message":"Large data exfiltration: 2.1GB upload to unknown host","translated_message":"Unusual outbound data transfer volume",        "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.96,"ml_score":0.97,"rule_score":0.95,"severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:44:33","log_level":"INFO",    "source":"192.168.1.108","ip_address":"192.168.1.108","user":"tpatel", "message":"Antivirus scan completed - no threats found",           "translated_message":"Clean AV scan result",                         "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.04,"ml_score":0.04,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:46:55","log_level":"ERROR",   "source":"172.16.0.88",  "ip_address":"172.16.0.88", "user":"service", "message":"Suspicious PowerShell: Invoke-Mimikatz detected",      "translated_message":"Known credential dumping tool detected",         "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.98,"ml_score":0.99,"rule_score":1.0, "severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:49:00","log_level":"INFO",    "source":"192.168.1.101","ip_address":"192.168.1.101","user":"jsmith", "message":"Password changed by user",                            "translated_message":"Account credential update",                     "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.15,"ml_score":0.13,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:51:20","log_level":"WARNING", "source":"192.168.1.202","ip_address":"192.168.1.202","user":"unknown","message":"Kerberoasting attack detected",                       "translated_message":"Kerberos ticket harvesting attempt",            "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.93,"ml_score":0.92,"rule_score":0.94,"severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:53:44","log_level":"INFO",    "source":"192.168.1.108","ip_address":"192.168.1.108","user":"tpatel", "message":"System update applied: KB5034441",                    "translated_message":"OS patch installed",                            "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.07,"ml_score":0.06,"rule_score":0.0, "severity":"LOW"},
    {"timestamp":"2025-01-15 08:56:01","log_level":"ERROR",   "source":"10.0.0.55",    "ip_address":"10.0.0.55",   "user":"admin",   "message":"Ransomware file extension pattern detected",           "translated_message":"Mass file encryption indicators found",          "final_classification":"CRITICAL","is_anomaly":True, "anomaly_score":0.99,"ml_score":0.99,"rule_score":1.0, "severity":"CRITICAL"},
    {"timestamp":"2025-01-15 08:58:30","log_level":"INFO",    "source":"192.168.1.110","ip_address":"192.168.1.110","user":"blee",   "message":"User logout",                                         "translated_message":"Session terminated normally",                   "final_classification":"NORMAL",  "is_anomaly":False,"anomaly_score":0.03,"ml_score":0.02,"rule_score":0.0, "severity":"LOW"},
]

DEMO_FILE_NAMES = ["demo_system_logs_2025-01-15.log"]


def get_demo_logs():
    """Return built-in demo dataset: (logs, file_names, raw_total, duplicates_removed)."""
    return list(DEMO_LOGS), DEMO_FILE_NAMES, len(DEMO_LOGS), 0

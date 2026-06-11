import re
import csv
import io
from typing import Dict, List, Optional
from html import escape as html_escape

from .detector import AnomalyPoint
from .context import ContextExtractor
from .templater import Template


SUGGESTION_RULES = [
    (r"\[404\]", "404错误暴增，可能某个API端点被移除或URL路径变更"),
    (r"\[500\]", "500内部错误暴增，可能后端服务出现异常（如数据库连接失败、内存溢出）"),
    (r"\[502\]", "502网关错误暴增，可能上游服务不可用或负载均衡配置问题"),
    (r"\[503\]", "503服务不可用暴增，可能服务过载或已停机"),
    (r"\[504\]", "504网关超时暴增，可能下游服务响应过慢或网络超时"),
    (r"\[403\]", "403禁止访问暴增，可能权限配置变更或遭受扫描攻击"),
    (r"\[401\]", "401未授权暴增，可能认证服务异常或Token过期策略变更"),
    (r"\[429\]", "429限流错误暴增，可能触发了限流策略或遭受DDoS攻击"),
    (r"\[ERROR\]|\[FATAL\]|\[CRITICAL\]", "严重错误日志暴增，需立即排查"),
    (r"\[WARN\]|\[WARNING\]", "警告日志增多，需关注系统稳定性"),
    (r"timeout|timed?\s*out", "超时日志暴增，可能网络延迟增大或下游服务响应变慢"),
    (r"OOM|out\s+of\s+memory|memory", "内存相关错误暴增，可能存在内存泄漏"),
    (r"connection\s*refused|connect\s*fail", "连接失败暴增，可能目标服务已停止或网络不通"),
    (r"disk\s*full|no\s*space", "磁盘空间不足日志暴增，可能日志或数据未及时清理"),
    (r"permission\s*denied", "权限拒绝日志暴增，可能文件/目录权限配置变更"),
    (r"segmentation\s*fault|segfault", "段错误暴增，可能存在程序崩溃缺陷"),
    (r"SSL|TLS|certificate", "SSL/TLS相关错误暴增，可能证书过期或配置错误"),
]


SEVERITY_LABELS = {
    "high": ("严重", "🔴"),
    "medium": ("中等", "🟡"),
    "low": ("轻微", "🟢"),
}


class Reporter:
    def __init__(self, context_extractor: ContextExtractor):
        self.context_extractor = context_extractor

    def _format_time(self, dt) -> str:
        if dt is None:
            return ""
        try:
            return dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        except Exception:
            return str(dt)

    def _suggest(self, template: Template, anomaly: AnomalyPoint) -> str:
        text = template.pattern
        direction = "暴增" if anomaly.direction == "spike" else "骤降"
        for pattern, suggestion in SUGGESTION_RULES:
            if re.search(pattern, text, re.IGNORECASE):
                time_str = self._format_time(anomaly.bucket_time)
                return f"{suggestion}（{template.template_id}在{time_str}后{direction}）"
        time_str = self._format_time(anomaly.bucket_time)
        return f"模板{template.template_id}在{time_str}后频率{direction}，建议排查相关变更"

    def _status_label(self, template: Template) -> str:
        if template.status_code:
            return f"  状态码: {template.status_code}"
        if template.level:
            return f"  日志级别: {template.level}"
        return ""

    def _severity_label(self, anomaly: AnomalyPoint) -> str:
        label, icon = SEVERITY_LABELS.get(anomaly.severity, ("未知", "⚪"))
        return f"  严重程度: {icon} {label} ({anomaly.severity_score:.1f})"

    def _collect_anomaly_data(
        self,
        anomalies: List[AnomalyPoint],
        all_entries: list,
        template_entries: Dict[str, list],
        templates: Dict[str, Template],
        top_n: int = 20,
    ) -> List[dict]:
        rows = []
        for i, anomaly in enumerate(anomalies[:top_n], 1):
            tmpl = anomaly.template
            if not tmpl:
                continue
            ctx = self.context_extractor.extract(anomaly, all_entries, template_entries)
            ctx_lines = []
            if ctx.get("before"):
                ctx_lines.extend([e.raw for e in ctx["before"]])
            if ctx.get("anomaly"):
                ctx_lines.extend([e.raw for e in ctx["anomaly"]])
            if ctx.get("after"):
                ctx_lines.extend([e.raw for e in ctx["after"]])
            rows.append({
                "rank": i,
                "severity": anomaly.severity,
                "severity_score": anomaly.severity_score,
                "template_id": anomaly.template_id,
                "is_error": tmpl.is_error(),
                "status_code": tmpl.status_code or "",
                "status_class": tmpl.status_class or "",
                "log_level": tmpl.level or "",
                "pattern": tmpl.pattern,
                "time": self._format_time(anomaly.bucket_time),
                "observed": anomaly.observed,
                "expected": round(anomaly.expected, 1),
                "score": round(anomaly.score, 2),
                "direction": anomaly.direction,
                "suggestion": self._suggest(tmpl, anomaly),
                "context": "\n".join(ctx_lines[:10]),
            })
        return rows

    def generate_report(
        self,
        anomalies: List[AnomalyPoint],
        all_entries: list,
        template_entries: Dict[str, list],
        templates: Dict[str, Template],
        top_n: int = 20,
    ) -> str:
        lines = []
        lines.append("=" * 72)
        lines.append("  日志异常模式挖掘报告")
        lines.append("=" * 72)
        lines.append("")

        if not anomalies:
            lines.append("  未检测到异常模式。")
            return "\n".join(lines)

        total_error = sum(1 for a in anomalies if a.template and a.template.is_error())
        high = sum(1 for a in anomalies if a.severity == "high")
        medium = sum(1 for a in anomalies if a.severity == "medium")
        low = sum(1 for a in anomalies if a.severity == "low")

        lines.append(
            f"  检测到 {len(anomalies)} 个异常点（显示前 {top_n} 个）"
        )
        lines.append(
            f"  按严重程度: 🔴严重 {high}  🟡中等 {medium}  🟢轻微 {low}  |  错误类: {total_error}"
        )
        lines.append("")

        rows = self._collect_anomaly_data(anomalies, all_entries, template_entries, templates, top_n)

        for row in rows:
            tmpl = anomalies[row["rank"] - 1].template
            anomaly = anomalies[row["rank"] - 1]
            is_err = " [ERROR]" if row["is_error"] else ""
            lines.append(f"  [{row['rank']}] 模板ID: {row['template_id']}{is_err}")
            lines.append(f"  {self._severity_label(anomaly).strip()}")
            status_label = self._status_label(tmpl)
            if status_label:
                lines.append(f"      {status_label.strip()}")
            lines.append(f"      模板: {row['pattern'][:100]}")
            lines.append(f"      时间: {row['time']}")
            lines.append(f"      观测值: {row['observed']}  期望值: {row['expected']}")
            lines.append(f"      异常分数: {row['score']}  方向: {row['direction']}")
            lines.append(f"      可能原因: {row['suggestion']}")

            ctx = self.context_extractor.extract(anomaly, all_entries, template_entries)
            ctx_text = self.context_extractor.format_context(ctx)
            lines.append(ctx_text)
            lines.append("")

        lines.append("=" * 72)
        lines.append("  报告结束")
        lines.append("=" * 72)
        return "\n".join(lines)

    def generate_report_csv(
        self,
        anomalies: List[AnomalyPoint],
        all_entries: list,
        template_entries: Dict[str, list],
        templates: Dict[str, Template],
        top_n: int = 20,
    ) -> str:
        rows = self._collect_anomaly_data(anomalies, all_entries, template_entries, templates, top_n)
        buf = io.StringIO()
        fieldnames = [
            "rank", "severity", "severity_score", "template_id", "is_error",
            "status_code", "status_class", "log_level", "pattern",
            "time", "observed", "expected", "score", "direction",
            "suggestion", "context",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return buf.getvalue()

    def generate_report_html(
        self,
        anomalies: List[AnomalyPoint],
        all_entries: list,
        template_entries: Dict[str, list],
        templates: Dict[str, Template],
        top_n: int = 20,
    ) -> str:
        rows = self._collect_anomaly_data(anomalies, all_entries, template_entries, templates, top_n)
        total_error = sum(1 for a in anomalies if a.template and a.template.is_error())
        high = sum(1 for a in anomalies if a.severity == "high")
        medium = sum(1 for a in anomalies if a.severity == "medium")
        low = sum(1 for a in anomalies if a.severity == "low")

        sev_colors = {
            "high": "#dc3545",
            "medium": "#ffc107",
            "low": "#28a745",
        }
        sev_labels = {
            "high": "严重",
            "medium": "中等",
            "low": "轻微",
        }

        parts = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="zh-CN">')
        parts.append("<head>")
        parts.append('<meta charset="UTF-8">')
        parts.append("<title>日志异常模式挖掘报告</title>")
        parts.append("<style>")
        parts.append("body { font-family: -apple-system, Arial, sans-serif; margin: 20px; }")
        parts.append("h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 8px; }")
        parts.append(".summary { background: #f8f9fa; padding: 12px; border-radius: 6px; margin-bottom: 20px; }")
        parts.append(".anomaly { border: 1px solid #dee2e6; border-radius: 6px; margin: 12px 0; overflow: hidden; }")
        parts.append(".anomaly-header { padding: 10px 14px; font-weight: bold; color: #fff; }")
        parts.append(".anomaly-body { padding: 12px 14px; }")
        parts.append(".meta { margin: 4px 0; font-size: 14px; }")
        parts.append(".pattern { font-family: Consolas, monospace; background: #f1f3f5; padding: 6px 8px; border-radius: 4px; margin: 8px 0; }")
        parts.append(".context { background: #fff3cd; padding: 8px 10px; border-radius: 4px; font-family: Consolas, monospace; font-size: 12px; white-space: pre-wrap; margin-top: 8px; max-height: 240px; overflow-y: auto; }")
        parts.append("table { border-collapse: collapse; width: 100%; }")
        parts.append("</style>")
        parts.append("</head>")
        parts.append("<body>")
        parts.append("<h1>日志异常模式挖掘报告</h1>")
        parts.append('<div class="summary">')
        parts.append(
            f"<p><strong>异常总数:</strong> {len(anomalies)} (显示前 {top_n} 个)&nbsp;&nbsp;"
            f"<strong>严重程度:</strong> "
            f'<span style="color:{sev_colors["high"]}">● 严重 {high}</span>&nbsp;&nbsp;'
            f'<span style="color:{sev_colors["medium"]}">● 中等 {medium}</span>&nbsp;&nbsp;'
            f'<span style="color:{sev_colors["low"]}">● 轻微 {low}</span>&nbsp;&nbsp;'
            f"<strong>错误类:</strong> {total_error}</p>"
        )
        parts.append("</div>")

        for row in rows:
            color = sev_colors.get(row["severity"], "#6c757d")
            sev_label = sev_labels.get(row["severity"], "未知")
            err_tag = ' <span style="background:#dc3545;color:#fff;padding:1px 6px;border-radius:3px;font-size:12px;">ERROR</span>' if row["is_error"] else ""
            parts.append('<div class="anomaly">')
            parts.append(
                f'<div class="anomaly-header" style="background:{color};">'
                f"[{row['rank']}] {row['template_id']}{err_tag} — {sev_label} ({row['severity_score']:.1f})"
                f"</div>"
            )
            parts.append('<div class="anomaly-body">')
            st_info = row["status_code"] or row["log_level"] or "-"
            parts.append(
                f'<div class="meta"><strong>状态码/级别:</strong> {html_escape(st_info)} &nbsp;|&nbsp; '
                f"<strong>时间:</strong> {html_escape(row['time'])} &nbsp;|&nbsp; "
                f"<strong>观测/期望:</strong> {row['observed']} / {row['expected']} &nbsp;|&nbsp; "
                f"<strong>分数:</strong> {row['score']} ({row['direction']})</div>"
            )
            parts.append(f'<div class="pattern"><strong>模板:</strong> {html_escape(row["pattern"])}</div>')
            parts.append(f'<div class="meta"><strong>可能原因:</strong> {html_escape(row["suggestion"])}</div>')
            if row["context"]:
                parts.append(f'<div class="context"><strong>上下文示例:</strong>\n{html_escape(row["context"])}</div>')
            parts.append("</div></div>")

        parts.append("</body></html>")
        return "\n".join(parts)

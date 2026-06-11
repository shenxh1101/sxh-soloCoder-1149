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
                if anomaly.direction == "drop":
                    if "暴增" in suggestion:
                        suggestion = suggestion.replace("暴增", "异常波动")
                    suggestion = suggestion.rstrip("），,。.")
                    return f"{suggestion}（{template.template_id}在{time_str}后频率{direction}，可能问题缓解或流量转移）"
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

    def _build_summary(self, anomalies: List[AnomalyPoint],
                       template_entries: Dict[str, list]) -> Dict:
        top_dangerous = []
        for a in anomalies:
            if a.template and a.template.is_error():
                top_dangerous.append(a)
            if len(top_dangerous) >= 5:
                break

        tid_first_seen = {}
        tid_last_seen = {}
        for tid, elist in template_entries.items():
            times = [e[0].timestamp for e in elist if e[0].timestamp]
            if times:
                if tid not in tid_first_seen or min(times) < tid_first_seen[tid]:
                    tid_first_seen[tid] = min(times)
                if tid not in tid_last_seen or max(times) > tid_last_seen[tid]:
                    tid_last_seen[tid] = max(times)
        durations = []
        for a in anomalies:
            tid = a.template_id
            if tid in tid_first_seen and tid in tid_last_seen:
                dur_sec = (tid_last_seen[tid] - tid_first_seen[tid]).total_seconds()
                durations.append((a, dur_sec))
        durations.sort(key=lambda x: x[1], reverse=True)
        longest = durations[:5]

        url_counter: Dict[str, int] = {}
        service_counter: Dict[str, int] = {}
        url_status_counter: Dict[str, Dict[str, int]] = {}
        service_err_counter: Dict[str, Dict[str, int]] = {}
        level_counter: Dict[str, int] = {}
        status_counter: Dict[str, int] = {}

        for tid, elist in template_entries.items():
            tmpl = None
            for _, t in elist:
                tmpl = t
                break
            if not tmpl:
                continue
            total = len(elist)
            is_err = tmpl.is_error()

            entry0 = elist[0][0]
            fields = entry0.fields or {}

            request = fields.get("request", "") if fields else ""
            if request:
                parts = request.split()
                if len(parts) >= 2:
                    path = parts[1].split("?")[0]
                    prefixes = path.strip("/").split("/")
                    if len(prefixes) >= 2:
                        url_key = f"/{prefixes[0]}/{prefixes[1]}"
                    else:
                        url_key = f"/{prefixes[0]}" if prefixes else "/"
                    if is_err:
                        url_counter[url_key] = url_counter.get(url_key, 0) + total
                        if url_key not in url_status_counter:
                            url_status_counter[url_key] = {}
                        sc = tmpl.status_code or tmpl.status_class or "OTHER"
                        url_status_counter[url_key][sc] = url_status_counter[url_key].get(sc, 0) + total

            svc = (fields.get("service") or fields.get("host") or
                   fields.get("hostname") or fields.get("logger") or
                   fields.get("program") or "")
            if svc and is_err:
                service_counter[svc] = service_counter.get(svc, 0) + total
                if svc not in service_err_counter:
                    service_err_counter[svc] = {}
                label = tmpl.status_code or (f"[{tmpl.level}]" if tmpl.level else tmpl.pattern[:30])
                service_err_counter[svc][label] = service_err_counter[svc].get(label, 0) + total

            if tmpl.level and is_err:
                level_counter[tmpl.level.upper()] = level_counter.get(tmpl.level.upper(), 0) + total
            if tmpl.status_code and is_err:
                status_counter[tmpl.status_code] = status_counter.get(tmpl.status_code, 0) + total

        top_urls = sorted(url_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_services = sorted(service_counter.items(), key=lambda x: x[1], reverse=True)[:5]

        url_status_breakdown = []
        for url, _ in top_urls:
            dist = sorted(url_status_counter.get(url, {}).items(), key=lambda x: x[1], reverse=True)
            url_status_breakdown.append((url, dist))

        svc_err_breakdown = []
        for svc, _ in top_services:
            dist = sorted(service_err_counter.get(svc, {}).items(), key=lambda x: x[1], reverse=True)
            svc_err_breakdown.append((svc, dist))

        level_items = sorted(level_counter.items(), key=lambda x: x[1], reverse=True)
        status_items = sorted(status_counter.items(), key=lambda x: x[1], reverse=True)

        return {
            "top_dangerous": top_dangerous,
            "longest": longest,
            "top_urls": top_urls,
            "top_services": top_services,
            "url_status_breakdown": url_status_breakdown,
            "svc_err_breakdown": svc_err_breakdown,
            "level_counts": level_items,
            "status_counts": status_items,
        }

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
            if ctx.get("at"):
                ctx_lines.extend([e.raw for e in ctx["at"]])
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

        summary = self._build_summary(anomalies, template_entries)

        lines.append("  " + "-" * 68)
        lines.append("  【排查摘要】建议按以下顺序优先处理")
        lines.append("  " + "-" * 68)
        if summary["top_dangerous"]:
            lines.append("  🔥 最危险异常（5xx/ERROR类，按严重度排序前5）：")
            for i, a in enumerate(summary["top_dangerous"], 1):
                tmpl = a.template
                sc = tmpl.status_code or tmpl.level or "-"
                lines.append(f"     {i}. [{a.severity.upper()}] {a.template_id} | {sc} | 观测{a.observed}/期望{a.expected:.1f}")
                lines.append(f"        模板: {tmpl.pattern[:70]}")
            lines.append("")

        if summary["longest"]:
            lines.append("  ⏱️ 持续最久的异常（前5）：")
            for i, (a, dur_s) in enumerate(summary["longest"], 1):
                tmpl = a.template
                dur_h = dur_s / 3600.0
                dur_str = f"{dur_h:.1f}h" if dur_h >= 1 else f"{dur_s/60:.1f}min"
                sc = tmpl.status_code or tmpl.level or "-"
                lines.append(f"     {i}. 已持续 {dur_str} | {a.template_id} | {sc} | {tmpl.pattern[:55]}")
            lines.append("")

        if summary["top_urls"]:
            lines.append("  🌐 影响最大的 URL 前缀（按错误累计量排序）：")
            for i, (url, cnt) in enumerate(summary["top_urls"], 1):
                lines.append(f"     {i}. {url:<40} 错误计数: {cnt}")
            lines.append("")

        if summary["top_services"]:
            lines.append("  🖥️ 受影响的服务/主机（按错误累计量排序）：")
            for i, (svc, cnt) in enumerate(summary["top_services"], 1):
                lines.append(f"     {i}. {svc:<40} 错误计数: {cnt}")
            lines.append("")

        if summary["svc_err_breakdown"]:
            lines.append("  📊 各服务内主要错误模板分布：")
            for svc, dist in summary["svc_err_breakdown"]:
                top_items = ", ".join(f"{k}={v}" for k, v in dist[:3])
                lines.append(f"     - {svc:<38} {top_items}")
            lines.append("")

        if summary["url_status_breakdown"]:
            lines.append("  🗂️ URL前缀的状态码分布（错误量最高的前缀）：")
            for url, dist in summary["url_status_breakdown"]:
                top_items = ", ".join(f"{k}={v}" for k, v in dist[:4])
                lines.append(f"     - {url:<38} {top_items}")
            lines.append("")

        if summary["status_counts"] or summary["level_counts"]:
            parts = []
            if summary["status_counts"]:
                parts.append("状态码: " + ", ".join(f"{k}={v}" for k, v in summary["status_counts"]))
            if summary["level_counts"]:
                parts.append("级别: " + ", ".join(f"{k}={v}" for k, v in summary["level_counts"]))
            if parts:
                lines.append("  📈 错误构成：" + "  |  ".join(parts))
                lines.append("")

        lines.append("  " + "-" * 68)
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
        summary = self._build_summary(anomalies, template_entries)
        rows = self._collect_anomaly_data(anomalies, all_entries, template_entries, templates, top_n)
        buf = io.StringIO()

        buf.write("===== 排查摘要 =====\n")
        buf.write(f"异常总数,{len(anomalies)},显示前,{top_n}\n")
        high = sum(1 for a in anomalies if a.severity == "high")
        medium = sum(1 for a in anomalies if a.severity == "medium")
        low = sum(1 for a in anomalies if a.severity == "low")
        total_error = sum(1 for a in anomalies if a.template and a.template.is_error())
        buf.write(f"严重度分布,严重={high},中等={medium},轻微={low},错误类={total_error}\n")

        if summary["top_dangerous"]:
            buf.write("\n[最危险异常 TOP5]\n")
            buf.write("排名,严重程度,模板ID,状态码/级别,观测,期望,模板片段\n")
            for i, a in enumerate(summary["top_dangerous"], 1):
                tmpl = a.template
                sc = tmpl.status_code or tmpl.level or "-"
                pat = tmpl.pattern.replace('"', '""')[:100]
                buf.write(f'{i},{a.severity},{a.template_id},{sc},{a.observed},{a.expected:.1f},"{pat}"\n')

        if summary["longest"]:
            buf.write("\n[持续最久异常 TOP5]\n")
            buf.write("排名,持续时间,模板ID,状态码/级别,模板片段\n")
            for i, (a, dur_s) in enumerate(summary["longest"], 1):
                tmpl = a.template
                dur_h = dur_s / 3600.0
                dur_str = f"{dur_h:.1f}h" if dur_h >= 1 else f"{dur_s/60:.1f}min"
                sc = tmpl.status_code or tmpl.level or "-"
                pat = tmpl.pattern.replace('"', '""')[:100]
                buf.write(f'{i},{dur_str},{a.template_id},{sc},"{pat}"\n')

        if summary["top_urls"]:
            buf.write("\n[影响最大URL前缀 TOP5]\n")
            buf.write("排名,URL前缀,错误累计数\n")
            for i, (url, cnt) in enumerate(summary["top_urls"], 1):
                buf.write(f'{i},"{url}",{cnt}\n')

        if summary["top_services"]:
            buf.write("\n[受影响服务 TOP5]\n")
            buf.write("排名,服务/主机,错误累计数\n")
            for i, (svc, cnt) in enumerate(summary["top_services"], 1):
                svc_csv = svc.replace('"', '""')
                buf.write(f'{i},"{svc_csv}",{cnt}\n')

        if summary["svc_err_breakdown"]:
            buf.write("\n[各服务主要错误分布]\n")
            buf.write("服务,错误类型1(计数),错误类型2(计数),错误类型3(计数)\n")
            for svc, dist in summary["svc_err_breakdown"]:
                svc_csv = svc.replace('"', '""')
                parts = [f'{k}={v}' for k, v in dist[:3]]
                while len(parts) < 3:
                    parts.append("")
                buf.write(f'"{svc_csv}",' + ",".join(f'"{p}"' for p in parts) + "\n")

        if summary["url_status_breakdown"]:
            buf.write("\n[URL前缀状态码分布]\n")
            buf.write("URL前缀,状态码1(计数),状态码2(计数),状态码3(计数),状态码4(计数)\n")
            for url, dist in summary["url_status_breakdown"]:
                url_csv = url.replace('"', '""')
                parts = [f'{k}={v}' for k, v in dist[:4]]
                while len(parts) < 4:
                    parts.append("")
                buf.write(f'"{url_csv}",' + ",".join(f'"{p}"' for p in parts) + "\n")

        if summary["status_counts"] or summary["level_counts"]:
            buf.write("\n[错误构成汇总]\n")
            if summary["status_counts"]:
                pairs = ",".join(f'"{k}",{v}' for k, v in summary["status_counts"])
                buf.write(f"状态码,{pairs}\n")
            if summary["level_counts"]:
                pairs = ",".join(f'"{k}",{v}' for k, v in summary["level_counts"])
                buf.write(f"日志级别,{pairs}\n")

        buf.write("\n===== 异常详情 =====\n")
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

        summary = self._build_summary(anomalies, template_entries)

        parts.append('<hr style="margin:12px 0;"><h3 style="margin:4px 0;">🔍 排查摘要</h3>')
        if summary["top_dangerous"]:
            parts.append("<p><strong>🔥 最危险异常（5xx/ERROR，按严重度前5）：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>#</th><th>严重度</th><th>模板ID</th><th>状态码/级别</th><th>观测/期望</th><th>模板片段</th></tr>')
            for i, a in enumerate(summary["top_dangerous"], 1):
                tmpl = a.template
                sc = html_escape(tmpl.status_code or tmpl.level or "-")
                pat = html_escape(tmpl.pattern[:70])
                color = sev_colors.get(a.severity, "#666")
                parts.append(f'<tr><td>{i}</td><td style="color:{color};font-weight:bold;">{sev_labels.get(a.severity,"?")}</td><td>{html_escape(a.template_id)}</td><td>{sc}</td><td>{a.observed}/{a.expected:.1f}</td><td>{pat}</td></tr>')
            parts.append("</table>")

        if summary["longest"]:
            parts.append("<p style='margin-top:14px;'><strong>⏱️ 持续最久的异常（前5）：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>#</th><th>持续时间</th><th>模板ID</th><th>状态码/级别</th><th>模板片段</th></tr>')
            for i, (a, dur_s) in enumerate(summary["longest"], 1):
                tmpl = a.template
                dur_h = dur_s / 3600.0
                dur_str = f"{dur_h:.1f}h" if dur_h >= 1 else f"{dur_s/60:.1f}min"
                sc = html_escape(tmpl.status_code or tmpl.level or "-")
                pat = html_escape(tmpl.pattern[:70])
                parts.append(f'<tr><td>{i}</td><td>{dur_str}</td><td>{html_escape(a.template_id)}</td><td>{sc}</td><td>{pat}</td></tr>')
            parts.append("</table>")

        if summary["top_urls"]:
            parts.append("<p style='margin-top:14px;'><strong>🌐 影响最大的 URL 前缀（按错误量前5）：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>#</th><th>URL前缀</th><th>错误累计</th></tr>')
            for i, (url, cnt) in enumerate(summary["top_urls"], 1):
                parts.append(f'<tr><td>{i}</td><td><code>{html_escape(url)}</code></td><td>{cnt}</td></tr>')
            parts.append("</table>")

        if summary["top_services"]:
            parts.append("<p style='margin-top:14px;'><strong>🖥️ 受影响的服务/主机（前5）：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>#</th><th>服务/主机</th><th>错误累计</th></tr>')
            for i, (svc, cnt) in enumerate(summary["top_services"], 1):
                parts.append(f'<tr><td>{i}</td><td>{html_escape(svc)}</td><td>{cnt}</td></tr>')
            parts.append("</table>")

        if summary["svc_err_breakdown"]:
            parts.append("<p style='margin-top:14px;'><strong>📊 各服务内主要错误模板分布：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>服务</th><th>主要错误类型</th></tr>')
            for svc, dist in summary["svc_err_breakdown"]:
                top_items = ", ".join(f"{k}={v}" for k, v in dist[:3])
                parts.append(f'<tr><td>{html_escape(svc)}</td><td>{html_escape(top_items)}</td></tr>')
            parts.append("</table>")

        if summary["url_status_breakdown"]:
            parts.append("<p style='margin-top:14px;'><strong>🗂️ URL前缀的状态码分布（错误量最高的前缀）：</strong></p>")
            parts.append('<table border="1" style="font-size:13px;border-collapse:collapse;"><tr style="background:#eee;"><th>URL前缀</th><th>状态码分布</th></tr>')
            for url, dist in summary["url_status_breakdown"]:
                top_items = ", ".join(f"{k}={v}" for k, v in dist[:4])
                parts.append(f'<tr><td><code>{html_escape(url)}</code></td><td>{html_escape(top_items)}</td></tr>')
            parts.append("</table>")

        if summary["status_counts"] or summary["level_counts"]:
            parts.append("<p style='margin-top:14px;'><strong>📈 错误构成：</strong> ")
            bits = []
            if summary["status_counts"]:
                bits.append("状态码: " + ", ".join(f"{k}={v}" for k, v in summary["status_counts"]))
            if summary["level_counts"]:
                bits.append("级别: " + ", ".join(f"{k}={v}" for k, v in summary["level_counts"]))
            parts.append("  |  ".join(bits) + "</p>")

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

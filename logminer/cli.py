import argparse
import sys
from datetime import datetime
from typing import Optional, Any, Tuple, Dict, List

from .config import load_config, get_default_config, AppConfig
from .parser import LogParser
from .templater import LogTemplater
from .detector import AnomalyDetector
from .context import ContextExtractor
from .reporter import Reporter
from .chart import ASCIITrendChart
from .exporter import RegexExporter


def parse_datetime(s: str) -> Optional[datetime]:
    formats = [
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M %z",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y%m%d %H%M%S",
        "%Y%m%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logminer",
        description="日志异常模式挖掘工具 - 从日志中发现频率突变模式并生成异常报告",
    )
    subparsers = parser.add_subparsers(dest="command", help="可用子命令")

    analyze_parser = subparsers.add_parser("analyze", help="分析日志文件，检测异常模式")
    analyze_parser.add_argument("logfile", help="日志文件路径")
    analyze_parser.add_argument("-c", "--config", default=None, help="配置文件路径 (YAML)")
    analyze_parser.add_argument("-f", "--format", default=None,
                                choices=["apache_combined", "nginx_combined", "syslog", "application"],
                                help="指定日志格式（覆盖配置文件）")
    analyze_parser.add_argument("--start", default=None, help="开始时间 (如 2024-01-01 10:00:00)")
    analyze_parser.add_argument("--end", default=None, help="结束时间 (如 2024-01-01 12:00:00)")
    analyze_parser.add_argument("-w", "--window", type=int, default=None,
                                help="移动平均窗口大小（覆盖配置文件）")
    analyze_parser.add_argument("-t", "--threshold", type=float, default=None,
                                help="异常检测阈值（覆盖配置文件）")
    analyze_parser.add_argument("-m", "--method", default=None,
                                choices=["zscore", "diff"],
                                help="异常检测方法（覆盖配置文件）")
    analyze_parser.add_argument("-b", "--bucket", type=int, default=None,
                                help="时间桶大小（分钟，覆盖配置文件）")
    analyze_parser.add_argument("-n", "--top", type=int, default=20,
                                help="显示前N个异常")
    analyze_parser.add_argument("--no-chart", action="store_true", help="不显示趋势图")
    analyze_parser.add_argument("--chart-only", action="store_true", help="仅显示趋势图")
    analyze_parser.add_argument("-o", "--output", default=None, help="输出报告到文件")
    analyze_parser.add_argument("--report-format", default="text",
                                choices=["text", "csv", "html"],
                                help="报告输出格式 (text/csv/html)")
    analyze_parser.add_argument("--url-prefix", default=None,
                                help="按 URL 前缀过滤 (如 /api/)")
    analyze_parser.add_argument("--status-class", default=None,
                                choices=["2xx", "3xx", "4xx", "5xx", "error"],
                                help="按状态码类别过滤 (error=4xx+5xx)")
    analyze_parser.add_argument("--log-level", default=None,
                                help="按应用日志级别过滤 (如 ERROR/WARN/INFO)")
    analyze_parser.add_argument("--errors-only", action="store_true",
                                help="只看错误类日志 (4xx/5xx/ERROR等)")
    analyze_parser.add_argument("--export-context", action="store_true",
                                help="将每个异常的上下文原始日志打包保存（与报告同目录，按模板编号分文件）")

    export_parser = subparsers.add_parser("export", help="导出模板为正则表达式规则")
    export_parser.add_argument("logfile", help="日志文件路径")
    export_parser.add_argument("-c", "--config", default=None, help="配置文件路径 (YAML)")
    export_parser.add_argument("-f", "--format", default=None,
                               choices=["apache_combined", "nginx_combined", "syslog", "application"],
                               help="指定日志格式")
    export_parser.add_argument("--start", default=None, help="开始时间")
    export_parser.add_argument("--end", default=None, help="结束时间")
    export_parser.add_argument("--export-format", default="json",
                               choices=["json", "yaml", "plain"],
                               help="导出格式")
    export_parser.add_argument("--min-count", type=int, default=1,
                               help="最小出现次数过滤")
    export_parser.add_argument("-o", "--output", default=None, help="输出到文件")

    template_parser = subparsers.add_parser("templates", help="列出所有发现的日志模板")
    template_parser.add_argument("logfile", help="日志文件路径")
    template_parser.add_argument("-c", "--config", default=None, help="配置文件路径 (YAML)")
    template_parser.add_argument("-f", "--format", default=None,
                                 choices=["apache_combined", "nginx_combined", "syslog", "application"],
                                 help="指定日志格式")
    template_parser.add_argument("--start", default=None, help="开始时间")
    template_parser.add_argument("--end", default=None, help="结束时间")
    template_parser.add_argument("--sort", default="count", choices=["count", "id"],
                                 help="排序方式")
    template_parser.add_argument("--min-count", type=int, default=1,
                                 help="最小出现次数过滤")
    template_parser.add_argument("--errors-only", action="store_true",
                                 help="只显示错误类模板 (4xx/5xx/ERROR等)")
    template_parser.add_argument("--url-prefix", default=None,
                                 help="按 URL 前缀过滤 (如 /api/)")
    template_parser.add_argument("--status-class", default=None,
                                 choices=["2xx", "3xx", "4xx", "5xx", "error"],
                                 help="按状态码类别过滤 (error=4xx+5xx)")
    template_parser.add_argument("--log-level", default=None,
                                 help="按应用日志级别过滤 (如 ERROR/WARN/INFO)")

    compare_parser = subparsers.add_parser("compare", help="对比两个时间段的模板频率变化")
    compare_parser.add_argument("logfile", help="日志文件路径")
    compare_parser.add_argument("-c", "--config", default=None, help="配置文件路径 (YAML)")
    compare_parser.add_argument("-f", "--format", default=None,
                                choices=["apache_combined", "nginx_combined", "syslog", "application"],
                                help="指定日志格式")
    compare_parser.add_argument("--period1-start", default=None, help="时间段1开始时间（使用--baseline时可选）")
    compare_parser.add_argument("--period1-end", default=None, help="时间段1结束时间（使用--baseline时可选）")
    compare_parser.add_argument("--period2-start", required=True, help="时间段2开始时间（目标窗口）")
    compare_parser.add_argument("--period2-end", required=True, help="时间段2结束时间（目标窗口）")
    compare_parser.add_argument("-n", "--top", type=int, default=10,
                                help="显示前N个增长/下降模板")
    compare_parser.add_argument("--errors-only", action="store_true",
                                help="只对比错误类模板")
    compare_parser.add_argument("--url-prefix", default=None,
                                help="按 URL 前缀过滤 (如 /api/)")
    compare_parser.add_argument("--status-class", default=None,
                                choices=["2xx", "3xx", "4xx", "5xx", "error"],
                                help="按状态码类别过滤 (error=4xx+5xx)")
    compare_parser.add_argument("--log-level", default=None,
                                help="按应用日志级别过滤 (如 ERROR/WARN/INFO)")
    compare_parser.add_argument("--baseline", default=None,
                                choices=["prev_day", "history_avg"],
                                help="基线对比方式：prev_day(前一天同时段) / history_avg(历史均值)")
    compare_parser.add_argument("--baseline-days", type=int, default=7,
                                help="历史均值基线的天数（默认7天）")
    compare_parser.add_argument("--show-categories", action="store_true",
                                help="显示新增、长期高频、稳定变化的分类")
    compare_parser.add_argument("--postmortem", action="store_true",
                                help="故障复盘视图：自动对比三组基线（前一天同窗口/历史均值/故障前1小时）并按四类分类")
    compare_parser.add_argument("--export-report", action="store_true",
                                help="故障复盘模式下导出复盘包（三组基线表+四类模板清单+上下文日志zip）")
    compare_parser.add_argument("-o", "--output", default=None,
                                help="复盘包输出文件路径前缀（默认 postmortem_report）")

    return parser


def _load_and_apply_overrides(args) -> AppConfig:
    if args.config:
        config = load_config(args.config)
    else:
        config = get_default_config()

    if hasattr(args, "window") and args.window is not None:
        config.anomaly.window_size = args.window
    if hasattr(args, "threshold") and args.threshold is not None:
        config.anomaly.threshold = args.threshold
    if hasattr(args, "method") and args.method is not None:
        config.anomaly.method = args.method
    if hasattr(args, "bucket") and args.bucket is not None:
        config.time_bucket_minutes = args.bucket

    if hasattr(args, "format") and args.format:
        from .config import BUILTIN_FORMATS
        if args.format in BUILTIN_FORMATS:
            config.log_formats = [BUILTIN_FORMATS[args.format]]

    return config


def cmd_analyze(args):
    config = _load_and_apply_overrides(args)

    time_start = parse_datetime(args.start) if args.start else None
    time_end = parse_datetime(args.end) if args.end else None

    parser = LogParser(config)
    entries = parser.parse_file(args.logfile, time_start, time_end)

    if not entries:
        print("未找到日志条目。")
        return

    entries = _filter_entries(entries, args)
    if not entries:
        print("过滤后无符合条件的日志条目。")
        return

    print(f"已解析 {len(entries)} 条日志")

    templater = LogTemplater(config)
    template_entries = templater.process_entries(entries)

    all_templates = templater.get_all_templates()
    templates_dict = {t.template_id: t for t in all_templates}

    print(f"发现 {len(all_templates)} 个日志模板")

    detector = AnomalyDetector(
        window_size=config.anomaly.window_size,
        threshold=config.anomaly.threshold,
        method=config.anomaly.method,
        min_count=config.anomaly.min_count,
        bucket_minutes=config.time_bucket_minutes,
    )

    template_series = {}
    for tid, entry_list in template_entries.items():
        if templater.is_whitelisted(templates_dict[tid].pattern):
            continue
        series = detector.build_template_time_series(entry_list)
        template_series[tid] = series

    anomalies = detector.detect_template_anomalies(template_series, templates_dict)

    if not args.chart_only:
        ctx_extractor = ContextExtractor(context_lines=config.context_lines)
        reporter = Reporter(ctx_extractor)

        report_format = getattr(args, "report_format", "text")
        if report_format == "csv":
            report = reporter.generate_report_csv(
                anomalies, entries, template_entries, templates_dict, top_n=args.top
            )
        elif report_format == "html":
            report = reporter.generate_report_html(
                anomalies, entries, template_entries, templates_dict, top_n=args.top
            )
        else:
            report = reporter.generate_report(
                anomalies, entries, template_entries, templates_dict, top_n=args.top
            )

        if getattr(args, "export_context", False):
            import os, zipfile
            output_base = args.output or f"logminer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            base_dir = os.path.dirname(os.path.abspath(output_base)) or "."
            stem = os.path.splitext(os.path.basename(output_base))[0]
            ctx_dir = os.path.join(base_dir, f"{stem}_contexts")
            os.makedirs(ctx_dir, exist_ok=True)
            manifest = []
            ctx_count = 0
            for i, anomaly in enumerate(anomalies[:args.top], 1):
                tmpl = anomaly.template
                if not tmpl:
                    continue
                ctx = ctx_extractor.extract(anomaly, entries, template_entries)
                lines = []
                lines.append(f"=== 上下文详情 编号 [{i}] 模板ID: {anomaly.template_id} ===")
                lines.append(f"严重程度: {anomaly.severity} ({anomaly.severity_score:.1f})")
                if tmpl.status_code:
                    lines.append(f"状态码: {tmpl.status_code}")
                if tmpl.level:
                    lines.append(f"日志级别: {tmpl.level}")
                lines.append(f"异常时间桶: {anomaly.bucket_time}")
                lines.append(f"观测值: {anomaly.observed}  期望值: {anomaly.expected:.1f}  异常分数: {anomaly.score:.2f}")
                lines.append(f"方向: {anomaly.direction}")
                lines.append(f"模板: {tmpl.pattern}")
                lines.append("")
                if ctx.get("before"):
                    lines.append(f"--- 异常点之前（{len(ctx['before'])}条）---")
                    for e in ctx["before"]:
                        lines.append(e.raw)
                if ctx.get("at"):
                    lines.append("")
                    lines.append(f"--- 异常点附近（{len(ctx['at'])}条，同模板±5分钟）---")
                    for e in ctx["at"]:
                        lines.append(e.raw)
                if ctx.get("after"):
                    lines.append("")
                    lines.append(f"--- 异常点之后（{len(ctx['after'])}条）---")
                    for e in ctx["after"]:
                        lines.append(e.raw)
                safe_id = anomaly.template_id.replace("/", "_").replace("\\", "_")
                fname = f"{i:03d}_{safe_id}.log"
                fpath = os.path.join(ctx_dir, fname)
                with open(fpath, "w", encoding="utf-8") as fc:
                    fc.write("\n".join(lines))
                ctx_count += 1
                sev_mark = f"[{anomaly.severity.upper()}]"
                manifest.append(f"{i:03d} | {sev_mark:<8} | {anomaly.template_id:<14} | {fname}")
            zip_path = os.path.join(base_dir, f"{stem}_contexts.zip")
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(ctx_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        zf.write(fp, os.path.relpath(fp, ctx_dir))
                if manifest:
                    zf.writestr("000_MANIFEST.txt", "\n".join(manifest))
            print(f"\n上下文已打包保存: 目录={ctx_dir}  ZIP={zip_path}  文件数={ctx_count}")

        if report_format == "text":
            print(report)
        else:
            if not args.output:
                default_ext = ".csv" if report_format == "csv" else ".html"
                args.output = f"logminer_report{default_ext}"
            print(f"报告将以 {report_format.upper()} 格式保存到: {args.output}")

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n报告已保存到: {args.output}")

    if not args.no_chart and template_series:
        chart = ASCIITrendChart()
        if args.chart_only:
            chart_output = chart.render_multi(template_series, top_n=10)
        else:
            top_templates = sorted(
                template_series.items(),
                key=lambda x: sum(x[1].values()),
                reverse=True,
            )[:3]
            chart_output = ""
            for tid, series in top_templates:
                tmpl = templates_dict.get(tid)
                title = f"Template {tid} ({tmpl.pattern[:40]}...)" if tmpl else f"Template {tid}"
                chart_output += chart.render(series, title=title) + "\n\n"

        print("\n" + chart_output)


def cmd_export(args):
    config = _load_and_apply_overrides(args)

    time_start = parse_datetime(args.start) if args.start else None
    time_end = parse_datetime(args.end) if args.end else None

    parser = LogParser(config)
    entries = parser.parse_file(args.logfile, time_start, time_end)

    if not entries:
        print("未找到日志条目。")
        return

    templater = LogTemplater(config)
    templater.process_entries(entries)

    all_templates = templater.get_all_templates()
    filtered = [t for t in all_templates if t.count >= args.min_count]
    filtered.sort(key=lambda t: t.count, reverse=True)

    exporter = RegexExporter()
    content = exporter.export_rules(filtered, output_format=args.export_format)

    if args.output:
        exporter.save_to_file(filtered, args.output, output_format=args.export_format)
        print(f"已导出 {len(filtered)} 条规则到: {args.output}")
    else:
        print(content)


def cmd_templates(args):
    config = _load_and_apply_overrides(args)

    time_start = parse_datetime(args.start) if args.start else None
    time_end = parse_datetime(args.end) if args.end else None

    parser = LogParser(config)
    entries = parser.parse_file(args.logfile, time_start, time_end)

    if not entries:
        print("未找到日志条目。")
        return

    entries = _filter_entries(entries, args)
    if not entries:
        print("过滤后无符合条件的日志条目。")
        return

    templater = LogTemplater(config)
    templater.process_entries(entries)

    all_templates = templater.get_all_templates()
    filtered = [t for t in all_templates if t.count >= args.min_count]

    if hasattr(args, "errors_only") and args.errors_only:
        filtered = [t for t in filtered if t.is_error()]

    if args.sort == "count":
        filtered.sort(key=lambda t: t.count, reverse=True)
    else:
        filtered.sort(key=lambda t: t.template_id)

    print(f"{'ID':<10} {'Count':<10} {'Status/Level':<14} {'Template'}")
    print("-" * 90)
    for t in filtered:
        whitelisted = " [WL]" if templater.is_whitelisted(t.pattern) else ""
        status_info = t.status_code or t.level or ""
        is_err = " [ERR]" if t.is_error() else ""
        print(f"{t.template_id:<10} {t.count:<10} {status_info:<14} {t.pattern[:55]}{whitelisted}{is_err}")


def _compare_two_periods(config, all_entries, p1_start, p1_end, p2_start, p2_end,
                        baseline_desc, target_desc, top_n, errors_only, args):
    from datetime import timedelta
    from collections import defaultdict

    p1_entries = [e for e in all_entries if _in_range(e.timestamp, p1_start, p1_end)]
    p2_entries = [e for e in all_entries if _in_range(e.timestamp, p2_start, p2_end)]

    print(f"{baseline_desc}: {len(p1_entries)} 条日志")
    print(f"{target_desc}: {len(p2_entries)} 条日志")
    print()

    templater1 = LogTemplater(config)
    templater1.process_entries(p1_entries)

    templater2 = LogTemplater(config)
    templater2.process_entries(p2_entries)

    p1_counts = {t.pattern: t.count for t in templater1.get_all_templates()}
    p2_counts = {t.pattern: t.count for t in templater2.get_all_templates()}

    p1_tmpl = {t.pattern: t for t in templater1.get_all_templates()}
    p2_tmpl = {t.pattern: t for t in templater2.get_all_templates()}
    total_p1 = sum(p1_counts.values()) if p1_counts else 1
    total_p2 = sum(p2_counts.values()) if p2_counts else 1

    all_patterns = set(p1_counts.keys()) | set(p2_counts.keys())
    changes = []
    for pat in all_patterns:
        c1 = p1_counts.get(pat, 0)
        c2 = p2_counts.get(pat, 0)
        diff = c2 - c1
        ratio = (c2 - c1) / c1 if c1 > 0 else (float('inf') if c2 > 0 else 0.0)
        tmpl_info = p2_tmpl.get(pat) or p1_tmpl.get(pat)
        if errors_only and tmpl_info and not tmpl_info.is_error():
            continue
        freq_p1 = c1 / total_p1 if total_p1 > 0 else 0
        freq_p2 = c2 / total_p2 if total_p2 > 0 else 0
        if c1 == 0 and c2 > 0:
            category = "NEW"
        elif freq_p1 > 0.05 and ratio > 0:
            category = "HOT_GROW"
        elif freq_p1 > 0.01:
            category = "HIGH_FREQ"
        else:
            category = "NORMAL"
        changes.append({
            "pattern": pat, "count1": c1, "count2": c2, "diff": diff, "ratio": ratio,
            "template": tmpl_info, "category": category, "freq1": freq_p1, "freq2": freq_p2,
        })
    return changes


def cmd_compare(args):
    config = _load_and_apply_overrides(args)
    from datetime import timedelta

    p2_start = parse_datetime(args.period2_start)
    p2_end = parse_datetime(args.period2_end)

    if not all([p2_start, p2_end]):
        print("错误：必须提供目标时间段（--period2-start/end）")
        return
    duration = p2_end - p2_start

    is_postmortem = getattr(args, "postmortem", False)

    log_parser = LogParser(config)
    all_entries = log_parser.parse_file(args.logfile)
    if not all_entries:
        print("未找到日志条目。")
        return
    all_entries = _filter_entries(all_entries, args)

    if is_postmortem:
        num_days = args.baseline_days
        target_desc = f"故障窗口 ({args.period2_start} ~ {args.period2_end})"
        p2_entries = [e for e in all_entries if _in_range(e.timestamp, p2_start, p2_end)]
        templater_p2 = LogTemplater(config)
        template_entries_p2 = templater_p2.process_entries(p2_entries)
        p2_counts = {t.pattern: t.count for t in templater_p2.get_all_templates()}
        p2_tmpl = {t.pattern: t for t in templater_p2.get_all_templates()}
        pattern_entries_p2: Dict[str, List[Tuple[Any, Any]]] = {}
        for tid, lst in template_entries_p2.items():
            if lst:
                pat = lst[0][1].pattern
                pattern_entries_p2[pat] = lst

        prev_day_start = p2_start - timedelta(days=1)
        prev_day_end = prev_day_start + duration
        pd_entries = [e for e in all_entries if _in_range(e.timestamp, prev_day_start, prev_day_end)]
        templater_pd = LogTemplater(config)
        templater_pd.process_entries(pd_entries)
        pd_counts = {t.pattern: t.count for t in templater_pd.get_all_templates()}

        hist_counts_total = {}
        valid_days = 0
        for d in range(1, num_days + 1):
            day_start = p2_start - timedelta(days=d)
            day_end = day_start + duration
            day_entries = [e for e in all_entries if _in_range(e.timestamp, day_start, day_end)]
            if len(day_entries) == 0:
                continue
            tpl = LogTemplater(config)
            tpl.process_entries(day_entries)
            valid_days += 1
            for t in tpl.get_all_templates():
                hist_counts_total[t.pattern] = hist_counts_total.get(t.pattern, 0) + t.count
        hist_counts = {}
        if valid_days > 0:
            hist_counts = {pat: cnt / valid_days for pat, cnt in hist_counts_total.items()}
            print(f"历史同窗口均值: 过去 {valid_days}/{num_days} 天有数据, 归一化除数={valid_days}")
        else:
            print(f"历史同窗口均值: 过去 {num_days} 天无同窗口数据")

        prehour_start = p2_start - timedelta(hours=1)
        prehour_end = p2_start
        ph_entries = [e for e in all_entries if _in_range(e.timestamp, prehour_start, prehour_end)]
        templater_ph = LogTemplater(config)
        templater_ph.process_entries(ph_entries)
        ph_counts = {t.pattern: t.count for t in templater_ph.get_all_templates()}

        print()
        print("=" * 80)
        print(f"  故障复盘视图 — 故障窗口: {args.period2_start} ~ {args.period2_end} ({duration})")
        print("=" * 80)
        print()

        all_pats = set(p2_counts.keys()) | set(pd_counts.keys()) | set(hist_counts.keys()) | set(ph_counts.keys())

        new_templates, rebound_templates, sustained_templates, recovering_templates = [], [], [], []
        for pat in all_pats:
            cur = p2_counts.get(pat, 0)
            prev_day = pd_counts.get(pat, 0)
            hist_avg = hist_counts.get(pat, 0)
            pre_hour = ph_counts.get(pat, 0)
            baseline = max(prev_day, hist_avg, pre_hour, 1)

            tmpl = p2_tmpl.get(pat)
            if args.errors_only and tmpl and not tmpl.is_error():
                continue

            is_cur_high = cur > 0 and (cur >= 2 * baseline or (cur >= 5 and baseline <= 1))
            prev_high = max(prev_day, hist_avg, pre_hour)

            if prev_day == 0 and hist_avg == 0 and pre_hour == 0 and cur > 0:
                new_templates.append((pat, cur, prev_day, hist_avg, pre_hour, tmpl))
            elif cur > prev_day and cur > hist_avg and cur > pre_hour and cur > 0:
                rebound_templates.append((pat, cur, prev_day, hist_avg, pre_hour, tmpl))
            elif cur > 0 and is_cur_high and prev_high > baseline * 0.5:
                sustained_templates.append((pat, cur, prev_day, hist_avg, pre_hour, tmpl))
            elif cur < prev_day * 0.5 or cur < hist_avg * 0.5:
                if cur > 0 or prev_day > 0 or hist_avg > 0:
                    recovering_templates.append((pat, cur, prev_day, hist_avg, pre_hour, tmpl))

        buckets = [
            ("new", "🆕 新增模板（三组基线均为0，故障窗口首次出现）", new_templates),
            ("rebound", "📈 回升模板（比三组基线都明显升高）", rebound_templates),
            ("sustained", "🔥 持续高位（之前就高，故障期仍然高）", sustained_templates),
            ("recovering", "✅ 恢复下降（比基线明显降低）", recovering_templates),
        ]
        for tag, title, bucket in buckets:
            if not bucket:
                continue
            bucket.sort(key=lambda x: x[1], reverse=True)
            print("-" * 80)
            print(f"  {title}: {len(bucket)} 个")
            print("-" * 80)
            print(f"  {'当前':>6}  {'前一天':>6}  {'历史均':>6}  {'前1h':>6}  模板")
            for item in bucket[:args.top]:
                pat, cur, pd, ha, ph, tmpl = item
                is_err = " [ERR]" if tmpl and tmpl.is_error() else ""
                ha_s = f"{ha:.1f}" if isinstance(ha, float) else str(ha)
                print(f"  {cur:>6}  {pd:>6}  {ha_s:>6}  {ph:>6}  {pat[:44]}{is_err}")
            print()

        if getattr(args, "export_report", False):
            import os, zipfile
            output_base = args.output or f"postmortem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            base_dir = os.path.dirname(os.path.abspath(output_base)) or "."
            stem = os.path.splitext(os.path.basename(output_base))[0]
            out_dir = os.path.join(base_dir, stem)
            os.makedirs(out_dir, exist_ok=True)

            summary_path = os.path.join(out_dir, "00_SUMMARY.txt")
            with open(summary_path, "w", encoding="utf-8") as fs:
                fs.write("=" * 72 + "\n")
                fs.write("  故障复盘报告\n")
                fs.write("=" * 72 + "\n\n")
                fs.write(f"故障窗口: {args.period2_start} ~ {args.period2_end} (时长: {duration})\n")
                fs.write(f"基线对比: 前一天同时段 | 过去{num_days}天同窗口均值 | 故障前1小时\n")
                fs.write(f"故障窗口日志数: {len(p2_entries)}\n")
                fs.write(f"历史有效天数: {valid_days}/{num_days}\n\n")
                for tag, title, bucket in buckets:
                    if not bucket:
                        continue
                    bucket.sort(key=lambda x: x[1], reverse=True)
                    fs.write("-" * 72 + "\n")
                    fs.write(f"  {title}: {len(bucket)} 个\n")
                    fs.write("-" * 72 + "\n")
                    fs.write(f"  {'当前':>6}  {'前一天':>6}  {'历史均':>6}  {'前1h':>6}  模板\n")
                    for item in bucket:
                        pat, cur, pd, ha, ph, tmpl = item
                        is_err = " [ERR]" if tmpl and tmpl.is_error() else ""
                        ha_s = f"{ha:.1f}" if isinstance(ha, float) else str(ha)
                        fs.write(f"  {cur:>6}  {pd:>6}  {ha_s:>6}  {ph:>6}  {pat}{is_err}\n")
                    fs.write("\n")

            baseline_path = os.path.join(out_dir, "01_BASELINES_COMPARISON.csv")
            with open(baseline_path, "w", encoding="utf-8", newline="") as fb:
                import csv
                w = csv.writer(fb)
                w.writerow(["分类", "模板", "当前故障窗口", "前一天同时段", "历史天均值", "故障前1小时",
                            "状态码/级别", "错误类"])
                for tag, title, bucket in buckets:
                    bucket.sort(key=lambda x: x[1], reverse=True)
                    for pat, cur, pd, ha, ph, tmpl in bucket:
                        sc = (tmpl.status_code or tmpl.level or "") if tmpl else ""
                        is_err = "是" if (tmpl and tmpl.is_error()) else "否"
                        w.writerow([title, pat, cur, pd, ha, ph, sc, is_err])

            templates_path = os.path.join(out_dir, "02_TEMPLATES_BY_CATEGORY.txt")
            with open(templates_path, "w", encoding="utf-8") as ft:
                for tag, title, bucket in buckets:
                    if not bucket:
                        continue
                    bucket.sort(key=lambda x: x[1], reverse=True)
                    ft.write(f"\n===== [{tag.upper()}] {title} =====\n")
                    for pat, cur, pd, ha, ph, tmpl in bucket:
                        ft.write(f"  - 当前={cur} 前一天={pd} 历史均={ha} 前1h={ph}  模板: {pat}\n")
                        if tmpl:
                            meta = []
                            if tmpl.status_code:
                                meta.append(f"status={tmpl.status_code}")
                            if tmpl.level:
                                meta.append(f"level={tmpl.level}")
                            if meta:
                                ft.write(f"    元信息: {' '.join(meta)}\n")
                        ft.write("\n")

            ctx_dir = os.path.join(out_dir, "contexts")
            os.makedirs(ctx_dir, exist_ok=True)
            ctx_count = 0
            manifest = []
            for tag, title, bucket in buckets:
                bucket.sort(key=lambda x: x[1], reverse=True)
                for idx, (pat, cur, pd, ha, ph, tmpl) in enumerate(bucket[:args.top], 1):
                    if not tmpl:
                        continue
                    elist = pattern_entries_p2.get(pat, [])
                    if not elist:
                        continue
                    lines = []
                    lines.append(f"=== 上下文: {title} 排名#{idx} ===")
                    lines.append(f"模板: {pat}")
                    lines.append(f"故障窗口计数: {cur}  |  前一天={pd}  历史均值={ha}  故障前1h={ph}")
                    if tmpl.status_code:
                        lines.append(f"状态码: {tmpl.status_code}")
                    if tmpl.level:
                        lines.append(f"日志级别: {tmpl.level}")
                    lines.append("")
                    lines.append(f"--- 原始日志样例（该模板在故障窗口内的 {min(20, len(elist))} 条）---")
                    for e, _ in elist[:20]:
                        lines.append(e.raw)
                    safe_id = (tmpl.template_id or pat[:20]).replace("/", "_").replace("\\", "_")
                    fname = f"{tag}_{idx:03d}_{safe_id}.log"
                    fpath = os.path.join(ctx_dir, fname)
                    with open(fpath, "w", encoding="utf-8") as fc:
                        fc.write("\n".join(lines))
                    ctx_count += 1
                    manifest.append(f"{tag:<10} #{idx:03d} | {tmpl.template_id or pat[:20]:<14} | {fname}")

            if manifest:
                manifest_path = os.path.join(ctx_dir, "000_MANIFEST.txt")
                with open(manifest_path, "w", encoding="utf-8") as fm:
                    fm.write("故障复盘上下文索引\n")
                    fm.write("=" * 72 + "\n")
                    fm.write("\n".join(manifest))

            zip_path = os.path.join(base_dir, f"{stem}.zip")
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(out_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        zf.write(fp, os.path.relpath(fp, out_dir))

            print(f"\n复盘包已导出: 目录={out_dir}  ZIP={zip_path}  上下文文件数={ctx_count}")

        return

    if args.baseline:
        if args.baseline == "prev_day":
            p1_start = p2_start - timedelta(days=1)
            p1_end = p1_start + duration
        elif args.baseline == "history_avg":
            baseline_counts = {}
            valid_days = 0
            for d in range(1, args.baseline_days + 1):
                day_start = p2_start - timedelta(days=d)
                day_end = day_start + duration
                day_entries = [e for e in all_entries if _in_range(e.timestamp, day_start, day_end)]
                if not day_entries:
                    continue
                tpl = LogTemplater(config)
                tpl.process_entries(day_entries)
                valid_days += 1
                for t in tpl.get_all_templates():
                    baseline_counts[t.pattern] = baseline_counts.get(t.pattern, 0) + t.count
            p1_start = p2_start - timedelta(days=args.baseline_days)
            p1_end = p2_start
            p1_entries = []
            if valid_days > 0:
                baseline_avg = {pat: cnt / valid_days for pat, cnt in baseline_counts.items()}
                baseline_desc = f"过去{valid_days}/{args.baseline_days}天同窗口均值"
                p2_entries_target = [e for e in all_entries if _in_range(e.timestamp, p2_start, p2_end)]
                print(f"{baseline_desc}: 窗口大小={duration}, 归一化除数={valid_days}")
                print(f"目标时间段 ({args.period2_start} ~ {args.period2_end}): {len(p2_entries_target)} 条日志")
                print()

                templater2 = LogTemplater(config)
                templater2.process_entries(p2_entries_target)
                p2_counts = {t.pattern: t.count for t in templater2.get_all_templates()}
                p2_tmpl = {t.pattern: t for t in templater2.get_all_templates()}
                p1_counts = baseline_avg
                p1_tmpl = {}
                total_p1 = sum(p1_counts.values()) if p1_counts else 1
                total_p2 = sum(p2_counts.values()) if p2_counts else 1
                all_patterns = set(p1_counts.keys()) | set(p2_counts.keys())
                changes = []
                for pat in all_patterns:
                    c1 = p1_counts.get(pat, 0)
                    c2 = p2_counts.get(pat, 0)
                    diff = c2 - c1
                    ratio = (c2 - c1) / c1 if c1 > 0 else (float('inf') if c2 > 0 else 0.0)
                    tmpl_info = p2_tmpl.get(pat)
                    if args.errors_only and tmpl_info and not tmpl_info.is_error():
                        continue
                    freq_p1 = c1 / total_p1 if total_p1 > 0 else 0
                    freq_p2 = c2 / total_p2 if total_p2 > 0 else 0
                    if c1 == 0 and c2 > 0:
                        category = "NEW"
                    elif freq_p1 > 0.05 and ratio > 0:
                        category = "HOT_GROW"
                    elif freq_p1 > 0.01:
                        category = "HIGH_FREQ"
                    else:
                        category = "NORMAL"
                    changes.append({
                        "pattern": pat, "count1": c1, "count2": c2, "diff": diff, "ratio": ratio,
                        "template": tmpl_info, "category": category, "freq1": freq_p1, "freq2": freq_p2,
                    })
                top_n = args.top
                if args.show_categories:
                    for cat, cat_name in [
                        ("NEW", "新增模板（基线为0）"),
                        ("HOT_GROW", "长期高频且显著增长"),
                        ("HIGH_FREQ", "长期高频"),
                        ("NORMAL", "其他变化"),
                    ]:
                        cat_items = [c for c in changes if c["category"] == cat and c["diff"] >= 0]
                        if not cat_items:
                            continue
                        cat_items.sort(key=lambda x: (x["ratio"], x["diff"]), reverse=True)
                        print("=" * 80)
                        print(f"  {cat_name}: {len(cat_items)} 个")
                        print("=" * 80)
                        print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
                        print("-" * 80)
                        for c in cat_items[:top_n]:
                            ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "NEW"
                            diff_str = f"+{c['diff']:.0f}" if c['diff'] >= 0 else str(c['diff'])
                            c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
                            c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
                            is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
                            print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}")
                        print()
                    return
                increases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]), reverse=True)
                decreases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]))
                print("=" * 80)
                print(f"  增长最快的 {min(top_n, len(increases))} 个模板（目标 vs {baseline_desc}）")
                print("=" * 80)
                print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
                print("-" * 80)
                for c in increases[:top_n]:
                    ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "NEW"
                    diff_str = f"+{c['diff']:.0f}" if c['diff'] >= 0 else str(c['diff'])
                    c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
                    c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
                    is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
                    cat_tag = f" [{c['category']}]" if c['category'] in ("NEW", "HOT_GROW") else ""
                    print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}{cat_tag}")
                print()
                print("=" * 80)
                drops = [c for c in decreases if c['diff'] < 0]
                print(f"  下降最快的 {min(top_n, len(drops))} 个模板（目标 vs {baseline_desc}）")
                print("=" * 80)
                print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
                print("-" * 80)
                for c in decreases[:top_n]:
                    if c['diff'] >= 0:
                        continue
                    ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "N/A"
                    diff_str = f"+{c['diff']:.0f}" if c['diff'] >= 0 else str(c['diff'])
                    c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
                    c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
                    is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
                    print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}")
                print()
                return
        else:
            p1_start = parse_datetime(args.period1_start)
            p1_end = parse_datetime(args.period1_end)
        baseline_desc_map = {
            "prev_day": f"前一天同时段 ({p1_start.strftime('%Y-%m-%d %H:%M:%S')} ~ {p1_end.strftime('%Y-%m-%d %H:%M:%S')})",
            "history_avg": f"过去{args.baseline_days}天同窗口均值",
        }
        baseline_desc = baseline_desc_map.get(args.baseline, "时间段1")
    else:
        p1_start = parse_datetime(args.period1_start)
        p1_end = parse_datetime(args.period1_end)
        if not all([p1_start, p1_end]):
            print("错误：未使用 --baseline 时必须提供 --period1-start/end")
            return
        baseline_desc = "时间段1"

    changes = _compare_two_periods(
        config, all_entries, p1_start, p1_end, p2_start, p2_end,
        baseline_desc, f"目标时间段 ({args.period2_start} ~ {args.period2_end})",
        args.top, args.errors_only, args
    )
    if not changes:
        print("没有找到符合条件的模板。")
        return

    top_n = args.top
    if args.show_categories:
        for cat, cat_name in [
            ("NEW", "新增模板（基线为0）"),
            ("HOT_GROW", "长期高频且显著增长"),
            ("HIGH_FREQ", "长期高频"),
            ("NORMAL", "其他变化"),
        ]:
            cat_items = [c for c in changes if c["category"] == cat and c["diff"] >= 0]
            if not cat_items:
                continue
            cat_items.sort(key=lambda x: (x["ratio"], x["diff"]), reverse=True)
            print("=" * 80)
            print(f"  {cat_name}: {len(cat_items)} 个")
            print("=" * 80)
            print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
            print("-" * 80)
            for c in cat_items[:top_n]:
                ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "NEW"
                diff_str = f"+{c['diff']:.0f}" if isinstance(c['diff'], float) and c['diff'] >= 0 else (f"+{c['diff']}" if c['diff'] >= 0 else str(c['diff']))
                c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
                c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
                is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
                print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}")
            print()
        return

    increases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]), reverse=True)
    decreases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]))

    print("=" * 80)
    print(f"  增长最快的 {min(top_n, len(increases))} 个模板（目标 vs {baseline_desc}）")
    print("=" * 80)
    print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
    print("-" * 80)
    for c in increases[:top_n]:
        ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "NEW"
        diff_str = f"+{c['diff']:.0f}" if isinstance(c['diff'], float) and c['diff'] >= 0 else (f"+{c['diff']}" if c['diff'] >= 0 else str(c['diff']))
        c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
        c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
        is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
        cat_tag = f" [{c['category']}]" if c['category'] in ("NEW", "HOT_GROW") else ""
        print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}{cat_tag}")

    print()
    drops = [c for c in decreases if c['diff'] < 0]
    print("=" * 80)
    print(f"  下降最快的 {min(top_n, len(drops))} 个模板（目标 vs {baseline_desc}）")
    print("=" * 80)
    print(f"  {'变化率':>8}  {'增减':>8}  {'基线计数':>10}  {'目标计数':>10}  模板")
    print("-" * 80)
    for c in decreases[:top_n]:
        if c['diff'] >= 0:
            continue
        ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "N/A"
        diff_str = f"+{c['diff']:.0f}" if isinstance(c['diff'], float) and c['diff'] >= 0 else (f"+{c['diff']}" if c['diff'] >= 0 else str(c['diff']))
        c1_str = f"{c['count1']:.1f}" if isinstance(c['count1'], float) else str(c['count1'])
        c2_str = f"{c['count2']:.1f}" if isinstance(c['count2'], float) else str(c['count2'])
        is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
        print(f"  {ratio_str:>8}  {diff_str:>8}  {c1_str:>10}  {c2_str:>10}  {c['pattern'][:48]}{is_err}")
    print()


def _in_range(ts, start, end):
    if ts is None:
        return False
    from .parser import _naive_compare
    return _naive_compare(ts, start) >= 0 and _naive_compare(ts, end) <= 0


def _filter_entries(entries, args):
    from .parser import LogEntry
    filtered = []
    for e in entries:
        if hasattr(args, "errors_only") and args.errors_only and not e.is_error():
            continue
        if hasattr(args, "url_prefix") and args.url_prefix:
            request = e.fields.get("request", "") or ""
            msg = e.message or ""
            prefix = args.url_prefix.lstrip("/")
            parts = request.split()
            path = ""
            if len(parts) >= 2:
                path = parts[1].split("?")[0]
            target_path = path.lstrip("/")
            hit = False
            if target_path and target_path.startswith(prefix):
                hit = True
            elif path.startswith("/" + prefix):
                hit = True
            elif msg.startswith(prefix) or ("/" + prefix) in msg:
                hit = True
            if not hit:
                continue
        if hasattr(args, "status_class") and args.status_class:
            if args.status_class == "error":
                if e.status_class not in ("4xx", "5xx"):
                    continue
            elif e.status_class != args.status_class:
                continue
        if hasattr(args, "log_level") and args.log_level:
            if not e.level or e.level.upper() != args.log_level.upper():
                continue
        filtered.append(e)
    return filtered


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "export":
        cmd_export(args)
    elif args.command == "templates":
        cmd_templates(args)
    elif args.command == "compare":
        cmd_compare(args)


if __name__ == "__main__":
    main()

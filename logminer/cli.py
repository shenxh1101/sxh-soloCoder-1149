import argparse
import sys
from datetime import datetime
from typing import Optional

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


def cmd_compare(args):
    config = _load_and_apply_overrides(args)
    from datetime import timedelta

    p2_start = parse_datetime(args.period2_start)
    p2_end = parse_datetime(args.period2_end)

    if not all([p2_start, p2_end]):
        print("错误：必须提供目标时间段（--period2-start/end）")
        return

    if args.baseline:
        duration = p2_end - p2_start
        if args.baseline == "prev_day":
            p1_start = p2_start - timedelta(days=1)
            p1_end = p1_start + duration
        elif args.baseline == "history_avg":
            p1_start = p2_start - timedelta(days=args.baseline_days)
            p1_end = p2_start
        else:
            p1_start = parse_datetime(args.period1_start)
            p1_end = parse_datetime(args.period1_end)
        baseline_desc = {
            "prev_day": f"前一天同时段 ({p1_start.strftime('%Y-%m-%d %H:%M:%S')} ~ {p1_end.strftime('%Y-%m-%d %H:%M:%S')})",
            "history_avg": f"过去{args.baseline_days}天均值 ({p1_start.strftime('%Y-%m-%d %H:%M:%S')} ~ {p1_end.strftime('%Y-%m-%d %H:%M:%S')})",
        }.get(args.baseline, "时间段1")
    else:
        p1_start = parse_datetime(args.period1_start)
        p1_end = parse_datetime(args.period1_end)
        if not all([p1_start, p1_end]):
            print("错误：未使用 --baseline 时必须提供 --period1-start/end")
            return
        baseline_desc = "时间段1"

    log_parser = LogParser(config)
    all_entries = log_parser.parse_file(args.logfile)

    if not all_entries:
        print("未找到日志条目。")
        return

    all_entries = _filter_entries(all_entries, args)

    p1_entries = [e for e in all_entries if _in_range(e.timestamp, p1_start, p1_end)]
    p2_entries = [e for e in all_entries if _in_range(e.timestamp, p2_start, p2_end)]

    print(f"{baseline_desc}: {len(p1_entries)} 条日志")
    print(f"目标时间段 ({args.period2_start} ~ {args.period2_end}): {len(p2_entries)} 条日志")
    print()

    templater1 = LogTemplater(config)
    templater1.process_entries(p1_entries)

    templater2 = LogTemplater(config)
    templater2.process_entries(p2_entries)

    if args.baseline == "history_avg" and len(p1_entries) > 0:
        num_days = max(1, (p2_start - p1_start).days)
        p1_counts_raw = {t.pattern: t.count for t in templater1.get_all_templates()}
        p1_counts = {pat: cnt / num_days for pat, cnt in p1_counts_raw.items()}
        print(f"  (历史均值按 {num_days} 天归一化)")
        print()
    else:
        p1_counts = {t.pattern: t.count for t in templater1.get_all_templates()}

    p2_counts = {t.pattern: t.count for t in templater2.get_all_templates()}
    all_patterns = set(p1_counts.keys()) | set(p2_counts.keys())

    p1_tmpl = {t.pattern: t for t in templater1.get_all_templates()}
    p2_tmpl = {t.pattern: t for t in templater2.get_all_templates()}

    total_p1 = sum(p1_counts.values()) if p1_counts else 1
    total_p2 = sum(p2_counts.values()) if p2_counts else 1

    changes = []
    for pat in all_patterns:
        c1 = p1_counts.get(pat, 0)
        c2 = p2_counts.get(pat, 0)
        diff = c2 - c1
        if c1 > 0:
            ratio = (c2 - c1) / c1
        elif c2 > 0:
            ratio = float('inf')
        else:
            ratio = 0.0

        tmpl_info = p2_tmpl.get(pat) or p1_tmpl.get(pat)

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
            "pattern": pat,
            "count1": c1,
            "count2": c2,
            "diff": diff,
            "ratio": ratio,
            "template": tmpl_info,
            "category": category,
            "freq1": freq_p1,
            "freq2": freq_p2,
        })

    if not changes:
        print("没有找到符合条件的模板。")
        return

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
            for c in cat_items[:args.top]:
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

    top_n = args.top

    print("=" * 80)
    print(f"  增长最快的 {min(top_n, len(increases))} 个模板（目标时间段 vs {baseline_desc}）")
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
    print("=" * 80)
    print(f"  下降最快的 {min(top_n, len([c for c in decreases if c['diff'] < 0]))} 个模板（目标时间段 vs {baseline_desc}）")
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
            request = e.fields.get("request", "")
            msg = e.message or ""
            if args.url_prefix not in request and args.url_prefix not in msg:
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

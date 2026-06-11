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
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
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

    compare_parser = subparsers.add_parser("compare", help="对比两个时间段的模板频率变化")
    compare_parser.add_argument("logfile", help="日志文件路径")
    compare_parser.add_argument("-c", "--config", default=None, help="配置文件路径 (YAML)")
    compare_parser.add_argument("-f", "--format", default=None,
                                choices=["apache_combined", "nginx_combined", "syslog", "application"],
                                help="指定日志格式")
    compare_parser.add_argument("--period1-start", required=True, help="时间段1开始时间")
    compare_parser.add_argument("--period1-end", required=True, help="时间段1结束时间")
    compare_parser.add_argument("--period2-start", required=True, help="时间段2开始时间")
    compare_parser.add_argument("--period2-end", required=True, help="时间段2结束时间")
    compare_parser.add_argument("-n", "--top", type=int, default=10,
                                help="显示前N个增长/下降模板")
    compare_parser.add_argument("--errors-only", action="store_true",
                                help="只对比错误类模板")

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
        report = reporter.generate_report(
            anomalies, entries, template_entries, templates_dict, top_n=args.top
        )
        print(report)

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

    p1_start = parse_datetime(args.period1_start)
    p1_end = parse_datetime(args.period1_end)
    p2_start = parse_datetime(args.period2_start)
    p2_end = parse_datetime(args.period2_end)

    if not all([p1_start, p1_end, p2_start, p2_end]):
        print("错误：必须提供两个时间段的起止时间（--period1-start/end, --period2-start/end）")
        return

    log_parser = LogParser(config)
    all_entries = log_parser.parse_file(args.logfile)

    if not all_entries:
        print("未找到日志条目。")
        return

    p1_entries = [e for e in all_entries if _in_range(e.timestamp, p1_start, p1_end)]
    p2_entries = [e for e in all_entries if _in_range(e.timestamp, p2_start, p2_end)]

    print(f"时间段1 ({args.period1_start} ~ {args.period1_end}): {len(p1_entries)} 条日志")
    print(f"时间段2 ({args.period2_start} ~ {args.period2_end}): {len(p2_entries)} 条日志")
    print()

    templater1 = LogTemplater(config)
    templater1.process_entries(p1_entries)

    templater2 = LogTemplater(config)
    templater2.process_entries(p2_entries)

    p1_counts = {t.pattern: t.count for t in templater1.get_all_templates()}
    p2_counts = {t.pattern: t.count for t in templater2.get_all_templates()}

    all_patterns = set(p1_counts.keys()) | set(p2_counts.keys())

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

        tmpl_info = None
        for t in templater2.get_all_templates():
            if t.pattern == pat:
                tmpl_info = t
                break
        if tmpl_info is None:
            for t in templater1.get_all_templates():
                if t.pattern == pat:
                    tmpl_info = t
                    break

        if args.errors_only and tmpl_info and not tmpl_info.is_error():
            continue

        changes.append({
            "pattern": pat,
            "count1": c1,
            "count2": c2,
            "diff": diff,
            "ratio": ratio,
            "template": tmpl_info,
        })

    if not changes:
        print("没有找到符合条件的模板。")
        return

    increases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]), reverse=True)
    decreases = sorted(changes, key=lambda x: (x["ratio"], x["diff"]))

    top_n = args.top

    print("=" * 80)
    print(f"  增长最快的 {min(top_n, len(increases))} 个模板（时间段2 vs 时间段1）")
    print("=" * 80)
    print(f"  {'变化率':>8}  {'增减':>6}  {'P1计数':>8}  {'P2计数':>8}  模板")
    print("-" * 80)
    for c in increases[:top_n]:
        ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "NEW"
        diff_str = f"+{c['diff']}" if c['diff'] >= 0 else str(c['diff'])
        is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
        print(f"  {ratio_str:>8}  {diff_str:>6}  {c['count1']:>8}  {c['count2']:>8}  {c['pattern'][:50]}{is_err}")

    print()
    print("=" * 80)
    print(f"  下降最快的 {min(top_n, len(decreases))} 个模板（时间段2 vs 时间段1）")
    print("=" * 80)
    print(f"  {'变化率':>8}  {'增减':>6}  {'P1计数':>8}  {'P2计数':>8}  模板")
    print("-" * 80)
    for c in decreases[:top_n]:
        if c['diff'] >= 0:
            continue
        ratio_str = f"{c['ratio']*100:.0f}%" if c['ratio'] != float('inf') else "N/A"
        diff_str = f"+{c['diff']}" if c['diff'] >= 0 else str(c['diff'])
        is_err = " [ERR]" if c['template'] and c['template'].is_error() else ""
        print(f"  {ratio_str:>8}  {diff_str:>6}  {c['count1']:>8}  {c['count2']:>8}  {c['pattern'][:50]}{is_err}")
    print()


def _in_range(ts, start, end):
    if ts is None:
        return False
    from .parser import _naive_compare
    return _naive_compare(ts, start) >= 0 and _naive_compare(ts, end) <= 0


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

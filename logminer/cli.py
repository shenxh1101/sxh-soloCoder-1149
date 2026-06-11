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

    if args.sort == "count":
        filtered.sort(key=lambda t: t.count, reverse=True)
    else:
        filtered.sort(key=lambda t: t.template_id)

    print(f"{'ID':<10} {'Count':<10} {'Template'}")
    print("-" * 80)
    for t in filtered:
        whitelisted = " [WL]" if templater.is_whitelisted(t.pattern) else ""
        print(f"{t.template_id:<10} {t.count:<10} {t.pattern[:60]}{whitelisted}")


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


if __name__ == "__main__":
    main()

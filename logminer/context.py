from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .parser import LogEntry, _naive_compare
from .templater import Template
from .detector import AnomalyPoint


class ContextExtractor:
    def __init__(self, context_lines: int = 5):
        self.context_lines = context_lines

    def _format_ts(self, dt: Optional[datetime]) -> str:
        if dt is None:
            return "??:??:??"
        try:
            return dt.strftime("%H:%M:%S")
        except Exception:
            return str(dt)

    def extract(
        self,
        anomaly: AnomalyPoint,
        all_entries: List[LogEntry],
        template_entries: Dict[str, List[Tuple[LogEntry, Template]]]
    ) -> Dict:
        anomaly_time = anomaly.bucket_time
        window = timedelta(minutes=self.context_lines * 5)
        before_start = anomaly_time - window
        after_end = anomaly_time + window

        before_entries = []
        after_entries = []
        at_entries = []

        for entry in all_entries:
            if entry.timestamp is None:
                continue
            if _naive_compare(entry.timestamp, before_start) >= 0 and _naive_compare(entry.timestamp, anomaly_time) < 0:
                before_entries.append(entry)
            elif _naive_compare(entry.timestamp, anomaly_time) >= 0 and _naive_compare(entry.timestamp, after_end) < 0:
                after_entries.append(entry)

        tid = anomaly.template_id
        if tid in template_entries:
            for entry, _ in template_entries[tid]:
                if entry.timestamp:
                    diff = abs((entry.timestamp.replace(tzinfo=None) - anomaly_time.replace(tzinfo=None)).total_seconds())
                    if diff < 300:
                        at_entries.append(entry)

        return {
            "anomaly_time": anomaly_time,
            "before": before_entries[-self.context_lines:],
            "at": at_entries[:self.context_lines],
            "after": after_entries[:self.context_lines],
        }

    def format_context(self, ctx: Dict) -> str:
        lines = []
        anomaly_time_str = self._format_ts(ctx["anomaly_time"])
        lines.append(f"  === 上下文 around {anomaly_time_str} ===")
        lines.append("  [之前]")
        for e in ctx["before"]:
            ts = self._format_ts(e.timestamp)
            lines.append(f"    {ts} | {e.raw[:120]}")
        lines.append("  [异常时刻]")
        for e in ctx["at"]:
            ts = self._format_ts(e.timestamp)
            lines.append(f"    {ts} | {e.raw[:120]}")
        lines.append("  [之后]")
        for e in ctx["after"]:
            ts = self._format_ts(e.timestamp)
            lines.append(f"    {ts} | {e.raw[:120]}")
        return "\n".join(lines)

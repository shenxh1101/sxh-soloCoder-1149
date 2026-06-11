from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .parser import LogEntry
from .templater import Template
from .detector import AnomalyPoint


class ContextExtractor:
    def __init__(self, context_lines: int = 5):
        self.context_lines = context_lines

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
            if before_start <= entry.timestamp < anomaly_time:
                before_entries.append(entry)
            elif anomaly_time <= entry.timestamp < after_end:
                after_entries.append(entry)

        tid = anomaly.template_id
        if tid in template_entries:
            for entry, _ in template_entries[tid]:
                if entry.timestamp and abs((entry.timestamp - anomaly_time).total_seconds()) < 300:
                    at_entries.append(entry)

        return {
            "anomaly_time": anomaly_time,
            "before": before_entries[-self.context_lines:],
            "at": at_entries[:self.context_lines],
            "after": after_entries[:self.context_lines],
        }

    def format_context(self, ctx: Dict) -> str:
        lines = []
        lines.append(f"  === Context around {ctx['anomaly_time']} ===")
        lines.append("  [Before]")
        for e in ctx["before"]:
            ts = e.timestamp.strftime("%H:%M:%S") if e.timestamp else "??:??:??"
            lines.append(f"    {ts} | {e.raw[:120]}")
        lines.append("  [At anomaly point]")
        for e in ctx["at"]:
            ts = e.timestamp.strftime("%H:%M:%S") if e.timestamp else "??:??:??"
            lines.append(f"    {ts} | {e.raw[:120]}")
        lines.append("  [After]")
        for e in ctx["after"]:
            ts = e.timestamp.strftime("%H:%M:%S") if e.timestamp else "??:??:??"
            lines.append(f"    {ts} | {e.raw[:120]}")
        return "\n".join(lines)

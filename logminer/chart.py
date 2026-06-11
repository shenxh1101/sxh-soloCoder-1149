from datetime import datetime
from typing import Dict, List, Optional


class ASCIITrendChart:
    def __init__(self, width: int = 60, height: int = 15):
        self.width = width
        self.height = height

    def render(
        self,
        series: Dict[datetime, int],
        title: str = "Frequency Trend",
        show_labels: bool = True,
    ) -> str:
        if not series:
            return "  (no data)"

        sorted_times = sorted(series.keys())
        values = [series[t] for t in sorted_times]

        max_val = max(values) if values else 1
        if max_val == 0:
            max_val = 1

        if len(values) > self.width:
            step = len(values) / self.width
            sampled = []
            sampled_times = []
            for i in range(self.width):
                start_idx = int(i * step)
                end_idx = int((i + 1) * step)
                chunk = values[start_idx:end_idx]
                sampled.append(sum(chunk) / len(chunk) if chunk else 0)
                sampled_times.append(sorted_times[start_idx])
            values = sampled
            sorted_times = sampled_times
        elif len(values) < self.width:
            padded = [0.0] * self.width
            times_padded = [None] * self.width
            offset = (self.width - len(values)) // 2
            for i, v in enumerate(values):
                padded[offset + i] = v
                times_padded[offset + i] = sorted_times[i]
            values = padded
            sorted_times = times_padded

        rows = []
        rows.append(f"  {title}")
        rows.append(f"  {'+' + '-' * self.width + '+'}")

        for row in range(self.height, 0, -1):
            threshold = (row / self.height) * max_val
            line = "  |"
            for v in values:
                if v >= threshold:
                    line += "█"
                elif v >= threshold - (max_val / self.height) * 0.3:
                    line += "▄"
                else:
                    line += " "
            line += "|"
            if row == self.height:
                line += f" {max_val}"
            elif row == 1:
                line += " 0"
            elif row == self.height // 2:
                line += f" {max_val / 2:.0f}"
            rows.append(line)

        rows.append(f"  {'+' + '-' * self.width + '+'}")

        if show_labels and sorted_times:
            valid_times = [t for t in sorted_times if t is not None]
            if valid_times:
                first = valid_times[0]
                last = valid_times[-1]
                time_label = f"  {first.strftime('%m-%d %H:%M')}{' ' * (self.width - 26)}{last.strftime('%m-%d %H:%M')}"
                rows.append(time_label[: self.width + 4])

        return "\n".join(rows)

    def render_multi(
        self,
        all_series: Dict[str, Dict[datetime, int]],
        top_n: int = 5,
    ) -> str:
        sorted_series = sorted(all_series.items(), key=lambda x: sum(x[1].values()), reverse=True)
        charts = []
        for tid, series in sorted_series[:top_n]:
            title = f"Template {tid} Frequency"
            charts.append(self.render(series, title=title))
        return "\n\n".join(charts)

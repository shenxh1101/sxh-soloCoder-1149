import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .parser import LogEntry
from .templater import Template


@dataclass
class TimeBucket:
    start: datetime
    end: datetime
    count: int = 0


@dataclass
class AnomalyPoint:
    template_id: str
    template: Template
    bucket_time: datetime
    observed: int
    expected: float
    score: float
    direction: str  # "spike" or "drop"


class AnomalyDetector:
    def __init__(self, window_size: int = 5, threshold: float = 2.0,
                 method: str = "zscore", min_count: int = 3,
                 bucket_minutes: int = 5):
        self.window_size = window_size
        self.threshold = threshold
        self.method = method
        self.min_count = min_count
        self.bucket_minutes = bucket_minutes

    def _bucket_key(self, dt: datetime) -> datetime:
        truncated = dt.replace(minute=(dt.minute // self.bucket_minutes) * self.bucket_minutes,
                               second=0, microsecond=0)
        return truncated

    def build_time_series(self, entries: List[LogEntry]) -> Dict[datetime, int]:
        series: Dict[datetime, int] = {}
        for entry in entries:
            if entry.timestamp is None:
                continue
            key = self._bucket_key(entry.timestamp)
            series[key] = series.get(key, 0) + 1
        return series

    def build_template_time_series(
        self,
        template_entries: List[Tuple[LogEntry, Template]]
    ) -> Dict[datetime, int]:
        series: Dict[datetime, int] = {}
        for entry, _ in template_entries:
            if entry.timestamp is None:
                continue
            key = self._bucket_key(entry.timestamp)
            series[key] = series.get(key, 0) + 1
        return series

    def _fill_missing_buckets(self, series: Dict[datetime, int]) -> Dict[datetime, int]:
        if not series:
            return series
        sorted_keys = sorted(series.keys())
        filled = dict(series)
        current = sorted_keys[0]
        end = sorted_keys[-1]
        delta = timedelta(minutes=self.bucket_minutes)
        while current <= end:
            if current not in filled:
                filled[current] = 0
            current += delta
        return filled

    def _zscore_detect(self, values: List[float], times: List[datetime]) -> List[Tuple[int, float, float]]:
        anomalies = []
        for i in range(self.window_size, len(values)):
            window = values[i - self.window_size:i]
            if len(window) < self.min_count and max(window) == 0:
                continue
            mean = sum(window) / len(window)
            variance = sum((x - mean) ** 2 for x in window) / len(window)
            std = math.sqrt(variance) if variance > 0 else 1.0
            if std == 0:
                if values[i] > mean:
                    anomalies.append((i, values[i], float('inf')))
                continue
            z = (values[i] - mean) / std
            if abs(z) >= self.threshold:
                anomalies.append((i, values[i], z))
        return anomalies

    def _diff_detect(self, values: List[float], times: List[datetime]) -> List[Tuple[int, float, float]]:
        anomalies = []
        for i in range(1, len(values)):
            prev = values[i - 1] if values[i - 1] > 0 else 1.0
            diff_ratio = (values[i] - prev) / prev
            if abs(diff_ratio) >= self.threshold:
                anomalies.append((i, values[i], diff_ratio))
        return anomalies

    def detect(self, series: Dict[datetime, int]) -> List[AnomalyPoint]:
        filled = self._fill_missing_buckets(series)
        if not filled:
            return []

        sorted_times = sorted(filled.keys())
        values = [float(filled[t]) for t in sorted_times]

        if self.method == "zscore":
            raw_anomalies = self._zscore_detect(values, sorted_times)
        elif self.method == "diff":
            raw_anomalies = self._diff_detect(values, sorted_times)
        else:
            raw_anomalies = self._zscore_detect(values, sorted_times)

        results = []
        for idx, observed, score in raw_anomalies:
            window = values[max(0, idx - self.window_size):idx]
            expected = sum(window) / len(window) if window else 0.0
            direction = "spike" if observed > expected else "drop"
            results.append(AnomalyPoint(
                template_id="",
                template=None,
                bucket_time=sorted_times[idx],
                observed=int(observed),
                expected=expected,
                score=score,
                direction=direction,
            ))
        return results

    def detect_template_anomalies(
        self,
        template_series: Dict[str, Dict[datetime, int]],
        templates: Dict[str, Template]
    ) -> List[AnomalyPoint]:
        all_anomalies = []
        for tid, series in template_series.items():
            if tid not in templates:
                continue
            tmpl = templates[tid]
            anomalies = self.detect(series)
            for a in anomalies:
                a.template_id = tid
                a.template = tmpl
                all_anomalies.append(a)
        return sorted(all_anomalies, key=lambda x: abs(x.score), reverse=True)

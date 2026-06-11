import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .config import AppConfig, LogFormat, BUILTIN_FORMATS


STATUS_CLASSES = {
    "1xx": "info",
    "2xx": "success",
    "3xx": "redirect",
    "4xx": "client_error",
    "5xx": "server_error",
}


@dataclass
class LogEntry:
    raw: str
    line_number: int
    timestamp: Optional[datetime] = None
    fields: Dict[str, str] = field(default_factory=dict)
    format_name: str = ""
    message: str = ""
    status_code: Optional[str] = None
    status_class: Optional[str] = None
    level: Optional[str] = None

    def is_error(self) -> bool:
        if self.status_class in ("client_error", "server_error"):
            return True
        if self.level and self.level.upper() in ("ERROR", "FATAL", "CRITICAL"):
            return True
        return False


class LogParser:
    def __init__(self, config: AppConfig):
        self.config = config
        self.formats: List[LogFormat] = config.log_formats or list(BUILTIN_FORMATS.values())
        self._syslog_year = None

    def _try_parse(self, line: str, fmt: LogFormat) -> Optional[Dict[str, str]]:
        if not fmt.compiled:
            return None
        m = fmt.compiled.match(line)
        if m:
            return m.groupdict()
        return None

    def _classify_status(self, status: Optional[str]) -> Optional[str]:
        if not status or not status.isdigit():
            return None
        if len(status) == 3:
            return status[0] + "xx"
        return None

    def _parse_timestamp(self, raw_ts: str, fmt: LogFormat,
                         default_year: Optional[int] = None) -> Optional[datetime]:
        if not raw_ts:
            return None
        ts_str = raw_ts.strip("[]")
        ts_formats = [fmt.timestamp_format]
        common_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
            "%Y%m%d %H%M%S",
            "%Y-%m-%d %H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S%z",
        ]
        all_formats = ts_formats + common_formats

        for tf in all_formats:
            try:
                dt = datetime.strptime(ts_str, tf)
                if dt.year == 1900 and default_year:
                    dt = dt.replace(year=default_year)
                return dt
            except (ValueError, TypeError):
                continue

        if default_year:
            for tf in all_formats:
                try:
                    test_str = f"{default_year} {ts_str}"
                    dt = datetime.strptime(test_str, f"%Y {tf}")
                    return dt
                except (ValueError, TypeError):
                    continue
        return None

    def _guess_year(self, entries: List[LogEntry]) -> Optional[int]:
        from datetime import date
        for e in entries:
            if e.timestamp and e.timestamp.year > 1900:
                return e.timestamp.year
        return date.today().year

    def _post_process_syslog_year(self, entries: List[LogEntry], year: int):
        for entry in entries:
            if entry.timestamp and entry.timestamp.year == 1900:
                entry.timestamp = entry.timestamp.replace(year=year)

    def parse_line(self, line: str, line_number: int = 0,
                   default_year: Optional[int] = None) -> LogEntry:
        entry = LogEntry(raw=line, line_number=line_number)

        for fmt in self.formats:
            fields = self._try_parse(line, fmt)
            if fields:
                entry.fields = fields
                entry.format_name = fmt.name
                raw_ts = fields.get(fmt.timestamp_field, "")
                entry.timestamp = self._parse_timestamp(raw_ts, fmt, default_year)
                entry.message = fields.get("message", fields.get("request", line))
                entry.status_code = fields.get("status") or fields.get("status_code")
                entry.status_class = self._classify_status(entry.status_code)
                entry.level = fields.get("level")
                return entry

        entry.message = line
        return entry

    def parse_file(self, filepath: str,
                   time_start: Optional[datetime] = None,
                   time_end: Optional[datetime] = None) -> List[LogEntry]:
        entries = []
        first_pass_entries = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                line = line.rstrip("\n\r")
                if not line.strip():
                    continue
                entry = self.parse_line(line, i)
                first_pass_entries.append(entry)

        guessed_year = self._guess_year(first_pass_entries)
        if guessed_year:
            self._post_process_syslog_year(first_pass_entries, guessed_year)

        for entry in first_pass_entries:
            if time_start and entry.timestamp:
                if _naive_compare(entry.timestamp, time_start) < 0:
                    continue
            if time_end and entry.timestamp:
                if _naive_compare(entry.timestamp, time_end) > 0:
                    continue
            entries.append(entry)

        return entries

    def parse_lines(self, lines: List[str]) -> List[LogEntry]:
        entries = []
        first_pass = []
        for i, line in enumerate(lines, 1):
            line = line.rstrip("\n\r")
            if not line.strip():
                continue
            first_pass.append(self.parse_line(line, i))

        guessed_year = self._guess_year(first_pass)
        if guessed_year:
            self._post_process_syslog_year(first_pass, guessed_year)
        return first_pass


def _naive_compare(dt1: datetime, dt2: datetime) -> int:
    d1 = dt1.replace(tzinfo=None) if dt1.tzinfo else dt1
    d2 = dt2.replace(tzinfo=None) if dt2.tzinfo else dt2
    if d1 < d2:
        return -1
    elif d1 > d2:
        return 1
    return 0

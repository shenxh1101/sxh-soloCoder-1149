import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .config import AppConfig, LogFormat, BUILTIN_FORMATS


@dataclass
class LogEntry:
    raw: str
    line_number: int
    timestamp: Optional[datetime] = None
    fields: Dict[str, str] = field(default_factory=dict)
    format_name: str = ""
    message: str = ""


class LogParser:
    def __init__(self, config: AppConfig):
        self.config = config
        self.formats: List[LogFormat] = config.log_formats or list(BUILTIN_FORMATS.values())

    def _try_parse(self, line: str, fmt: LogFormat) -> Optional[Dict[str, str]]:
        if not fmt.compiled:
            return None
        m = fmt.compiled.match(line)
        if m:
            return m.groupdict()
        return None

    def _parse_timestamp(self, raw_ts: str, fmt: LogFormat) -> Optional[datetime]:
        if not raw_ts:
            return None
        ts_formats = [fmt.timestamp_format]
        common_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S %z",
            "[%d/%b/%Y:%H:%M:%S %z]",
            "%b %d %H:%M:%S",
            "%Y%m%d %H:%M:%S",
        ]
        for tf in ts_formats + common_formats:
            try:
                return datetime.strptime(raw_ts.strip("[]"), tf)
            except (ValueError, TypeError):
                continue
        return None

    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        entry = LogEntry(raw=line, line_number=line_number)

        for fmt in self.formats:
            fields = self._try_parse(line, fmt)
            if fields:
                entry.fields = fields
                entry.format_name = fmt.name
                raw_ts = fields.get(fmt.timestamp_field, "")
                entry.timestamp = self._parse_timestamp(raw_ts, fmt)
                entry.message = fields.get("message", fields.get("request", line))
                return entry

        entry.message = line
        return entry

    def parse_file(self, filepath: str,
                   time_start: Optional[datetime] = None,
                   time_end: Optional[datetime] = None) -> List[LogEntry]:
        entries = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                line = line.rstrip("\n\r")
                if not line.strip():
                    continue
                entry = self.parse_line(line, i)
                if time_start and entry.timestamp and entry.timestamp < time_start:
                    continue
                if time_end and entry.timestamp and entry.timestamp > time_end:
                    continue
                entries.append(entry)
        return entries

    def parse_lines(self, lines: List[str]) -> List[LogEntry]:
        entries = []
        for i, line in enumerate(lines, 1):
            line = line.rstrip("\n\r")
            if not line.strip():
                continue
            entries.append(self.parse_line(line, i))
        return entries

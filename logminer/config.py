import yaml
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern


@dataclass
class FieldRule:
    name: str
    pattern: str
    compiled: Optional[Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        if self.pattern:
            self.compiled = re.compile(self.pattern)


@dataclass
class LogFormat:
    name: str
    pattern: str
    compiled: Optional[Pattern] = field(default=None, repr=False)
    timestamp_field: str = "timestamp"
    timestamp_format: str = "%d/%b/%Y:%H:%M:%S %z"
    fields: List[FieldRule] = field(default_factory=list)

    def __post_init__(self):
        if self.pattern:
            self.compiled = re.compile(self.pattern)
        for f in self.fields:
            if isinstance(f, dict):
                f = FieldRule(**f)
            if f.pattern and not f.compiled:
                f.compiled = re.compile(f.pattern)


@dataclass
class AnomalyConfig:
    window_size: int = 5
    threshold: float = 2.0
    method: str = "zscore"
    min_count: int = 3


@dataclass
class AppConfig:
    log_formats: List[LogFormat] = field(default_factory=list)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    whitelist_templates: List[str] = field(default_factory=list)
    whitelist_patterns: List[Pattern] = field(default_factory=list)
    context_lines: int = 5
    time_bucket_minutes: int = 5
    template_placeholders: Dict[str, str] = field(default_factory=dict)


DEFAULT_PLACEHOLDERS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "timestamp": r"\b\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
    "http_timestamp": r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]",
    "number_with_unit": r"\b\d+(?:\.\d+)?(?:ms|s|KB|MB|GB|TB|KB|kb|mb|gb|tb|B|bps|K|M|G|Hz|kHz|MHz|GHz)\b",
    "hex": r"\b0[xX][0-9a-fA-F]+\b",
    "uuid": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "filepath": r"(?:/[\w\-\.]+)+",
    "url": r"https?://\S+",
    "email": r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
    "number": r"\b\d+(?:\.\d+)?\b",
    "pid": r"\[\d+\]",
}


BUILTIN_FORMATS = {
    "apache_combined": LogFormat(
        name="apache_combined",
        pattern=r'^(?P<remote_host>\S+)\s+(?P<ident>\S+)\s+(?P<remote_user>\S+)\s+(?P<timestamp>\[.+?\])\s+"(?P<request>.+?)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
                r'(?:\s+"(?P<referer>.+?)"\s+"(?P<user_agent>.+?)")?',
        timestamp_field="timestamp",
        timestamp_format="[%d/%b/%Y:%H:%M:%S %z]",
    ),
    "nginx_combined": LogFormat(
        name="nginx_combined",
        pattern=r'^(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+(?P<timestamp>\[.+?\])\s+"(?P<request>.+?)"\s+(?P<status>\d{3})\s+(?P<body_bytes_sent>\S+)'
                r'\s+"(?P<http_referer>.+?)"\s+"(?P<http_user_agent>.+?)"',
        timestamp_field="timestamp",
        timestamp_format="[%d/%b/%Y:%H:%M:%S %z]",
    ),
    "syslog": LogFormat(
        name="syslog",
        pattern=r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$',
        timestamp_field="timestamp",
        timestamp_format="%b %d %H:%M:%S",
    ),
    "application": LogFormat(
        name="application",
        pattern=r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(?:\[?(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\]?)?\s*(?::?\s*(?P<logger>\S+))?\s*(?::?\s*(?P<message>.*))?$',
        timestamp_field="timestamp",
        timestamp_format="%Y-%m-%d %H:%M:%S",
    ),
}


def _parse_log_format(data: dict) -> LogFormat:
    fields = []
    for f in data.get("fields", []):
        if isinstance(f, dict):
            fields.append(FieldRule(name=f.get("name", ""), pattern=f.get("pattern", "")))
        else:
            fields.append(FieldRule(name=str(f), pattern=""))
    lf = LogFormat(
        name=data.get("name", "custom"),
        pattern=data.get("pattern", ""),
        timestamp_field=data.get("timestamp_field", "timestamp"),
        timestamp_format=data.get("timestamp_format", "%Y-%m-%d %H:%M:%S"),
        fields=fields,
    )
    return lf


def load_config(config_path: str) -> AppConfig:
    cfg = AppConfig()
    if not os.path.exists(config_path):
        return cfg

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    for fmt_data in data.get("log_formats", []):
        lf = _parse_log_format(fmt_data)
        cfg.log_formats.append(lf)

    anomaly_data = data.get("anomaly", {})
    cfg.anomaly = AnomalyConfig(
        window_size=anomaly_data.get("window_size", 5),
        threshold=anomaly_data.get("threshold", 2.0),
        method=anomaly_data.get("method", "zscore"),
        min_count=anomaly_data.get("min_count", 3),
    )

    cfg.whitelist_templates = data.get("whitelist_templates", [])
    cfg.whitelist_patterns = [
        re.compile(p) for p in data.get("whitelist_patterns", [])
    ]

    cfg.context_lines = data.get("context_lines", 5)
    cfg.time_bucket_minutes = data.get("time_bucket_minutes", 5)

    custom_placeholders = data.get("template_placeholders", {})
    cfg.template_placeholders = {**DEFAULT_PLACEHOLDERS, **custom_placeholders}

    return cfg


def get_default_config() -> AppConfig:
    cfg = AppConfig()
    cfg.log_formats = list(BUILTIN_FORMATS.values())
    cfg.template_placeholders = dict(DEFAULT_PLACEHOLDERS)
    return cfg

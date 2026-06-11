import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

from .config import AppConfig, DEFAULT_PLACEHOLDERS
from .parser import LogEntry


@dataclass
class Template:
    template_id: str
    pattern: str
    placeholder_map: Dict[str, str] = field(default_factory=dict)
    regex: str = ""
    count: int = 0
    status_code: Optional[str] = None
    status_class: Optional[str] = None
    level: Optional[str] = None

    def is_error(self) -> bool:
        if self.status_class in ("4xx", "5xx"):
            return True
        if self.level and self.level.upper() in ("ERROR", "FATAL", "CRITICAL"):
            return True
        return False


class LogTemplater:
    def __init__(self, config: AppConfig):
        self.config = config
        placeholders = config.template_placeholders or dict(DEFAULT_PLACEHOLDERS)
        self.placeholder_patterns: List[Tuple[str, re.Pattern]] = []
        order = [
            "url", "email", "ipv6", "ipv4", "http_timestamp", "timestamp",
            "uuid", "hex", "filepath", "number_with_unit", "pid", "number",
        ]
        for key in order:
            if key in placeholders:
                try:
                    self.placeholder_patterns.append(
                        (key, re.compile(placeholders[key]))
                    )
                except re.error:
                    pass
        for key, pat in placeholders.items():
            if key not in order:
                try:
                    self.placeholder_patterns.append(
                        (key, re.compile(pat))
                    )
                except re.error:
                    pass

        self._cache: Dict[str, Tuple[str, Dict[str, str]]] = {}
        self._template_counter = 0
        self._template_registry: Dict[str, Template] = {}

    def _template_text(self, text: str) -> Tuple[str, Dict[str, str]]:
        replacements: Dict[str, str] = {}
        for placeholder_name, pattern in self.placeholder_patterns:
            matches = list(pattern.finditer(text))
            for m in reversed(matches):
                original = m.group()
                if original not in replacements:
                    replacements[original] = placeholder_name
                text = text[:m.start()] + f"<{placeholder_name}>" + text[m.end():]
        return text, replacements

    def template_line(self, entry: LogEntry) -> Tuple[str, Dict[str, str]]:
        cache_key = f"{entry.format_name}:{entry.status_code or ''}:{entry.raw}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if entry.format_name in ("apache_combined", "nginx_combined") and entry.status_code:
            request = entry.fields.get("request", entry.message)
            templated_req, replacements = self._template_text(request)
            template_str = f"{templated_req} [{entry.status_code}]"
        elif entry.format_name == "application" and entry.level:
            msg = entry.message
            templated_msg, replacements = self._template_text(msg)
            template_str = f"[{entry.level}] {templated_msg}"
        else:
            text = entry.message if entry.message else entry.raw
            template_str, replacements = self._template_text(text)

        self._cache[cache_key] = (template_str, replacements)
        return template_str, replacements

    def _build_regex(self, template_str: str) -> str:
        regex = re.escape(template_str)
        placeholder_names = [pn for pn, _ in self.placeholder_patterns]

        counts: Dict[str, int] = {}
        for pn in placeholder_names:
            tag = re.escape(f"<{pn}>")
            count = 0
            pos = 0
            while True:
                idx = regex.find(tag, pos)
                if idx == -1:
                    break
                count += 1
                pos = idx + len(tag)
            counts[pn] = count

        for pn in placeholder_names:
            count = counts.get(pn, 0)
            if count <= 0:
                continue
            if count == 1:
                tag = re.escape(f"<{pn}>")
                regex = regex.replace(tag, f"(?P<{pn}>\\S+)")
            else:
                tag = re.escape(f"<{pn}>")
                parts = regex.split(tag)
                rebuilt = parts[0]
                for i in range(1, len(parts)):
                    rebuilt += f"(?P<{pn}_{i}>\\S+)" + parts[i]
                regex = rebuilt

        try:
            re.compile(regex)
        except re.error:
            cleaned = re.sub(r"\(\?P<[\w_]+>", "(?:", regex)
            try:
                re.compile(cleaned)
                regex = cleaned
            except re.error:
                pass
        return regex

    def get_or_create_template(self, template_str: str, replacements: Dict[str, str],
                               entry: Optional[LogEntry] = None) -> Template:
        if template_str in self._template_registry:
            return self._template_registry[template_str]

        self._template_counter += 1
        tid = f"T{self._template_counter:04d}"
        regex = self._build_regex(template_str)
        tmpl = Template(
            template_id=tid,
            pattern=template_str,
            placeholder_map=replacements,
            regex=regex,
            status_code=entry.status_code if entry else None,
            status_class=entry.status_class if entry else None,
            level=entry.level if entry else None,
        )
        self._template_registry[template_str] = tmpl
        return tmpl

    def process_entries(self, entries: List[LogEntry]) -> Dict[str, List[Tuple[LogEntry, Template]]]:
        results: Dict[str, List[Tuple[LogEntry, Template]]] = {}
        for entry in entries:
            template_str, replacements = self.template_line(entry)
            tmpl = self.get_or_create_template(template_str, replacements, entry)
            tmpl.count += 1
            if tmpl.template_id not in results:
                results[tmpl.template_id] = []
            results[tmpl.template_id].append((entry, tmpl))
        return results

    def get_all_templates(self) -> List[Template]:
        return list(self._template_registry.values())

    def is_whitelisted(self, template_str: str) -> bool:
        for wt in self.config.whitelist_templates:
            if template_str == wt or template_str.strip() == wt.strip():
                return True
        for wp in self.config.whitelist_patterns:
            if wp.search(template_str):
                return True
        return False

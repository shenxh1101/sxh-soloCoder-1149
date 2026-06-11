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

    def template_line(self, entry: LogEntry) -> Tuple[str, Dict[str, str]]:
        if entry.raw in self._cache:
            return self._cache[entry.raw]

        text = entry.message if entry.message else entry.raw
        replacements: Dict[str, str] = {}

        for placeholder_name, pattern in self.placeholder_patterns:
            matches = list(pattern.finditer(text))
            for m in reversed(matches):
                original = m.group()
                if original not in replacements:
                    replacements[original] = placeholder_name
                text = text[:m.start()] + f"<{placeholder_name}>" + text[m.end():]

        result = (text, replacements)
        self._cache[entry.raw] = result
        return result

    def _build_regex(self, template_str: str) -> str:
        regex = re.escape(template_str)

        for placeholder_name in {pn for pn, _ in self.placeholder_patterns}:
            tag = re.escape(f"<{placeholder_name}>")
            regex = regex.replace(tag, f"(?P<{placeholder_name}>\\S+)")
        return regex

    def get_or_create_template(self, template_str: str, replacements: Dict[str, str]) -> Template:
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
        )
        self._template_registry[template_str] = tmpl
        return tmpl

    def process_entries(self, entries: List[LogEntry]) -> Dict[str, List[Tuple[LogEntry, Template]]]:
        results: Dict[str, List[Tuple[LogEntry, Template]]] = {}
        for entry in entries:
            template_str, replacements = self.template_line(entry)
            tmpl = self.get_or_create_template(template_str, replacements)
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

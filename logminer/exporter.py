import json
import re
from typing import Dict, List

from .templater import Template


class RegexExporter:
    def export_rules(
        self,
        templates: List[Template],
        output_format: str = "json",
        include_counts: bool = True,
    ) -> str:
        if output_format == "json":
            return self._export_json(templates, include_counts)
        elif output_format == "yaml":
            return self._export_yaml(templates, include_counts)
        elif output_format == "plain":
            return self._export_plain(templates, include_counts)
        else:
            return self._export_json(templates, include_counts)

    def _export_json(self, templates: List[Template], include_counts: bool) -> str:
        rules = []
        for tmpl in templates:
            rule = {
                "id": tmpl.template_id,
                "pattern": tmpl.pattern,
                "regex": tmpl.regex,
            }
            if include_counts:
                rule["count"] = tmpl.count
            rules.append(rule)
        return json.dumps({"rules": rules}, indent=2, ensure_ascii=False)

    def _export_yaml(self, templates: List[Template], include_counts: bool) -> str:
        lines = ["rules:"]
        for tmpl in templates:
            lines.append(f"  - id: {tmpl.template_id}")
            lines.append(f'    pattern: "{tmpl.pattern}"')
            lines.append(f'    regex: "{tmpl.regex}"')
            if include_counts:
                lines.append(f"    count: {tmpl.count}")
        return "\n".join(lines)

    def _export_plain(self, templates: List[Template], include_counts: bool) -> str:
        lines = []
        for tmpl in templates:
            count_str = f" (count={tmpl.count})" if include_counts else ""
            lines.append(f"# Template {tmpl.template_id}{count_str}")
            lines.append(f"# Original: {tmpl.pattern}")
            lines.append(f"{tmpl.regex}")
            lines.append("")
        return "\n".join(lines)

    def save_to_file(self, templates: List[Template], filepath: str,
                     output_format: str = "json", include_counts: bool = True):
        content = self.export_rules(templates, output_format, include_counts)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

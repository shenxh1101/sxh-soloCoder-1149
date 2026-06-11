import json
import re
import yaml
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

    def _to_dict(self, tmpl: Template, include_counts: bool) -> dict:
        d = {
            "id": tmpl.template_id,
            "pattern": tmpl.pattern,
            "regex": tmpl.regex,
        }
        if tmpl.status_code:
            d["status_code"] = tmpl.status_code
        if tmpl.status_class:
            d["status_class"] = tmpl.status_class
        if tmpl.level:
            d["level"] = tmpl.level
        if include_counts:
            d["count"] = tmpl.count
        return d

    def _export_json(self, templates: List[Template], include_counts: bool) -> str:
        rules = [self._to_dict(t, include_counts) for t in templates]
        return json.dumps({"rules": rules}, indent=2, ensure_ascii=False)

    def _export_yaml(self, templates: List[Template], include_counts: bool) -> str:
        rules = [self._to_dict(t, include_counts) for t in templates]
        return yaml.dump({"rules": rules}, default_flow_style=False,
                         allow_unicode=True, sort_keys=False)

    def _export_plain(self, templates: List[Template], include_counts: bool) -> str:
        lines = []
        for tmpl in templates:
            count_str = f" (count={tmpl.count})" if include_counts else ""
            extra = []
            if tmpl.status_code:
                extra.append(f"status={tmpl.status_code}")
            if tmpl.level:
                extra.append(f"level={tmpl.level}")
            extra_str = f" [{', '.join(extra)}]" if extra else ""
            lines.append(f"# Template {tmpl.template_id}{count_str}{extra_str}")
            lines.append(f"# Pattern: {tmpl.pattern}")
            lines.append(tmpl.regex)
            lines.append("")
        return "\n".join(lines)

    def save_to_file(self, templates: List[Template], filepath: str,
                     output_format: str = "json", include_counts: bool = True):
        content = self.export_rules(templates, output_format, include_counts)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def load_from_file(self, filepath: str) -> List[dict]:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        if filepath.endswith(".json"):
            data = json.loads(content)
            return data.get("rules", [])
        elif filepath.endswith(".yaml") or filepath.endswith(".yml"):
            data = yaml.safe_load(content)
            return data.get("rules", [])
        else:
            rules = []
            current = None
            for line in content.split("\n"):
                if line.startswith("# Template "):
                    if current:
                        rules.append(current)
                    tid = line.split("# Template ")[1].split(" ")[0]
                    current = {"id": tid, "pattern": "", "regex": ""}
                elif line.startswith("# Pattern: "):
                    if current:
                        current["pattern"] = line[len("# Pattern: "):]
                elif line.strip() and not line.startswith("#") and current:
                    current["regex"] = line.strip()
            if current and current["regex"]:
                rules.append(current)
            return rules

    def validate_regex(self, rules: List[dict]) -> List[str]:
        errors = []
        for r in rules:
            try:
                re.compile(r.get("regex", ""))
            except re.error as e:
                errors.append(f"{r.get('id', '?')}: {e}")
        return errors

import re
import json
import yaml
from logminer.config import get_default_config
from logminer.parser import LogParser
from logminer.templater import LogTemplater
from logminer.exporter import RegexExporter

config = get_default_config()
parser = LogParser(config)
entries = parser.parse_file('sample_access.log')
templater = LogTemplater(config)
templater.process_entries(entries)
all_t = templater.get_all_templates()

print('=== 测试正则编译 ===')
failed = 0
for t in all_t:
    try:
        re.compile(t.regex)
    except re.error as e:
        print(f'  失败: {t.template_id}: {e}')
        print(f'    pattern: {t.pattern[:80]}')
        print(f'    regex: {t.regex[:120]}')
        failed += 1
print(f'  总计 {len(all_t)} 个模板，失败 {failed} 个')

print()
print('=== 测试多占位符模板 ===')
multi = [t for t in all_t if t.pattern.count('<') >= 3]
if multi:
    for t in multi[:3]:
        print(f'  {t.template_id}: {t.pattern[:80]}')
        print(f'    regex: {t.regex[:100]}')
        try:
            re.compile(t.regex)
            print('    编译: OK')
        except re.error as e:
            print(f'    编译: FAIL - {e}')

print()
print('=== 测试JSON导出再读取 ===')
exporter = RegexExporter()
json_str = exporter.export_rules(all_t[:10], output_format='json')
data = json.loads(json_str)
print(f'  JSON 读写成功，共 {len(data["rules"])} 条规则')
compile_ok = True
for r in data['rules']:
    try:
        re.compile(r['regex'])
    except re.error as e:
        print(f'  编译失败: {r["id"]}: {e}')
        compile_ok = False
if compile_ok:
    print('  所有规则编译通过')

print()
print('=== 测试YAML导出再读取 ===')
yaml_str = exporter.export_rules(all_t[:10], output_format='yaml')
data = yaml.safe_load(yaml_str)
print(f'  YAML 读写成功，共 {len(data["rules"])} 条规则')
compile_ok = True
for r in data['rules']:
    try:
        re.compile(r['regex'])
    except re.error as e:
        print(f'  编译失败: {r["id"]}: {e}')
        compile_ok = False
if compile_ok:
    print('  所有规则编译通过')

print()
print('=== 测试Plain导出 ===')
plain_str = exporter.export_rules(all_t[:5], output_format='plain')
print(plain_str[:500])

print()
print('=== 测试应用日志模板 ===')
entries2 = parser.parse_file('sample_app.log')
templater2 = LogTemplater(config)
templater2.process_entries(entries2)
all_t2 = templater2.get_all_templates()
failed2 = 0
for t in all_t2:
    try:
        re.compile(t.regex)
    except re.error as e:
        print(f'  失败: {t.template_id}: {e}')
        print(f'    pattern: {t.pattern[:80]}')
        failed2 += 1
print(f'  应用日志 {len(all_t2)} 个模板，失败 {failed2} 个')

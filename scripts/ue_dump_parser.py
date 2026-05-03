import re
from dataclasses import dataclass, field


ENTRY_RE = re.compile(r'^\[([0-9A-Fa-f]+)\]\s+\{0x[0-9A-Fa-f]+\}\s+(.+)$')


@dataclass
class DumpProperty:
    offset: int
    kind: str
    name: str


@dataclass
class DumpObject:
    index: int
    text: str
    short_name: str
    properties: list[DumpProperty] = field(default_factory=list)


class DumpIndex:
    def __init__(self):
        self.by_index = {}
        self.by_short_name = {}
        self.by_text = {}

    def add_object(self, obj):
        self.by_index[obj.index] = obj
        self.by_short_name.setdefault(obj.short_name, []).append(obj)
        self.by_text[obj.text] = obj

    def find_one(self, short_name):
        if short_name in self.by_text:
            return self.by_text[short_name]
        matches = self.by_short_name.get(short_name, [])
        if not matches:
            return None
        with_properties = [obj for obj in matches if obj.properties]
        return with_properties[0] if with_properties else matches[0]


def load_dump(path):
    result = DumpIndex()
    current = None
    with open(path, 'r', encoding='utf-8', errors='replace') as handle:
        for raw_line in handle:
            line = raw_line.rstrip('\r\n')
            entry_match = ENTRY_RE.match(line)
            if not entry_match:
                current = None
                continue

            entry_value = int(entry_match.group(1), 16)
            text = entry_match.group(2).strip()
            tokens = text.split()
            if not tokens:
                current = None
                continue

            if tokens[0].endswith('Property') and current is not None:
                prop_kind = tokens[0]
                prop_name = tokens[-1]
                current.properties.append(DumpProperty(entry_value, prop_kind, prop_name))
                continue

            if tokens[0] in {'Class', 'ScriptStruct', 'Enum', 'Package', 'Function'}:
                index = entry_value
                short_name = text.split()[-1].split('.')[-1]
                current = DumpObject(index, text, short_name)
                result.add_object(current)
                continue

            current = None
    return result

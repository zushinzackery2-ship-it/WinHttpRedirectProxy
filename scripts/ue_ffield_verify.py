import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from ipc_client import IpcClient
from ue_dump_parser import load_dump
from ue_object_array import ObjectArray, read_exact, u32, u64, valid_ptr


class FFieldVerifier:
    def __init__(self, ipc, objects, dump_index):
        self.ipc = ipc
        self.objects = objects
        self.dump_index = dump_index
        self.child_offsets = list(range(0x48, 0x90, 8))
        self.name_offsets = list(range(0x08, 0x40, 4))
        self.next_offset = 0x18
        self.field_size = 0x80

    def read_field(self, address):
        data = read_exact(self.ipc, address, self.field_size)
        if not data:
            return None
        class_ptr = u64(data, 0x08)
        if not valid_ptr(class_ptr):
            return None
        return data

    def walk_chain(self, first, limit):
        fields = []
        current = first
        seen = set()
        for _ in range(limit):
            if not valid_ptr(current) or current in seen:
                break
            data = self.read_field(current)
            if not data:
                break
            fields.append((current, data))
            seen.add(current)
            current = u64(data, self.next_offset)
        return fields

    def score_child_offset(self, object_address, expected_count):
        best = None
        for offset in self.child_offsets:
            data = read_exact(self.ipc, object_address + offset, 8)
            if not data:
                continue
            first = u64(data, 0)
            fields = self.walk_chain(first, min(max(expected_count, 8), 256))
            if not fields:
                continue
            score = len(fields)
            if expected_count:
                score -= abs(expected_count - len(fields)) * 4
            if best is None or score > best[0]:
                best = (score, offset, first, fields)
        return best

    def evaluate_name_offset(self, fields, expected_names):
        rows = []
        for offset in self.name_offsets:
            values = [u32(data, offset) for _, data in fields]
            unique_values = len(set(values))
            conflicts = 0
            mapping = {}
            for index, value in enumerate(values[:len(expected_names)]):
                name = expected_names[index]
                previous = mapping.get(value)
                if previous is not None and previous != name:
                    conflicts += 1
                mapping[value] = name
            pointer_like = sum(1 for value in values if value > 0x10000000)
            all_same = unique_values <= 1 and len(values) >= 3
            score = unique_values * 4 - conflicts * 20 - pointer_like * 8
            if all_same:
                score -= 50
            rows.append({
                'offset': offset,
                'values': values,
                'unique': unique_values,
                'conflicts': conflicts,
                'pointer_like': pointer_like,
                'all_same': all_same,
                'score': score,
            })
        rows.sort(key=lambda row: row['score'], reverse=True)
        return rows

    def verify_object(self, short_name, max_fields):
        dump_obj = self.dump_index.find_one(short_name)
        if not dump_obj:
            print(f'[{short_name}] missing in dump')
            return None

        object_address = self.objects.get_address(dump_obj.index)
        if not object_address:
            print(f'[{short_name}] missing live object index=0x{dump_obj.index:X}')
            return None

        expected = [prop.name for prop in dump_obj.properties[:max_fields]]
        child = self.score_child_offset(object_address, len(expected))
        if not child:
            print(f'[{short_name}] no readable FField chain')
            return None

        _, child_offset, first_field, fields = child
        name_rows = self.evaluate_name_offset(fields, expected)
        best_name = name_rows[0]
        default_28 = next((row for row in name_rows if row['offset'] == 0x28), None)

        print(f'\n[{short_name}] index=0x{dump_obj.index:X} object=0x{object_address:X}')
        print(f'  ChildProperties=0x{child_offset:X} first=0x{first_field:X} fields={len(fields)} expected={len(expected)}')
        print(f'  BestNameOffset=0x{best_name["offset"]:X} unique={best_name["unique"]} conflicts={best_name["conflicts"]} pointerLike={best_name["pointer_like"]}')
        if default_28:
            sample = ', '.join(f'0x{value:X}' for value in default_28['values'][:8])
            print(f'  Offset0x28 unique={default_28["unique"]} conflicts={default_28["conflicts"]} values={sample}')

        learned = {}
        best_values = best_name['values']
        for index, ((address, data), value) in enumerate(zip(fields, best_values)):
            expected_name = expected[index] if index < len(expected) else '<unknown>'
            learned[value] = expected_name
            offset_internal = u32(data, 0x40)
            class_ptr = u64(data, 0x08)
            print(f'    [{index:03d}] field=0x{address:X} ci=0x{value:X} expected={expected_name} class=0x{class_ptr:X} offset=0x{offset_internal:X}')
            if index + 1 >= max_fields:
                break

        return {
            'name': short_name,
            'object': dump_obj,
            'object_address': object_address,
            'child_offset': child_offset,
            'first_field': first_field,
            'fields': fields,
            'best_name_offset': best_name['offset'],
            'default_28': default_28,
            'learned': learned,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pid', type=int)
    parser.add_argument('--gobjects', default='0x14E6ADF00')
    parser.add_argument('--dump', required=True)
    parser.add_argument('--targets', default='Guid,Vector,Engine')
    parser.add_argument('--max-fields', type=int, default=24)
    args = parser.parse_args()

    ipc = IpcClient(args.pid)
    if not ipc.is_connected():
        print('connect failed')
        return 1

    dump_index = load_dump(args.dump)
    objects = ObjectArray(ipc, int(args.gobjects, 16))
    print(f'GObjects num={objects.num} chunks={len(objects.chunks)}')

    verifier = FFieldVerifier(ipc, objects, dump_index)
    results = []
    for target in [item.strip() for item in args.targets.split(',') if item.strip()]:
        result = verifier.verify_object(target, args.max_fields)
        if result:
            results.append(result)

    engine = next((result for result in results if result['object'].text == 'Class Engine.Engine'), None)
    if engine:
        best_offset = engine['best_name_offset']
        default_28 = engine['default_28']
        if best_offset != 0x28 and default_28 and default_28['unique'] <= 1:
            print('\n[OK] Engine TinyFont duplication condition reproduced at wrong offset and avoided by best offset')
        else:
            print('\n[WARN] Engine verification did not isolate the TinyFont duplication condition')

    ipc.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

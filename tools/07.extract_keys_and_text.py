# ==============================================================================
# extract_keys_and_text.py
# 用途：扫描 EXE，提取所有 [键名] -> [默认文本] 的 0x18 结构体，输出槽偏移。
# ==============================================================================

# 按“翻译冲突组”输出（把共用同一功能的英文和日文全部聚在一起，非常方便找冲突）：
# python extract_keys_and_text.py --group-shared

import struct
import re
import argparse
from collections import defaultdict

bin_file = r"sai2.exe"
out_file = r"keys_and_texts_map.txt"

# ==============================================================================
# 1. PEInfo 解析类
# ==============================================================================
class PEInfo:
    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        d = self.data
        e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
        fh = e_lfanew + 4
        opt_size = struct.unpack_from('<H', d, fh + 16)[0]
        opt = fh + 20
        magic = struct.unpack_from('<H', d, opt)[0]
        if magic == 0x20B:
            self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        else:
            self.image_base = struct.unpack_from('<I', d, opt + 28)[0]
            
        self.size_of_headers = struct.unpack_from('<I', d, opt + 60)[0]
        self.sections = []
        sh = opt + opt_size
        num_sections = struct.unpack_from('<H', d, fh + 2)[0]
        for i in range(num_sections):
            b = sh + i * 40
            name = d[b:b+8].rstrip(b'\0').decode('ascii', 'replace')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', d, b + 8)
            self.sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                                      rsize=rsize, rptr=rptr))

    def file_off_to_va(self, off):
        for s in self.sections:
            if s['rptr'] <= off < s['rptr'] + s['rsize']:
                rva = off - s['rptr'] + s['vaddr']
                return self.image_base + rva
        if off < self.size_of_headers:
            return self.image_base + off
        return None

    def va_to_file_off(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + s['rsize']:
                return s['rptr'] + (rva - s['vaddr'])
        return None

# ==============================================================================
# 2. 转义处理
# ==============================================================================
def escape_tsv(s):
    return s.replace('\n', '\\n').replace('\r', '')

# ==============================================================================
# 3. 扫描全文件合法的 UTF-16LE 字符串
# ==============================================================================
def is_printable(c):
    o = ord(c)
    if c in '\n\r\t': return True
    if 0x20 <= o <= 0x7E: return True
    if 0x4E00 <= o <= 0x9FFF: return True
    if 0x3040 <= o <= 0x30FF: return True
    if 0x2000 <= o <= 0x206F: return True
    if 0xFF00 <= o <= 0xFFEF: return True
    return False

def scan_utf16_strings(data):
    strings = {}
    n = len(data)
    i = 0
    while i < n - 1:
        if i >= 2 and (data[i-1] != 0 or data[i-2] != 0):
            i += 1
            continue

        chars = []
        j = i
        hit_null = False
        while j < n - 1:
            code = data[j] | (data[j + 1] << 8)
            if code == 0:
                hit_null = True
                break
            ch = chr(code)
            if not is_printable(ch):
                break
            chars.append(ch)
            j += 2
            if len(chars) > 1000:
                break

        if len(chars) >= 2 and hit_null:
            s = ''.join(chars)
            if s.strip():
                strings[i] = s
            i = j + 2
        else:
            i += 1
    return strings

# ==============================================================================
# 4. 扫描双指针结构
# ==============================================================================
def find_key_value_pairs(pe, data):
    print("正在扫描所有字符串并建立映射库...")
    str_file_offsets = scan_utf16_strings(data)
    
    va_to_str = {}
    for f_off, s in str_file_offsets.items():
        va = pe.file_off_to_va(f_off)
        if va:
            va_to_str[va] = s
            
    print(f"找到 {len(va_to_str)} 个合法的字符串 VA。")
    print("正在扫描双指针结构 (0x18 结构)...")

    key_pattern = re.compile(r'^[A-Za-z0-9_]+$')
    
    results = []
    n = len(data)
    
    for section in pe.sections:
        if section['name'] != '.rdata':
            continue
            
        start = section['rptr']
        end = start + section['rsize']
        
        for i in range(start, end - 16, 8):
            ptr1 = struct.unpack_from('<Q', data, i)[0]
            
            if ptr1 in va_to_str:
                key_str = va_to_str[ptr1]
                
                if key_pattern.match(key_str) and len(key_str) > 3:
                    ptr2 = struct.unpack_from('<Q', data, i + 8)[0]
                    
                    if ptr2 in va_to_str:
                        text_str = va_to_str[ptr2]
                        
                        # 如果是带下划线的，说明它是另一个内部键名，跳过
                        if '_' not in text_str:
                            text_file_off = pe.va_to_file_off(ptr2)
                            results.append((i, ptr1, key_str, ptr2, text_str, text_file_off))
                            
    return results

# ==============================================================================
# 5. 主程序逻辑
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="提取 SAI2 的键名与文本映射表")
    parser.add_argument("--group-shared", action="store_true", help="按共用冲突组输出，把同一键名的英文/日文聚在一起")
    parser.add_argument("--shared", action="store_true", help="只输出被多个键名共用的文本")
    parser.add_argument("--output", "-o", default=None, help="输出文件名（不指定则根据模式自动命名）")
    args = parser.parse_args()

    # 如果同时指定 --shared 和 --group-shared，优先使用 --group-shared
    if args.shared and args.group_shared:
        print("⚠️ --shared 和 --group-shared 同时指定，优先使用 --group-shared")
        args.shared = False

    # 自动命名输出文件
    if args.output is None:
        if args.shared:
            args.output = r"keys_and_texts_map-shared.txt"
        elif args.group_shared:
            args.output = r"keys_and_texts_map-group-shared.txt"
        else:
            args.output = out_file

    data = open(bin_file, 'rb').read()
    pe = PEInfo(data)
    results = find_key_value_pairs(pe, data)

    if args.group_shared:
        # ---- 核心：按翻译冲突组建组 ----
        key_to_texts = defaultdict(set)
        for _, _, k, _, t, _ in results:
            key_to_texts[k].add(t)

        parent = {}
        def find(x):
            parent.setdefault(x, x)
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for t in set(t for _,_,_,_,t,_ in results):
            find(t)

        for texts in key_to_texts.values():
            texts = list(texts)
            for i in range(1, len(texts)):
                union(texts[0], texts[i])

        groups = defaultdict(list)
        for t in set(t for _,_,_,_,t,_ in results):
            groups[find(t)].append(t)

        valid_groups = []
        for root, texts in groups.items():
            group_items = [r for r in results if r[4] in texts]
            if len(group_items) > 1:
                valid_groups.append((texts, group_items))

        valid_groups.sort(key=lambda x: len(x[1]), reverse=True)
        
        print(f"\n共发现 {len(valid_groups)} 个翻译冲突组。")
        
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write("# 翻译冲突组映射表\n")
            f.write("# 把共用同一功能的英文、日文等不同语言的槽位全部聚在了一起。\n")
            f.write("# 格式：<键名指针>\t<槽文件偏移>\t<键名>\t<文本指针(VA)>\t<文本文件偏移>\t<默认文本>\n\n")
            
            for texts, items in valid_groups:
                unique_texts = sorted(list(set(t for _, _, _, _, t, _ in items)))
                text_desc = " / ".join(unique_texts)
                
                f.write(f"# ===== 组内文本: {text_desc} (共 {len(items)} 处) =====\n")
                
                items_sorted = sorted(items, key=lambda x: (x[2], x[4]))
                
                for slot_off, ptr1, key_str, ptr2, text_str, text_f_off in items_sorted:
                    text_str_escaped = escape_tsv(text_str)
                    f.write(f"0x{ptr1:08X}\t0x{slot_off:08X}\t{key_str}\t0x{ptr2:08X}\t0x{text_f_off:08X}\t{text_str_escaped}\n")
                f.write("\n")

    elif args.shared:
        # ---- 核心：按共用文本分组输出 ----
        # 统计每个文本出现的次数
        text_counts = defaultdict(int)
        for _, _, _, _, t, _ in results:
            text_counts[t] += 1

        shared_texts = {t for t, c in text_counts.items() if c > 1}

        text_to_items = defaultdict(list)
        for item in results:
            if item[4] in shared_texts:
                text_to_items[item[4]].append(item)

        print(f"\n共发现 {len(text_to_items)} 组共用文本。")

        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write("# 共用文本映射表（仅包含被多个键名引用的文本）\n")
            f.write("# 格式：<键名指针>\t<槽文件偏移>\t<键名>\t<文本指针(VA)>\t<文本文件偏移>\t<默认文本>\n\n")

            sorted_items = sorted(text_to_items.items(), key=lambda x: len(x[1]), reverse=True)

            for text_str, items in sorted_items:
                text_str_escaped = escape_tsv(text_str)
                f.write(f"# ===== 共用文本: {text_str_escaped} (共 {len(items)} 处) =====\n")

                items_sorted = sorted(items, key=lambda x: (x[2], x[4]))

                for slot_off, ptr1, key_str, ptr2, text_str, text_f_off in items_sorted:
                    key_str_escaped = escape_tsv(key_str)
                    text_str_escaped = escape_tsv(text_str)
                    f.write(f"0x{ptr1:08X}\t0x{slot_off:08X}\t{key_str_escaped}\t0x{ptr2:08X}\t0x{text_f_off:08X}\t{text_str_escaped}\n")
                f.write("\n")

    else:
        # ---- 默认全量输出 ----
        print(f"\n共找到 {len(results)} 组 [键名 + 文本] 结构！")
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write("# 自动提取的 键名 -> 文本 映射表\n")
            f.write("# 格式：<键名指针>\t<槽文件偏移>\t<键名>\t<文本指针(VA)>\t<文本文件偏移>\t<默认英文文本>\n\n")
            for slot_off, ptr1, key_str, ptr2, text_str, text_f_off in results:
                key_str_escaped = escape_tsv(key_str)
                text_str_escaped = escape_tsv(text_str)
                f.write(f"0x{ptr1:08X}\t0x{slot_off:08X}\t{key_str_escaped}\t0x{ptr2:08X}\t0x{text_f_off:08X}\t{text_str_escaped}\n")

    print(f"输出完成: {args.output}")

if __name__ == "__main__":
    main()
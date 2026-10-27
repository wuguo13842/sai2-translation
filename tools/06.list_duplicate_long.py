#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
06.list_duplicate_long.py

扫描「地址 + 英文 [ + 中文]」格式的文件，列出英文重复的长句。
输出格式与 append_duplicates.py 完全兼容：

    0x002D69A0\tPaintTool SAI Ver.2 (64bit) Preview.2026.07.02b
    0x002F0DB0\tPaintTool SAI Ver.2 (64bit) Preview.2026.07.02b
    (空行)
    0x00317560\tThis setting is enabled from the next created/opened canvas.
    0x003176E0\tThis setting is enabled from the next created/opened canvas.

append_duplicates.py 读这个文件时：
  - 每行 split('\t') → parts[0]=地址, parts[1]=英文
  - 空行自动跳过
  - 英文会在已有 map 里查中文，查到就插到同英文最后一条已有行之后

用法：
    python 06.list_duplicate_long.py full_all.txt -o long_dup.txt
    python 06.list_duplicate_long.py en_cn_map_fixed_20260702.txt -o long_dup.txt

    python 03.insert_duplicates.py en_cn_map_fixed_20260702.txt long_dup.txt --inplace

可选：
    --min-len 20    英文最小长度（默认 20）
    --min-words 3   英文最少词数（默认 3）
"""

import argparse
import sys
from collections import defaultdict, OrderedDict

FORCE_MARKS = {
    '# ===== FORCE WRITE =====',
    '# ===== POINTER FORCE =====',
}


def parse_map(path):
    addr_to_entry = OrderedDict()
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        in_force = False
        for lineno, line in enumerate(f, 1):
            s = line.rstrip('\r\n')
            if s.strip() in FORCE_MARKS:
                in_force = True
                continue
            if in_force:
                continue
            if not s.strip():
                continue
            lst = s.lstrip()
            if lst.startswith('#') or lst.startswith('//'):
                continue
            p = s.split('\t')
            if len(p) < 2:
                continue
            try:
                addr = int(p[0].strip(), 16)
            except ValueError:
                continue
            en = p[1]
            cn = p[2] if len(p) >= 3 else ''
            addr_to_entry[addr] = (en, cn, lineno)
    return addr_to_entry


def is_long_sentence(en, min_len, min_words):
    if ' ' not in en:
        return False
    if len(en) < min_len:
        return False
    if len(en.split()) < min_words:
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description="列出英文重复的长句（输出兼容 append_duplicates.py）")
    ap.add_argument('map_txt')
    ap.add_argument('-o', '--output', help='输出文件（默认打印到 stdout）')
    ap.add_argument('--min-len', type=int, default=20)
    ap.add_argument('--min-words', type=int, default=3)
    args = ap.parse_args()

    addr_to_entry = parse_map(args.map_txt)
    print(f"[i] 有效条目: {len(addr_to_entry)}", file=sys.stderr)

    en_to_entries = defaultdict(list)
    for addr, (en, cn, lineno) in addr_to_entry.items():
        en_to_entries[en].append((addr, cn, lineno))

    dup = {}
    for en, entries in en_to_entries.items():
        if len(entries) < 2:
            continue
        if not is_long_sentence(en, args.min_len, args.min_words):
            continue
        dup[en] = entries

    print(f"[i] 长句重复组: {len(dup)}", file=sys.stderr)
    print(f"[i] 涉及地址: {sum(len(e) for e in dup.values())}",
          file=sys.stderr)

    lines = []
    for en in sorted(dup, key=lambda x: (-len(dup[x]), x)):
        entries = sorted(dup[en], key=lambda x: x[0])
        if lines:
            lines.append('')
        for addr, cn, lineno in entries:
            lines.append(f"0x{addr:08X}\t{en}")

    text = '\n'.join(lines) + '\n'

    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        print(f"[i] 已写入 -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
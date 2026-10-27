#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
03.insert_duplicates.py

把「重复显示文本清单」中的地址，插入到 en_cn_map 中对应英文已有行的后面。
不是追加到文件末尾，而是紧跟在同英文的最后一条已有行之后。

翻译来源：从已有 en_cn_map 中学习「英文 → 中文」映射。
  - 清单里的地址若已存在于 map → 跳过
  - 英文在 map 里出现过 → 复用该中文，插入到该英文最后一条已有行之后
  - 英文在 map 里没出现过 → 列为「未匹配」，默认不插入，需手工处理
  - 以 . 开头的扩展名默认跳过

清单格式（每行一条，两种分隔都支持）：
    0x002F6EF0 | Pen | 钢笔工具
    0x002F6EF0<TAB>Pen<TAB>钢笔工具

用法：
    python 03.insert_duplicates.py en_cn_map_fixed_20260702.txt 重复项_纯显示.txt
    python 03.insert_duplicates.py en_cn_map_fixed_20260702.txt 重复项_纯显示.txt -o out.txt
    python 03.insert_duplicates.py en_cn_map_fixed_20260702.txt 重复项_纯显示.txt --inplace
    python 03.insert_duplicates.py en_cn_map_fixed_20260702.txt 重复项_纯显示.txt --unmatched-end
"""

import argparse
import os
import re
import shutil
import sys
from collections import defaultdict

FORCE_MARKS = {
    '# ===== FORCE WRITE =====',
    '# ===== POINTER FORCE =====',
}

ADDR_RE = re.compile(
    r'^(?P<prefix>[ \t]*(?://[ \t]*)?)'
    r'(?P<addr>0[xX][0-9A-Fa-f]+)'
    r'\t(?P<en>[^\t]*)'
    r'(?:\t(?P<cn>.*))?$'
)


def parse_map(path):
    with open(path, 'rb') as f:
        has_bom = f.read(3) == b'\xef\xbb\xbf'
    enc = 'utf-8-sig' if has_bom else 'utf-8'
    with open(path, 'r', encoding=enc, newline='') as f:
        content = f.read()
    lines = content.splitlines(keepends=True)

    newline = '\n'
    for ln in lines:
        if ln.endswith('\r\n'):
            newline = '\r\n'
            break
        if ln.endswith('\n'):
            newline = '\n'
            break

    existing_addrs = set()
    en_last_idx = {}
    en_to_cn_all = defaultdict(list)
    in_force = False

    for idx, ln in enumerate(lines):
        s = ln.rstrip('\r\n')
        if s.strip() in FORCE_MARKS:
            in_force = True
            continue
        if in_force:
            continue
        if not s.strip():
            continue
        m = ADDR_RE.match(s)
        if not m:
            continue
        addr = int(m.group('addr'), 16)
        en = m.group('en')
        cn = m.group('cn') or ''
        existing_addrs.add(addr)
        if s.lstrip().startswith('//'):
            continue
        en_last_idx[en] = idx
        if cn and cn not in en_to_cn_all[en]:
            en_to_cn_all[en].append(cn)

    en_to_cn = {}
    conflicts = []
    for en, cns in en_to_cn_all.items():
        en_to_cn[en] = cns[0]
        if len(cns) > 1:
            conflicts.append((en, cns))

    return lines, newline, existing_addrs, en_last_idx, en_to_cn, conflicts, has_bom


def parse_dup(path):
    items = []
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        for line in f:
            line = line.rstrip('\r\n')
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            if '|' in line:
                parts = [x.strip() for x in line.split('|')]
            else:
                parts = [x.strip() for x in line.split('\t')]
            if len(parts) < 2:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            en = parts[1]
            items.append((addr, en))
    return items


def main():
    ap = argparse.ArgumentParser(description="把重复显示文本插入到 en_cn_map 对应行后面")
    ap.add_argument('map_txt')
    ap.add_argument('dup_txt')
    ap.add_argument('-o', '--output')
    ap.add_argument('--inplace', action='store_true')
    ap.add_argument('--all', action='store_true', help='已存在的地址也插入（默认跳过）')
    ap.add_argument('--keep-ext', action='store_true', help='不跳过 . 开头的扩展名')
    ap.add_argument('--unmatched-end', action='store_true',
                    help='把未匹配的（英文不在 map 中）追加到文件末尾')
    args = ap.parse_args()

    (lines, newline, existing_addrs, en_last_idx, en_to_cn,
     conflicts, has_bom) = parse_map(args.map_txt)

    print(f"[i] 已有 map: {len(existing_addrs)} 个地址, "
          f"{len(en_last_idx)} 个唯一英文", file=sys.stderr)
    if conflicts:
        print(f"[!] {len(conflicts)} 个英文对应多个中文（取第一个）：", file=sys.stderr)
        for en, cns in conflicts[:20]:
            print(f"    {en!r} -> {cns}", file=sys.stderr)
        if len(conflicts) > 20:
            print(f"    ... 共 {len(conflicts)} 个", file=sys.stderr)

    items = parse_dup(args.dup_txt)
    print(f"[i] 清单: {len(items)} 条", file=sys.stderr)

    inserts = defaultdict(list)
    skipped_existing = 0
    skipped_ext = 0
    unmatched = []
    seen_addrs = set()
    seen_keys = set()
    n_insert = 0

    for addr, en in items:
        if addr in seen_addrs:
            continue
        seen_addrs.add(addr)

        if not args.all and addr in existing_addrs:
            skipped_existing += 1
            continue
        if not args.keep_ext and en.startswith('.'):
            skipped_ext += 1
            continue
        if en not in en_last_idx:
            unmatched.append((addr, en))
            continue
        cn = en_to_cn.get(en, '')
        if not cn:
            unmatched.append((addr, en))
            continue
        key = (addr, en)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        idx = en_last_idx[en]
        inserts[idx].append(f"0x{addr:08X}\t{en}\t{cn}")
        n_insert += 1

    out_lines = []
    for idx, ln in enumerate(lines):
        out_lines.append(ln)
        if idx in inserts:
            if not ln.endswith(('\n', '\r')):
                out_lines.append(newline)
            for new_ln in inserts[idx]:
                out_lines.append(new_ln + newline)

    if args.unmatched_end and unmatched:
        if out_lines and not out_lines[-1].endswith(('\n', '\r')):
            out_lines.append(newline)
        out_lines.append(newline)
        out_lines.append("# ===== 未匹配（英文不在 map 中） =====" + newline)
        for addr, en in unmatched:
            out_lines.append(f"0x{addr:08X}\t{en}\t{newline}")

    new_content = ''.join(out_lines)

    if args.inplace:
        bak = args.map_txt + '.bak'
        shutil.copy2(args.map_txt, bak)
        print(f"[i] 备份 -> {bak}", file=sys.stderr)
        out_path = args.map_txt
    else:
        out_path = args.output or (os.path.splitext(args.map_txt)[0] + '.inserted.txt')

    enc = 'utf-8-sig' if has_bom else 'utf-8'
    with open(out_path, 'w', encoding=enc, newline='') as f:
        f.write(new_content)

    print(f"[i] 已写入 -> {out_path}", file=sys.stderr)
    print(f"[i] 插入 {n_insert} 条 | "
          f"跳过(已存在) {skipped_existing} | "
          f"跳过(扩展名) {skipped_ext} | "
          f"未匹配 {len(unmatched)}", file=sys.stderr)

    if unmatched and not args.unmatched_end:
        print(f"\n[!] 未匹配 {len(unmatched)} 条（英文不在 map 中，未插入）：",
              file=sys.stderr)
        for addr, en in unmatched:
            print(f"    0x{addr:08X}\t{en}", file=sys.stderr)


if __name__ == '__main__':
    main()
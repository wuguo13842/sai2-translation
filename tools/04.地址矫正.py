#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_addr.py
用 full_en.txt 中的英文原文反查真实地址，校正 en_cn_map_fixed_*.txt 的地址列。
支持被 // 注释掉的行，英文/中文部分保持不变。

用法示例：
    python fix_addr.py full_en.txt en_cn_map_fixed_20231019.txt
    python fix_addr.py full_en.txt en_cn_map_fixed_20231019.txt -o fixed.txt
    python fix_addr.py full_en.txt en_cn_map_fixed_20231019.txt --inplace
    python fix_addr.py full_en.txt en_cn_map_fixed_20231019.txt --dry-run -v
    
-o fixed.txt 输出文件名由你指定
-v（--verbose）：输出详细警告。
--dry-run：只统计、不写文件
--inplace，意思是原地修改。
"""

import argparse
import os
import re
import shutil
import sys
from collections import defaultdict

# 行格式： [可选 // ] 0xXXXXXXXX <tab> 英文 <tab> 中文 ...
ADDR_RE = re.compile(r'^(?P<prefix>[ \t]*(?://[ \t]*)?)'
                     r'(?P<addr>0[xX][0-9A-Fa-f]+)'
                     r'(?P<rest>.*)$')
WS_RE = re.compile(r'\s+')

# 这两个标记之后的内容不是「地址 英文 中文」格式，原样输出，不参与校正
FORCE_MARKS = {
    '# ===== FORCE WRITE =====',
    '# ===== POINTER FORCE =====',
}


def norm(s: str) -> str:
    """把连续空白（含 tab）折叠为一个空格并去首尾。"""
    return WS_RE.sub(' ', s).strip()


# ---------------------------------------------------------------------------
# 1. 解析 full_en.txt
# ---------------------------------------------------------------------------
def load_full(path):
    """
    返回 exact: dict[规范化英文] = 升序地址列表
    """
    exact = defaultdict(list)

    with open(path, 'r', encoding='utf-8-sig', errors='replace', newline='') as f:
        for raw in f:
            line = raw.rstrip('\r\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            m = ADDR_RE.match(line)
            if not m:
                continue
            addr = int(m.group('addr'), 16)
            rest = m.group('rest')
            rest = rest.lstrip('\t')                      # 去掉所有前导 tab
            key = norm(rest.split('\t', 1)[0])            # 只取英文列
            if not key:
                continue
            exact[key].append(addr)

    for k in exact:
        exact[k] = sorted(set(exact[k]))

    return exact


# ---------------------------------------------------------------------------
# 2. 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="用 full_en.txt 校正翻译映射文件的地址")
    ap.add_argument('full_en', help='full_en.txt 路径')
    ap.add_argument('map_txt', help='en_cn_map_fixed_*.txt 路径')
    ap.add_argument('-o', '--output', help='输出文件（默认在原文件名后加 .fixed.txt）')
    ap.add_argument('--inplace', action='store_true',
                    help='直接覆盖原文件（会先备份为 .bak）')
    ap.add_argument('--dry-run', action='store_true', help='只统计不写文件')
    ap.add_argument('-v', '--verbose', action='count', default=0, help='输出警告详情')
    args = ap.parse_args()

    exact = load_full(args.full_en)
    print(f"[i] full_en: {len(exact)} 个唯一英文, "
          f"{sum(len(v) for v in exact.values())} 个地址条目", file=sys.stderr)

    # 保留原文件 BOM 状态（供写回时使用）
    with open(args.map_txt, 'rb') as fb:
        has_bom = fb.read(3) == b'\xef\xbb\xbf'
    enc = 'utf-8-sig' if has_bom else 'utf-8'

    # 读取：utf-8-sig 自动去 BOM；统一换行符为 LF 后再切行
    with open(args.map_txt, 'r', encoding='utf-8-sig', errors='replace') as f:
        content = f.read()
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.split('\n')

    used = defaultdict(set)
    out_lines = []
    stats = dict(total=0, changed=0, same=0, unmatched=0, skipped_force=0)
    warnings = []

    in_force = False

    for i, raw in enumerate(lines):
        cr = ''
        line = raw
        if line.endswith('\r'):          # 保留 CRLF
            cr = '\r'
            line = line[:-1]

        # ===== FORCE / POINTER FORCE 区：原样输出，不参与校正 =====
        if line.strip() in FORCE_MARKS:
            in_force = True
            out_lines.append(raw)
            continue
        if in_force:
            stats['skipped_force'] += 1
            out_lines.append(raw)
            continue

        m = ADDR_RE.match(line)
        if not m:                        # 注释行、空行等
            out_lines.append(raw)
            continue

        stats['total'] += 1
        prefix = m.group('prefix')
        old_addr = int(m.group('addr'), 16)
        rest = m.group('rest')

        payload = rest[1:] if rest.startswith('\t') else rest
        # 按 tab 取出英文列（第二列）做匹配，中文列原样保留在 rest 中；
        # 精确匹配，避免 'Delete the current asset.' 误命中 'Delete'
        pnorm = norm(payload.split('\t', 1)[0])
        if not pnorm:
            out_lines.append(raw)
            continue

        key = pnorm if pnorm in exact else None
        if key is None:
            stats['unmatched'] += 1
            warnings.append(f"L{i+1}: 未匹配 -> {pnorm[:90]!r}")
            out_lines.append(raw)
            continue

        addrs = exact[key]
        if len(addrs) == 1:
            new_addr = addrs[0]
        else:
            # 同一英文有多个地址时，选与旧地址最接近且尚未用过的
            cands = [a for a in addrs if a not in used[key]]
            if not cands:
                cands = addrs
            new_addr = min(cands, key=lambda a: abs(a - old_addr))
            used[key].add(new_addr)

        if new_addr == old_addr:
            stats['same'] += 1
            new_line = line
        else:
            stats['changed'] += 1
            new_line = f"{prefix}0x{new_addr:08X}{rest}"

        out_lines.append(new_line + cr)

    out_text = '\n'.join(out_lines)

    if args.dry_run:
        print(f"[dry-run] 将修改 {stats['changed']} 行（未写入）", file=sys.stderr)
    else:
        if args.inplace:
            bak = args.map_txt + '.bak'
            shutil.copy2(args.map_txt, bak)
            print(f"[i] 备份 -> {bak}", file=sys.stderr)
            out_path = args.map_txt
        else:
            out_path = args.output or (os.path.splitext(args.map_txt)[0] + '.fixed.txt')
        with open(out_path, 'w', encoding=enc, newline='') as f:
            f.write(out_text)
        print(f"[i] 已写入 -> {out_path}", file=sys.stderr)

    print(f"[i] 记录 {stats['total']} | 修改 {stats['changed']} | "
          f"未变 {stats['same']} | 未匹配 {stats['unmatched']} | "
          f"跳过(FORCE区) {stats['skipped_force']}", file=sys.stderr)

    if warnings:
        if args.verbose:
            print(f"[i] 警告 {len(warnings)} 条:", file=sys.stderr)
            for w in warnings:
                print("    " + w, file=sys.stderr)
        else:
            print(f"[i] 有 {len(warnings)} 条警告，加 -v 查看", file=sys.stderr)


if __name__ == '__main__':
    main()
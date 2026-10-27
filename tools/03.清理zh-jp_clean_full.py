#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 full.txt 删除乱码行，默认只保留中文/日文。

用法：
    python clean_full.py                       # 输入 full.txt → full.clean.txt，只保留中/日文
    python clean_full.py in.txt                # 指定输入
    python clean_full.py in.txt out.txt        # 指定输入输出
    python clean_full.py in.txt out.txt --keep-ascii   # 同时保留合法英文行
"""

import sys
import unicodedata

PUNCT_ALLOWED = set(
    '、。，．・：；？！「」『』（）〔〕【】〈〉《》'
    '…‥—―‐／＼｜＋－＝＊＆＾％＃＠～'
    '[](){}.,:;!?/\\|+-=*&^%#@~"\'`'
    '　 '
)

def char_kind(ch):
    o = ord(ch)
    if ch in ('\t', '\n', '\r'):
        return 'space'
    if unicodedata.category(ch) in ('Cc', 'Cn', 'Co', 'Cs'):
        return 'ctrl'
    if 0x20 <= o <= 0x7E:
        return 'ascii'
    if (0x3041 <= o <= 0x3096) or (0x309D <= o <= 0x309F) \
       or (0x30A1 <= o <= 0x30FA) or (0x30FC <= o <= 0x30FF) \
       or (0x31F0 <= o <= 0x31FF) or (0xFF65 <= o <= 0xFF9F):
        return 'kana'
    if (0xFF10 <= o <= 0xFF19) or (0xFF21 <= o <= 0xFF3A) or (0xFF41 <= o <= 0xFF5A):
        return 'fullwidth_alnum'
    if 0x4E00 <= o <= 0x9FFF:
        return 'cjk'
    if 0x3400 <= o <= 0x4DBF or 0x20000 <= o <= 0x2A6DF or 0xF900 <= o <= 0xFAFF:
        return 'cjk_ext'
    if ch in PUNCT_ALLOWED:
        return 'punct'
    if unicodedata.category(ch).startswith('P') or unicodedata.category(ch).startswith('S'):
        return 'punct'
    return 'other'

def is_level1_cjk(ch):
    try:
        b = ch.encode('gb2312')
    except UnicodeEncodeError:
        return False
    return 0xB0 <= b[0] <= 0xD7

def is_jis_kanji(ch):
    try:
        ch.encode('shift_jis')
        return True
    except UnicodeEncodeError:
        return False

def is_valid_cjk(ch):
    return is_level1_cjk(ch) or is_jis_kanji(ch)

def analyze_line(text):
    st = {'kana':0,'cjk_valid':0,'cjk_invalid':0,'ascii':0,'punct':0,'other':0,'ctrl':0}
    for ch in text:
        k = char_kind(ch)
        if k == 'kana': st['kana'] += 1
        elif k == 'cjk':
            if is_valid_cjk(ch): st['cjk_valid'] += 1
            else: st['cjk_invalid'] += 1
        elif k == 'cjk_ext': st['cjk_invalid'] += 1
        elif k == 'ascii': st['ascii'] += 1
        elif k == 'punct': st['punct'] += 1
        elif k == 'ctrl': st['ctrl'] += 1
        else: st['other'] += 1
    return st

def is_garbage(text, cn_only=True):
    text = text.strip()
    if not text:
        return True
    st = analyze_line(text)
    total = len(text)

    if st['ctrl'] > 0:
        return True

    if total == 1:
        k = char_kind(text[0])
        if k in ('cjk','cjk_ext','other','kana'):
            return True
        if k == 'ascii' and not text.isdigit():
            return True
        return False

    if st['cjk_invalid'] > 0:
        non_ascii = st['kana'] + st['cjk_valid'] + st['cjk_invalid']
        if non_ascii <= 4:
            return True
        if non_ascii > 0 and st['cjk_invalid'] / non_ascii >= 0.25:
            return True
        if st['cjk_invalid'] >= 3:
            return True

    if st['other'] > 0:
        non_ascii = st['kana'] + st['cjk_valid'] + st['cjk_invalid'] + st['other']
        if st['other'] / max(non_ascii, 1) >= 0.3:
            return True

    # 纯 ASCII
    if st['kana'] == 0 and st['cjk_valid'] == 0 and st['cjk_invalid'] == 0:
        if cn_only:
            return True
        if total < 2:
            return True
        if any(c.isalpha() for c in text):
            return False
        return True

    if st['kana'] > 0:
        return False
    if st['cjk_valid'] > 0:
        return False
    return True

def main():
    args = sys.argv[1:]
    cn_only = True
    if '--keep-ascii' in args:
        cn_only = False
        args.remove('--keep-ascii')

    in_path  = args[0] if len(args) > 0 else 'full.txt'
    out_path = args[1] if len(args) > 1 else 'full.clean.txt'

    with open(in_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()

    kept = removed = 0
    out_lines, samples = [], []

    for line in lines:
        raw = line.rstrip('\r\n')
        if not raw.strip():
            removed += 1
            continue
        if raw.startswith('#') or raw.startswith('//'):
            out_lines.append(raw); kept += 1; continue

        content = raw.split('\t', 1)[1] if '\t' in raw else raw
        if is_garbage(content, cn_only=cn_only):
            removed += 1
            if len(samples) < 60:
                samples.append(raw)
            continue
        out_lines.append(raw); kept += 1

    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        for l in out_lines:
            f.write(l + '\n')

    print(f'输入: {in_path}')
    print(f'输出: {out_path}')
    print(f'模式: {"只保留中文/日文" if cn_only else "保留英文"}')
    print(f'保留: {kept} 行')
    print(f'删除: {removed} 行')
    if samples:
        print(f'\n被删除的样例（前 {len(samples)} 条）：')
        for s in samples:
            print('  ', s[:120])

if __name__ == '__main__':
    main()
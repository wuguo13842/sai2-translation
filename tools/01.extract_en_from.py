# extract_en_from_bin.py
bin_file = r"sai2.exe"
out_file = r"full_all.txt"

BASE_OFFSET = 0x00000000
ZERO_LEN = 2                    # 前后各一个 word 的 00 00
MAX_LEN = 2000
MIN_LEN = 2                     # 单字符全砍
MIN_WORD_LEN = 2                # 至少 2 个连续字母（A-Z/a-z）
EXCLUDE_PERCENT_PREFIX = True   # 以 % 开头的格式串全砍
EXCLUDE_PURE_EXT = True        # True 时砍纯扩展名（.sai2/.psd/.bmp…）
# 如果你把 full_all.txt 当「全量锚点库」用（给 04 反查）→ 保留扩展名（EXCLUDE_PURE_EXT = False）。保持信息完整，下游 03/06 有开关可以过滤，不影响它们跑。
# 如果你把 full_all.txt 当「候选翻译清单」用（人眼看要翻哪些）→ 砍掉扩展名（EXCLUDE_PURE_EXT = True），否则满屏 .bmp、.jpg 会淹没真正要翻的句子。
EXCLUDE_UNDERSCORE = True       # 含 _ 的内部键名全砍（BrCtl_xxx / LayTxt_xxx / FuncCat_xxx 等）

data = open(bin_file, 'rb').read()
print(f"bin 大小: {len(data):,} 字节 ({len(data):#x})")

def is_printable_en(c):
    o = ord(c)
    if c in '\n\r\t': return True
    if 0x20 <= o <= 0x7E: return True
    if 0x2000 <= o <= 0x206F: return True
    if 0x2190 <= o <= 0x21FF: return True
    if o in (0x2018, 0x2019, 0x201C, 0x201D): return True
    # 新增：几何图形（●■▲等）
    if 0x25A0 <= o <= 0x25FF: return True
    # 已移除 0x00A0–0x00FF：该区间是 Ç*、ððð、Õ!Þ! 等乱码来源
    return False

def escape_tsv(s):
    return s.replace('\n', '\\n').replace('\r', '')

def is_letter(c):
    return ('a' <= c <= 'z') or ('A' <= c <= 'Z')

def has_word(s, min_word_len):
    run = 0
    for c in s:
        if is_letter(c):
            run += 1
            if run >= min_word_len:
                return True
        else:
            run = 0
    return False

def is_pure_extension(s):
    """纯扩展名：以 . 开头、无空格、无括号、长度 <= 12、只含字母数字和点"""
    if not s.startswith('.'):
        return False
    if len(s) > 12:
        return False
    if ' ' in s or '(' in s or ')' in s:
        return False
    for c in s[1:]:
        if not (c.isalnum() or c == '.'):
            return False
    return True

def is_meaningful(s):
    if len(s) < MIN_LEN:
        return False
    if EXCLUDE_PERCENT_PREFIX and s.startswith('%'):
        return False
    if EXCLUDE_PURE_EXT and is_pure_extension(s):
        return False
    if EXCLUDE_UNDERSCORE and '_' in s:
        return False
    if not has_word(s, MIN_WORD_LEN):
        return False
    return True

def scan_utf16_strings(data, is_printable, zero_len=2, max_len=2000, min_len=1):
    results = []
    n = len(data)
    i = 0
    while i < n - 1:
        # 1) 前面 zero_len 字节全 0（已到文件开头则视为通过）
        #    zero_len=2 语义：前一个 word 是 00 00，即紧跟在字符串结束符或对齐填充后
        pre_ok = True
        for k in range(1, zero_len + 1):
            if i - k < 0:
                break
            if data[i - k] != 0:
                pre_ok = False
                break
        if not pre_ok:
            i += 1
            continue

        # 2) 从 i 读 UTF-16LE，直到 00 00 或不可打印或超长
        chars = []
        j = i
        hit_null = False
        while j < n - 1:
            code = data[j] | (data[j + 1] << 8)
            if code == 0:
                hit_null = True
                break
            try:
                ch = chr(code)
            except ValueError:
                break
            if not is_printable(ch):
                break
            chars.append(ch)
            j += 2
            if len(chars) > max_len:
                break

        # 3) 必须真正遇到 00 00 结束符；hit_null 已排除不可打印/超长退出的假结束
        if len(chars) >= min_len and hit_null:
            raw_s = ''.join(chars)      # 保留 0000 之间的原始内容（含首尾空格）
            s = raw_s.strip()           # 仅用于过滤判断空串/有意义
            if s and is_meaningful(s):
                max_run = 1; cur_run = 1
                for k in range(1, len(s)):
                    if s[k] == s[k-1]:
                        cur_run += 1
                        max_run = max(max_run, cur_run)
                    else:
                        cur_run = 1
                if max_run < 5:
                    results.append((i, raw_s))      # 这里写入原始串
                    # 4) 跳过字符串和后面的 0 word
                    i = j + 2
                    while i < n - 1 and data[i] == 0 and data[i + 1] == 0:
                        i += 2
                    continue

        i += 1
    return results

strings = scan_utf16_strings(data, is_printable_en, ZERO_LEN, MAX_LEN, MIN_LEN)
print(f"扫描到 {len(strings)} 条（ZERO_LEN={ZERO_LEN}, MIN_LEN={MIN_LEN}, "
      f"MIN_WORD_LEN={MIN_WORD_LEN}, EXCLUDE_PURE_EXT={EXCLUDE_PURE_EXT}, "
      f"EXCLUDE_UNDERSCORE={EXCLUDE_UNDERSCORE}）")

# 去重
seen = set(); unique = []
for off, s in strings:
    key = (BASE_OFFSET + off, s)
    if key not in seen:
        seen.add(key); unique.append((BASE_OFFSET + off, s))

print(f"去重后 {len(unique)} 条")

with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
    f.write(f"# 英文区全偏移扫描\n")
    f.write(f"# 条件: ZERO_LEN={ZERO_LEN}, MIN_LEN={MIN_LEN}, "
            f"MIN_WORD_LEN={MIN_WORD_LEN}, "
            f"EXCLUDE_PERCENT_PREFIX={EXCLUDE_PERCENT_PREFIX}, "
            f"EXCLUDE_PURE_EXT={EXCLUDE_PURE_EXT}, "
            f"EXCLUDE_UNDERSCORE={EXCLUDE_UNDERSCORE}\n")
    f.write(f"# 总数: {len(unique)} 条\n")
    f.write(f"# bin 范围: 0x{BASE_OFFSET:08X} ~ 0x{BASE_OFFSET + len(data):08X}\n\n")
    for off, s in unique:
        f.write(f"0x{off:08X}\t{escape_tsv(s)}\n")

print(f"\n输出: {out_file}")

# 自检
txt = open(out_file, encoding="utf-8").read()
for probe in ("FuncCat_Edit", "FuncCat_Layer", "File"):
    print(f"  含 {probe!r}: {probe in txt}")
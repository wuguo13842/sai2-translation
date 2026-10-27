# extract_cjk_from_bin.py
bin_file = r"sai2.exe"
out_file = r"full_zhjp.txt"

BASE_OFFSET = 0x00000000
ZERO_LEN = 2                    # 前后各一个 word 的 00 00
MAX_LEN = 2000
MIN_LEN = 2                     # 单字符全砍（避免二进制误读成单个「中」）
MIN_WORD_LEN = 2                # 至少 2 个连续 CJK/假名字符
EXCLUDE_PERCENT_PREFIX = True   # 以 % 开头的格式串全砍
EXCLUDE_UNDERSCORE = True       # 含 _ 的内部键名全砍
REQUIRE_CJK = True              # 必须含至少一个 CJK/假名字符（排除纯英文串）
MAX_RUN = 5                     # 连续相同字符 >= MAX_RUN 则丢弃

data = open(bin_file, 'rb').read()
print(f"bin 大小: {len(data):,} 字节 ({len(data):#x})")

def is_printable_cjk(c):
    o = ord(c)
    if c in '\n\r\t': return True
    # ASCII 可打印（中英混排常见）
    if 0x20 <= o <= 0x7E: return True
    # CJK 统一表意文字
    if 0x4E00 <= o <= 0x9FFF: return True
    # CJK 扩展 A
    if 0x3400 <= o <= 0x4DBF: return True
    # 日文平假名 / 片假名
    if 0x3040 <= o <= 0x30FF: return True
    # 日文标点 / 中文标点 / 全角
    if 0x3000 <= o <= 0x303F: return True
    if 0xFF00 <= o <= 0xFFEF: return True
    # 箭头
    if 0x2190 <= o <= 0x21FF: return True
    # 通用标点（※、…、—、· 等）
    if 0x2000 <= o <= 0x206F: return True
    # 几何图形（●、■、▲、◆ 等）
    if 0x25A0 <= o <= 0x25FF: return True
    # 常用符号
    if o in (0x2018, 0x2019, 0x201C, 0x201D, 0x2026, 0x2014, 0x00B7,
             0x00A0, 0x2003, 0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518):
        return True
    return False

def is_cjk(c):
    o = ord(c)
    return (0x4E00 <= o <= 0x9FFF or
            0x3400 <= o <= 0x4DBF or
            0x3040 <= o <= 0x30FF)

def has_cjk_char(s):
    return any(is_cjk(c) for c in s)

def has_cjk_word(s, min_word_len):
    run = 0
    for c in s:
        if is_cjk(c):
            run += 1
            if run >= min_word_len:
                return True
        else:
            run = 0
    return False

def escape_tsv(s):
    return s.replace('\n', '\\n').replace('\r', '')

def is_meaningful(s):
    if len(s) < MIN_LEN:
        return False
    if EXCLUDE_PERCENT_PREFIX and s.startswith('%'):
        return False
    if EXCLUDE_UNDERSCORE and '_' in s:
        return False
    if REQUIRE_CJK and not has_cjk_char(s):
        return False
    if not has_cjk_word(s, MIN_WORD_LEN):
        return False
    return True

def scan_utf16_strings(data, is_printable, zero_len=2, max_len=2000, min_len=1):
    results = []
    n = len(data)
    i = 0
    while i < n - 1:
        # 1) 前面 zero_len 字节全 0（已到文件开头则视为通过）
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

        # 3) 必须真正遇到 00 00 结束符
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
                if max_run < MAX_RUN:
                    results.append((i, raw_s))      # 这里写入原始串
                    # 4) 跳过字符串和后面的 0 word
                    i = j + 2
                    while i < n - 1 and data[i] == 0 and data[i + 1] == 0:
                        i += 2
                    continue

        i += 1
    return results

strings = scan_utf16_strings(data, is_printable_cjk, ZERO_LEN, MAX_LEN, MIN_LEN)
print(f"扫描到 {len(strings)} 条（ZERO_LEN={ZERO_LEN}, MIN_LEN={MIN_LEN}, "
      f"MIN_WORD_LEN={MIN_WORD_LEN}, REQUIRE_CJK={REQUIRE_CJK}）")

seen = set(); unique = []
for off, s in strings:
    key = (BASE_OFFSET + off, s)
    if key not in seen:
        seen.add(key); unique.append((BASE_OFFSET + off, s))

print(f"去重后 {len(unique)} 条")

has_kana = sum(1 for _, s in unique if any(0x3040 <= ord(c) <= 0x30FF for c in s))
has_cjk  = sum(1 for _, s in unique
               if any(0x4E00 <= ord(c) <= 0x9FFF or 0x3400 <= ord(c) <= 0x4DBF for c in s))
both     = sum(1 for _, s in unique
               if any(0x3040 <= ord(c) <= 0x30FF for c in s)
               and any(0x4E00 <= ord(c) <= 0x9FFF or 0x3400 <= ord(c) <= 0x4DBF for c in s))
print(f"  含假名: {has_kana} 条")
print(f"  含汉字: {has_cjk} 条")
print(f"  两者都有: {both} 条")

with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
    f.write(f"# 中文/日文区全偏移扫描\n")
    f.write(f"# 条件: ZERO_LEN={ZERO_LEN}, MIN_LEN={MIN_LEN}, "
            f"MIN_WORD_LEN={MIN_WORD_LEN}, "
            f"EXCLUDE_PERCENT_PREFIX={EXCLUDE_PERCENT_PREFIX}, "
            f"EXCLUDE_UNDERSCORE={EXCLUDE_UNDERSCORE}, "
            f"REQUIRE_CJK={REQUIRE_CJK}, MAX_RUN={MAX_RUN}\n")
    f.write(f"# 总数: {len(unique)} 条\n")
    f.write(f"# bin 范围: 0x{BASE_OFFSET:08X} ~ 0x{BASE_OFFSET + len(data):08X}\n\n")
    for off, s in unique:
        f.write(f"0x{off:08X}\t{escape_tsv(s)}\n")

print(f"\n输出: {out_file}")

# 自检
txt = open(out_file, encoding="utf-8").read()
for probe in ("的", "ファイル", "開", "中文"):
    print(f"  含 {probe!r}: {probe in txt}")
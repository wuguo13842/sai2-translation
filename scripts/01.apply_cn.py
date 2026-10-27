# apply_cn.py
new_file = r"../new.exe"
map_file = r"../mappings/en_cn_map_fixed_20261019.txt"
out_file = r"Temp.exe"
log_file = r"apply_log.txt"

# ★ 自动分配范围的锚点字符串（脚本会在 new_data 里搜索这两个独立字符串，自动算出范围）
# 版本变化后，只要这两个字符串还在，范围会自动重新计算；改这两行即可调整搜索边界
AUTO_ALLOC_ANCHOR_START = "Open [Asset Manager] dialog."
AUTO_ALLOC_ANCHOR_END   = "FPU control mode was changed by some extension program."

# ===== 性能实测记录（2026-10-26）=====
# 环境：SAI2 二进制 ~5MB，K（auto_pointers 条数）= 11
#   扫描阶段耗时：62.2 ms（11 次 bytes.find 全文件搜索）
#   若改用纯 Python 循环建索引：预估 > 3s（慢 ~50 倍）
#   若改用 numpy.frombuffer + argsort：预估 > 200ms（慢 ~3 倍）
# 结论：当前规模下任何"一次性索引"方案都不划算。维持 bytes.find 方案。
# 若将来 K 增长到几千量级，再重新评估；在此之前请勿引入索引优化。

"""
# ===== FORCE WRITE =====
# 基础 2/3/4 列：
#   0x偏移\t中文                         只写字符串
#   0x偏移\t中文\t原字符串偏移            写字符串 + 改指向原字符串的所有指针
#   0x偏移\t中文\t原字符串偏移\t原指针hex 同上，原指针hex 仅作核对
# 示例：
#   0x00368A00	仅改文本
#   0x00368998	确定清除列表吗？	0x003689CC
#   0x00368998	确定清除列表吗？	0x003689CC	CC9B364001000000

# 合并格式（4 列）：<地址>\t<中文>\t<键名列表>\t<排除槽列表>
#   例：0x0036DA50	删除	FvMenu_Delete,ExiToolCtl_Delete,CtxMenu_Delete,LibEditbox_CtxMenuDelete	0x003954F0,0x00396648,0x00390750,0x003D85B0
#   行为：先写字符串，再按键名搜槽，纯英文槽改指向新地址，日文槽和排除槽跳过

# 自动分配（地址写 0x????????）：脚本会在普通区释放的空位里自动找位置写中文
# 锚点范围由文件顶部 AUTO_ALLOC_ANCHOR_START / AUTO_ALLOC_ANCHOR_END 决定
# 分配要求：2 字节对齐，前 2 字节 \x00\x00，后 2 字节 \x00\x00，保证不与相邻字符串挤在一起
# 两种写法：
#   A) 键名列表形式：0x????????\t中文\t键名列表\t[排除槽列表]
#      例：0x????????	删除	FvMenu_Delete, ExiToolCtl_Delete	0x003954F0, 0x00396648
#   B) 原字符串偏移形式：0x????????\t中文\t原字符串偏移\t[原指针hex，仅核对]
#      例：0x????????	确定清除列表吗？	0x003689CC
#      行为：分配新地址写中文，再把所有指向 0x003689CC 的指针改到新地址

# 执行顺序（重要）：
#   1. 扫描（只判断不写）：按键名找到槽，is_english 判断，记录待写槽
#   2. 普通区：英文改中文，释放空间
#   3. 强制区：写 FORCE WRITE 的普通 0x 地址字符串
#   4. 自动分配：在锚点范围内找空位写中文，确定目标地址
#   5. 统一写入：把第 1 步记下的槽指向第 3/4 步确定的目标地址
#   6. 指针强写：按文件偏移直接覆盖 8 字节
# 这样 is_english 读到的一定是原始英文，判断永远有效，不会出现“指向空地址”的中间状态

# ===== POINTER FORCE =====
# 格式：<文件偏移>\t<8字节hex>\t[可选注释]
# 按文件偏移直接覆盖 8 字节，不经过 PE 计算，也不做用户 hex 核对。
0x003D20F0	50 ec 36 40 01 00 00 00
0x003D28F0	50 ec 36 40 01 00 00 00

# ===== AUTO POINTER UPDATE =====
# 格式：<键名字符串>\t<新文本物理地址>\t[可选：排除的槽偏移，多个用空格或逗号隔开]
# 原理：通过全局搜索键名字符串，定位其指针，+8字节即为显示文本槽，自动修改槽的指向。
# 与 FORCE WRITE 合并格式的区别：这里不写字符串，只改指针，目标地址由 FORCE WRITE 提供
FvMenu_Delete	0x0036DA50	0x003954F0 0x00396648
ExiToolCtl_Delete	0x0036DA60	0x00396648,0x003D85B0
"""

# ★ 说明：原 VA_OFFSET 变量已删除。段映射由 PEInfo 从 PE 头自动计算，
#   换版本无需手动维护，也不会因节顺序变化出错。

import argparse
import re
import struct
import subprocess
import sys
import time
from pathlib import Path


# ===== 命令行参数 =====
# 默认值即原硬编码值，加 --dry-run / --no-icon 用于调试和流水线跳过图标注入。
# --dry-run 语义：内存里照常执行所有写入，但不落盘、不调用 02。
#   这样日志、自动分配空位、地址与真实执行完全一致，便于排查。
#   切勿在每处 new_data[x:y]=... 前加 if not dry_run——那样自动分配找不到前面释放的
#   的空位，日志全是假的。
parser = argparse.ArgumentParser(description="SAI2 中文补丁应用脚本")
parser.add_argument('--new-file', default=new_file, help=f'输入 EXE（默认 {new_file}）')
parser.add_argument('--map',      default=map_file, help=f'映射表（默认 {map_file}）')
parser.add_argument('--out',      default=out_file, help=f'输出文件（默认 {out_file}）')
parser.add_argument('--log',      default=log_file, help=f'日志文件（默认 {log_file}）')
parser.add_argument('--dry-run',  action='store_true',
                    help='只扫描并打印日志，不写文件，也不调用 02')
parser.add_argument('--no-icon',  action='store_true',
                    help='跳过图标注入（02 脚本）')
args = parser.parse_args()

new_file = args.new_file
map_file = args.map
out_file = args.out
log_file = args.log


# ===== PE 解析：从 new.exe 自动算“文件偏移 → VA” =====
class PEInfo:
    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b'MZ':
            raise ValueError("不是 MZ 文件")
        e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
        if d[e_lfanew:e_lfanew+4] != b'PE\0\0':
            raise ValueError("不是 PE 文件")
        fh = e_lfanew + 4
        self.num_sections = struct.unpack_from('<H', d, fh + 2)[0]
        opt_size = struct.unpack_from('<H', d, fh + 16)[0]
        opt = fh + 20
        magic = struct.unpack_from('<H', d, opt)[0]
        if magic == 0x10B:          # PE32
            self.image_base = struct.unpack_from('<I', d, opt + 28)[0]
            self.pe32plus = False
        elif magic == 0x20B:        # PE32+
            self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
            self.pe32plus = True
        else:
            raise ValueError(f"未知 OptionalHeader Magic 0x{magic:X}")
        self.size_of_headers = struct.unpack_from('<I', d, opt + 60)[0]

        self.sections = []
        sh = opt + opt_size
        for i in range(self.num_sections):
            b = sh + i * 40
            name = d[b:b+8].rstrip(b'\0').decode('ascii', 'replace')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', d, b + 8)
            self.sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                                      rsize=rsize, rptr=rptr))

    def file_off_to_va(self, off):
        for s in self.sections:
            if s['rptr'] <= off < s['rptr'] + s['rsize']:
                rva = off - s['rptr'] + s['vaddr']
                return self.image_base + rva, s
        if off < self.size_of_headers:
            return self.image_base + off, dict(name='<headers>')
        raise ValueError(f"文件偏移 0x{off:X} 不在任何节内")

    # ===== 反向转换：从虚拟地址（VA）算出文件物理偏移 =====
    def va_to_file_off(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + s['rsize']:
                return s['rptr'] + (rva - s['vaddr'])
        return None


# ===== 非重叠搜索 =====
# 本脚本搜索的都是长 needle（完整 UTF-16 字符串 + \x00\x00 结束符，或 8 字节指针），
# 不可能发生重叠匹配；p + n 可减少无意义扫描。
def find_all_bytes(haystack, needle):
    if not needle:
        return []
    out, start = [], 0
    n = len(needle)
    while True:
        p = haystack.find(needle, start)
        if p < 0:
            break
        out.append(p)
        start = p + n
    return out


# ===== 判断匹配位置是否是独立的 UTF-16LE 字符串 =====
def is_standalone_wstr(data, pos, byte_len):
    """判断 data[pos:pos+byte_len] 是否是独立的 UTF-16LE 字符串。"""
    if pos >= 2:
        if data[pos-2:pos] != b'\x00\x00':
            return False
    end = pos + byte_len
    if end + 2 <= len(data):
        if data[end:end+2] != b'\x00\x00':
            return False
    return True


# ===== 读 UTF-16LE 字符串，返回含 \x00\x00 结束符的总字节数 =====
def read_wstr_total(data, off, max_scan=0x10000):
    """从 off 开始按 2 字节步长找 \x00\x00，返回含结束符的总字节数；找不到返回 None"""
    end = off
    limit = min(len(data), off + max_scan)
    while end + 1 < limit:
        if data[end] == 0 and data[end+1] == 0:
            return end + 2 - off
        end += 2
    return None


# ===== 描述文件偏移所在节和 VA（给指针强写日志用）=====
def describe_file_off(pe, off):
    try:
        va, sec = pe.file_off_to_va(off)
        return f"{sec['name']} VA=0x{va:X}"
    except Exception:
        return "非节内"


# ===== 通过 VA 读取字符串 =====
def get_string_by_va(pe, data, va):
    """通过 VA 找到文件偏移，然后读 UTF-16LE 字符串。
    若字符串为空或 VA 无效返回 None。
    1000 字符上限：截断后不影响 is_english 判断（UTF-16 定长 2 字节，不会切开多字节字符）。"""
    f_off = pe.va_to_file_off(va)
    if f_off is None or f_off >= len(data) - 1:
        return None
    chars = []
    i = f_off
    while i + 1 < len(data):
        code = data[i] | (data[i+1] << 8)
        if code == 0:
            break
        chars.append(chr(code))
        i += 2
        if len(chars) > 1000:
            break
    return ''.join(chars) if chars else None


# ===== 判断是否为纯英文 =====
# 放行 \t\n\r：SAI2 存在含换行的多行英文提示（如 "Specify ...\nON..."），
#   若不放行，遇到 \n 会返回 False 导致英文槽被误判为日文跳过。
# 其余控制字符（<0x20）与非 ASCII（>0x7E）仍拒绝。
def is_english(s):
    """用于 AUTO POINTER UPDATE 自动识别日文槽，避免误伤。"""
    if not s:
        return False
    for c in s:
        if c in '\t\n\r':
            continue
        o = ord(c)
        if o < 0x20 or o > 0x7E:
            return False
    return True


# ===== 搜索独立 UTF-16LE 字符串的文件偏移，作为自动分配范围的锚点 =====
def find_anchor_offset(data, text, label=""):
    """在 data 里搜索独立 UTF-16LE 字符串，返回文件偏移；找不到返回 None。
    多点命中时打印位置列表提醒（使用第一处），便于排查。"""
    text_bytes = text.encode('utf-16-le')
    needle = text_bytes + b'\x00\x00'
    offsets = find_all_bytes(data, needle)
    hits = [pos for pos in offsets if is_standalone_wstr(data, pos, len(text_bytes))]
    if not hits:
        return None
    if len(hits) > 1:
        preview = ', '.join(hex(p) for p in hits[:8])
        more = ' ...' if len(hits) > 8 else ''
        print(f"ℹ️ 锚点{label}多点命中（{len(hits)} 处）：{preview}{more} —— 使用第一处 0x{hits[0]:08X}")
    return hits[0]


# ===== 在指定范围内找连续 0 的空位（2 字节对齐，前后 \x00\x00 边界） =====
def find_free_space(data, start, end, size, align=2):
    """在 [start, end) 范围内找可写入的槽位。

    要求：
      - pos 2 字节对齐（非对齐时跳到下一个对齐位，不逐字节推进）
      - pos-2:pos 是 \\x00\\x00（前界）
      - pos:pos+size 全 0（可写入）
      - pos+size:pos+size+2 是 \\x00\\x00（后界）
      - 后界贴近文件末尾无法验证时，保守返回 None
    """
    needle = b'\x00' * size
    pos = start
    while True:
        pos = data.find(needle, pos, end)
        if pos < 0:
            return None
        if pos % align != 0:
            pos = (pos + align - 1) // align * align
            continue
        if pos < 2 or data[pos-2:pos] != b'\x00\x00':
            pos += 1
            continue
        post_end = pos + size
        if post_end + 2 > len(data):
            return None  # 末尾无法验证后界，保守放弃
        if data[post_end:post_end+2] != b'\x00\x00':
            pos += 1
            continue
        return pos


# ===== 读入 new.exe =====
with open(new_file, 'rb') as _f:
    new_data = bytearray(_f.read())
orig_size = len(new_data)

# ★ 载入 PE 头，打印每节 VA_OFFSET 供核对（换版本无需再手动找指针）
pe = PEInfo(new_data)
print(f"ImageBase = 0x{pe.image_base:X}")
for s in pe.sections:
    delta = pe.image_base + s['vaddr'] - s['rptr']
    print(f"  {s['name']:8s} VA=0x{s['vaddr']:08X} Raw=0x{s['rptr']:08X} "
          f"Size=0x{s['rsize']:X}  VA_OFFSET=0x{delta:X}")

# ===== 自动搜索自动分配范围的锚点 =====
# 空串校验：find_anchor_offset('') 会搜索裸 \x00\x00，结果不可控，必须拦住。
if not AUTO_ALLOC_ANCHOR_START or not AUTO_ALLOC_ANCHOR_END:
    print("⚠️ 锚点字符串为空，自动分配禁用")
    AUTO_ALLOC_START = AUTO_ALLOC_END = None
else:
    AUTO_ALLOC_START = find_anchor_offset(new_data, AUTO_ALLOC_ANCHOR_START, " START")
    AUTO_ALLOC_END   = find_anchor_offset(new_data, AUTO_ALLOC_ANCHOR_END,   " END")

auto_alloc_enabled = (
    AUTO_ALLOC_START is not None
    and AUTO_ALLOC_END is not None
    and AUTO_ALLOC_START < AUTO_ALLOC_END
)

if not auto_alloc_enabled:
    print("⚠️ 自动分配锚点搜索失败或范围异常，自动分配功能禁用")
    if AUTO_ALLOC_START is None:
        print(f"   找不到起始锚点: {AUTO_ALLOC_ANCHOR_START!r}")
    if AUTO_ALLOC_END is None:
        print(f"   找不到结尾锚点: {AUTO_ALLOC_ANCHOR_END!r}")
    if AUTO_ALLOC_START is not None and AUTO_ALLOC_END is not None and AUTO_ALLOC_START >= AUTO_ALLOC_END:
        print(f"   范围异常: START=0x{AUTO_ALLOC_START:08X} >= END=0x{AUTO_ALLOC_END:08X}")
else:
    print(f"✓ 自动分配范围: 0x{AUTO_ALLOC_START:08X} ~ 0x{AUTO_ALLOC_END:08X} "
          f"({AUTO_ALLOC_END - AUTO_ALLOC_START} 字节)")

pairs = []
forces = []
pointer_forces = []
auto_pointers = []
auto_alloc_entries = []

FORCE_MARK = "# ===== FORCE WRITE ====="
POINTER_FORCE_MARK = "# ===== POINTER FORCE ====="
AUTO_POINTER_MARK = "# ===== AUTO POINTER UPDATE ====="
in_force = False
in_pointer_force = False
in_auto_pointer = False

# ===== 读文件：自动去 BOM，统一行尾 =====
with open(map_file, 'r', encoding='utf-8-sig') as f:
    raw_text = f.read()

raw_text = raw_text.replace('\r\n', '\n').replace('\r', '\n')

for line in raw_text.split('\n'):
    if not line.strip():
        continue

    if line.strip() == FORCE_MARK:
        in_force = True
        in_pointer_force = False
        in_auto_pointer = False
        continue

    if line.strip() == POINTER_FORCE_MARK:
        in_pointer_force = True
        in_force = False
        in_auto_pointer = False
        continue

    if line.strip() == AUTO_POINTER_MARK:
        in_auto_pointer = True
        in_force = False
        in_pointer_force = False
        continue

    stripped = line.lstrip()
    if stripped.startswith('#') or stripped.startswith('//'):
        continue

    # ===== 自动指针寻址区 =====
    if in_auto_pointer:
        p = [x for x in line.split('\t') if x.strip()]
        if len(p) < 2:
            print(f"⚠️ 自动寻址行列数不足，跳过: {line!r}")
            continue
        try:
            key_name = p[0].strip()
            target_off = int(p[1].strip(), 16)
            exclusions = set()
            if len(p) >= 3 and p[2].strip():
                parts = p[2].replace(',', ' ').split()
                for x in parts:
                    exclusions.add(int(x.strip(), 16))
            auto_pointers.append(dict(key=key_name, target_off=target_off, exclusions=exclusions))
        except Exception as e:
            print(f"⚠️ 自动寻址行解析失败: {line!r} ({e})")
        continue

    # ===== 指针强写区 =====
    if in_pointer_force:
        p = [x for x in line.split('\t') if x.strip()]
        if len(p) < 2:
            print(f"⚠️ 指针强写行列数不足，跳过: {line!r}")
            continue
        try:
            off = int(p[0].strip(), 16)
            hx = p[1].strip().replace(' ', '')
            if len(hx) != 16:
                raise ValueError(f"指针 hex 必须 16 字符(8字节)，实际 {len(hx)}: {hx!r}")
            val = bytes.fromhex(hx)
            comment = p[2].strip() if len(p) >= 3 else ''
            pointer_forces.append(dict(off=off, val=val, comment=comment))
        except Exception as e:
            print(f"⚠️ 指针强写行解析失败: {line!r} ({e})")
        continue

    # ===== 强制区 =====
    if in_force:
        p = [x for x in line.split('\t') if x.strip()]
        if len(p) < 2:
            continue
        try:
            addr_str = p[0].strip()
            cn = p[1].replace('\\n', '\n')

            # 【自动分配】地址写 0x????????，由脚本在锚点范围内找空位
            if '?' in addr_str:
                col3 = p[2].strip() if len(p) >= 3 else ''
                col4 = p[3].strip() if len(p) >= 4 else ''

                # 判断第三列是「原字符串偏移」还是「键名列表」
                is_orig_off = bool(col3) and bool(re.match(r'^0x[0-9A-Fa-f]+$', col3))

                if is_orig_off:
                    # 类型 B：自动分配 + 改指向原字符串的指针
                    orig_str_off = int(col3, 16)
                    orig_ptr_bytes = None
                    if col4:
                        hx = col4.replace(' ', '')
                        if len(hx) == 16:
                            orig_ptr_bytes = bytes.fromhex(hx)
                        else:
                            print(f"⚠️ 自动分配(指针模式) 4列 hex 长度异常，忽略核对: {col4!r}")
                    entry = dict(kind='ptr', cn=cn, orig_str_off=orig_str_off,
                                 orig_ptr_bytes=orig_ptr_bytes)
                    auto_alloc_entries.append(entry)
                    print(f"✓ 自动分配(指针模式): '{cn}' → 原字符串 0x{orig_str_off:08X}")
                    continue

                # 类型 A：键名列表
                key_list = [x.strip() for x in col3.replace(', ', ',').split(',') if x.strip()]
                excl_set = set()
                if col4:
                    for x in col4.replace(', ', ',').split(','):
                        x = x.strip()
                        if x:
                            try:
                                excl_set.add(int(x, 16))
                            except ValueError:
                                print(f"⚠️ 自动分配排除地址解析失败: {x!r}")

                entry = dict(kind='keys', cn=cn, key_list=key_list, excl_set=excl_set,
                             auto_ptr_indices=[])
                for key in key_list:
                    idx = len(auto_pointers)
                    auto_pointers.append(dict(key=key, target_off=None, exclusions=excl_set))
                    entry['auto_ptr_indices'].append(idx)
                auto_alloc_entries.append(entry)
                print(f"✓ 自动分配: '{cn}' → {len(key_list)} 键名, {len(excl_set)} 排除")
                continue

            # 普通 0x 地址
            new_str_off = int(addr_str, 16)
            col3 = p[2].strip() if len(p) >= 3 else ''
            col4 = p[3].strip() if len(p) >= 4 else ''

            is_merged = bool(col3) and not re.match(r'^0x[0-9A-Fa-f]+$', col3)

            if is_merged:
                # 合并格式：地址 \t 中文 \t 键名列表 \t 排除槽列表
                key_list = [x.strip() for x in col3.replace(', ', ',').split(',') if x.strip()]
                excl_set = set()
                if col4:
                    for x in col4.replace(', ', ',').split(','):
                        x = x.strip()
                        if x:
                            try:
                                excl_set.add(int(x, 16))
                            except ValueError:
                                print(f"⚠️ 合并格式排除地址解析失败: {x!r}")

                forces.append(dict(mode='str_only', new_str_off=new_str_off, cn=cn))
                for key in key_list:
                    auto_pointers.append(dict(key=key, target_off=new_str_off, exclusions=excl_set))
                print(f"✓ 合并格式: 0x{new_str_off:08X} '{cn}' → {len(key_list)} 键名, {len(excl_set)} 排除")

            elif len(p) >= 4 and col3 and col4:
                # 原 4 列
                orig_str_off = int(col3, 16)
                hx = col4.replace(' ', '')
                if len(hx) != 16:
                    raise ValueError(f"指针 hex 必须 16 字符(8字节)，实际 {len(hx)}: {hx!r}")
                forces.append(dict(mode='auto', new_str_off=new_str_off, cn=cn,
                                   orig_str_off=orig_str_off,
                                   orig_ptr_bytes=bytes.fromhex(hx)))
            elif len(p) >= 3 and col3:
                # 原 3 列
                orig_str_off = int(col3, 16)
                forces.append(dict(mode='auto', new_str_off=new_str_off, cn=cn,
                                   orig_str_off=orig_str_off, orig_ptr_bytes=None))
            else:
                # 原 2 列
                forces.append(dict(mode='str_only', new_str_off=new_str_off, cn=cn))
        except Exception as e:
            print(f"⚠️ 强制行解析失败: {line!r} ({e})")
        continue

    # ===== 普通区 =====
    p = [x for x in line.split('\t') if x.strip()]
    n = len(p)
    if n < 3:
        continue
    if (n - 1) % 2 != 0:
        print(f"⚠️ 列数异常，跳过: {line[:80]!r}")
        continue

    half = (n - 1) // 2
    try:
        off = int(p[0].strip(), 16)
        en = '\t'.join(p[1:1+half]).replace('\\n', '\n')
        cn = '\t'.join(p[1+half:]).replace('\\n', '\n')
        pairs.append((off, en, cn))
    except Exception as e:
        print(f"⚠️ 普通行解析失败: {line[:80]!r} ({e})")

print(f"普通名单: {len(pairs)} 对")
print(f"强制名单: {len(forces)} 对")
print(f"指针强写名单: {len(pointer_forces)} 条")
print(f"自动寻址名单: {len(auto_pointers)} 条（AUTO POINTER UPDATE 区 + FORCE WRITE 合并格式）")
print(f"自动分配条目: {len(auto_alloc_entries)} 条")

# ===== 第一步：自动指针寻址扫描（只判断，不写）=====
pending_writes = []
scan_log = []

_t_scan_start = time.perf_counter()

for idx, item in enumerate(auto_pointers):
    key_name = item['key']
    target_off = item['target_off']
    exclusions = item['exclusions']

    anchor_bytes = key_name.encode('utf-16-le') + b'\x00\x00'
    key_offsets = find_all_bytes(new_data, anchor_bytes)

    if not key_offsets:
        line = f"❌\t扫描: 找不到键名字符串 {key_name}"
        print(line); scan_log.append(line)
        continue

    found_any = False
    skipped_count = 0
    for k_off in key_offsets:
        try:
            key_va, _ = pe.file_off_to_va(k_off)
        except Exception:
            continue

        key_ptr_bytes = key_va.to_bytes(8, 'little')
        ptr_offsets = find_all_bytes(new_data, key_ptr_bytes)

        for ptr_off in ptr_offsets:
            slot_off = ptr_off + 8

            if slot_off in exclusions:
                line = f"ℹ️\t扫描: {key_name} -> 槽 0x{slot_off:08X} 已被配置排除"
                print(line); scan_log.append(line)
                skipped_count += 1
                continue

            old_val = bytes(new_data[slot_off:slot_off+8])
            old_va = int.from_bytes(old_val, 'little')

            old_str = get_string_by_va(pe, new_data, old_va)

            # 空/无效 VA 单独处理：语义上"槽没东西可改"，不是"日文槽"，跳过
            if old_str is None:
                line = f"ℹ️\t扫描: {key_name} -> 槽 0x{slot_off:08X} 指向空/无效 VA 0x{old_va:X}，跳过"
                print(line); scan_log.append(line)
                skipped_count += 1
                continue

            # 非纯英文（日文/中文等）：不覆盖用户已有翻译，跳过
            if not is_english(old_str):
                display_str = old_str if len(old_str) <= 30 else old_str[:30] + "..."
                line = f"ℹ️\t扫描: {key_name} -> 槽 0x{slot_off:08X} 指向非纯英文 '{display_str}'"
                print(line); scan_log.append(line)
                skipped_count += 1
                continue

            pending_writes.append(dict(
                auto_ptr_idx=idx,
                slot_off=slot_off,
                old_val=old_val,
                old_va=old_va,
                key_name=key_name,
            ))
            desc = describe_file_off(pe, slot_off)
            line = (f"✅\t扫描: {key_name} -> 槽 0x{slot_off:08X} ({desc}): "
                    f"纯英文，目标 VA 0x{old_va:X}，待写入")
            print(line); scan_log.append(line)
            found_any = True

    if not found_any and skipped_count == 0:
        line = f"⚠️\t扫描: 找到了 {key_name} 字符串，但未找到指向它的结构指针"
        print(line); scan_log.append(line)

_t_scan_elapsed = time.perf_counter() - _t_scan_start

print(f"\n待写入指针: {len(pending_writes)} 条")
print(f"[计时] 扫描阶段: {_t_scan_elapsed*1000:.1f} ms")

# ===== 第二步：普通名单 =====
success = 0
skip_long = 0
not_found = 0
skip_list = []
notfound_list = []

for off, en_s, cn_s in pairs:
    en_bytes = en_s.encode('utf-16-le')
    cn_bytes = cn_s.encode('utf-16-le')

    if off + len(en_bytes) <= len(new_data) and bytes(new_data[off:off+len(en_bytes)]) == en_bytes:
        pos = off
    else:
        all_pos = find_all_bytes(new_data, en_bytes)
        valid = [p for p in all_pos if is_standalone_wstr(new_data, p, len(en_bytes))]
        if not valid:
            if all_pos:
                print(f"⚠️ 0x{off:08X} {en_s!r}: 找到 {len(all_pos)} 处但均非独立字符串，跳过")
            not_found += 1
            notfound_list.append((off, en_s, cn_s))
            continue
        pos = min(valid, key=lambda p: abs(p - off)) if len(valid) > 1 else valid[0]

    if len(cn_bytes) <= len(en_bytes):
        new_data[pos:pos+len(cn_bytes)] = cn_bytes
        for k in range(len(cn_bytes), len(en_bytes)):
            new_data[pos+k] = 0
        success += 1
    else:
        skip_long += 1
        skip_list.append((off, en_s, cn_s, len(en_bytes), len(cn_bytes)))

# ===== 第三步：强制名单（普通 0x 地址）=====
force_log = []
for f in forces:
    new_str_off = f['new_str_off']
    cn = f['cn']
    cn_bytes = cn.encode('utf-16-le') + b'\x00\x00'

    if new_str_off + len(cn_bytes) > len(new_data):
        line = f"❌\t0x{new_str_off:08X}: 越界"
        print(line); force_log.append(line)
        continue

    orig_space = read_wstr_total(new_data, new_str_off)
    if orig_space is None:
        line = f"❌\t0x{new_str_off:08X}: 找不到 \\x00\\x00 结束符，跳过"
        print(line); force_log.append(line)
        continue

    need = len(cn_bytes)
    if need <= orig_space:
        force_log.append(f"✓\t空间 0x{new_str_off:08X}: 原 {orig_space}B ≥ 新 {need}B")
    else:
        region = bytes(new_data[new_str_off:new_str_off+need])
        ext = region[orig_space:]
        if all(b == 0 for b in ext):
            force_log.append(f"✓\t空间 0x{new_str_off:08X}: 原 {orig_space}B → 扩展至 {need}B，扩展区全为 0")
        else:
            first_nz = orig_space + next(i for i, b in enumerate(ext) if b != 0)
            snip_start = max(orig_space, first_nz - 8)
            snip = region[snip_start:first_nz + 8]
            line = (f"❌\t0x{new_str_off:08X}: 新串 {need}B > 原空间 {orig_space}B，"
                    f"扩展区 +0x{first_nz:X} 处有非 0 数据，跳过!\n"
                    f"\t附近字节: {snip.hex(' ')}")
            print(line); force_log.append(line)
            continue

    old_ptr_bytes = new_ptr_bytes = None
    matches = []
    new_va = None
    if f['mode'] == 'auto':
        try:
            old_va, sec_old = pe.file_off_to_va(f['orig_str_off'])
            new_va, sec_new = pe.file_off_to_va(new_str_off)
        except Exception as e:
            line = f"❌\t0x{new_str_off:08X}: PE 计算失败 {e}"
            print(line); force_log.append(line)
            continue

        old_ptr_bytes = old_va.to_bytes(8, 'little')
        new_ptr_bytes = new_va.to_bytes(8, 'little')

        if f['orig_ptr_bytes'] is not None and f['orig_ptr_bytes'] != old_ptr_bytes:
            line = f"⚠️\t0x{f['orig_str_off']:08X}: 用户 hex 与 PE 不一致，以 PE 为准"
            print(line); force_log.append(line)

        matches = find_all_bytes(new_data, old_ptr_bytes)

        force_log.append(f"🔎\t原 0x{f['orig_str_off']:08X} → VA 0x{old_va:X} [{old_ptr_bytes.hex(' ')}]")
        force_log.append(f"\t新 0x{new_str_off:08X} → VA 0x{new_va:X} [{new_ptr_bytes.hex(' ')}]")
        force_log.append(f"\t命中 {len(matches)} 处: {[hex(m) for m in matches]}")

    show_len = min(40, orig_space)
    orig_hex = bytes(new_data[new_str_off:new_str_off+show_len]).hex(' ')

    new_data[new_str_off:new_str_off+len(cn_bytes)] = cn_bytes
    line = f"✅\t字符串 0x{new_str_off:08X}: {cn!r} ({len(cn_bytes)}B)"
    print(line); force_log.append(line)
    force_log.append(f"\t原: {orig_hex}")

    if f['mode'] == 'auto':
        if not matches:
            line = f"❌\t找不到旧指针 {old_ptr_bytes.hex()}，指针未改"
            print(line); force_log.append(line)
        else:
            for pos in matches:
                old = bytes(new_data[pos:pos+8])
                new_data[pos:pos+8] = new_ptr_bytes
                try:
                    slot_va, slot_sec = pe.file_off_to_va(pos)
                    slot_desc = f"槽VA 0x{slot_va:X} {slot_sec['name']}"
                except Exception:
                    slot_desc = "槽VA 未知"
                line = (f"✅\t指针 0x{pos:08X} [{slot_desc}]: {old.hex(' ')} → "
                        f"{new_ptr_bytes.hex(' ')} (目标 VA 0x{new_va:X})")
                print(line); force_log.append(line)

# ===== 第四步：自动分配 0x???????? 的空位并写入 =====
alloc_log = []
if not auto_alloc_enabled and auto_alloc_entries:
    line = f"⚠️\t自动分配: 锚点搜索失败，跳过 {len(auto_alloc_entries)} 条自动分配条目"
    print(line); alloc_log.append(line)
else:
    for entry in auto_alloc_entries:
        cn = entry['cn']
        cn_bytes = cn.encode('utf-16-le') + b'\x00\x00'
        need = len(cn_bytes)

        alloc_off = find_free_space(new_data, AUTO_ALLOC_START, AUTO_ALLOC_END, need, align=2)
        if alloc_off is None:
            line = (f"❌\t自动分配: '{cn}' ({need}B) 在 "
                    f"0x{AUTO_ALLOC_START:08X} ~ 0x{AUTO_ALLOC_END:08X} 内找不到连续空白")
            print(line); alloc_log.append(line)
            continue

        try:
            alloc_va, sec = pe.file_off_to_va(alloc_off)
        except Exception as e:
            line = f"❌\t自动分配: 0x{alloc_off:08X} 算 VA 失败 {e}"
            print(line); alloc_log.append(line)
            continue

        new_data[alloc_off:alloc_off+need] = cn_bytes
        entry['alloc_off'] = alloc_off
        entry['alloc_va'] = alloc_va
        entry['alloc_sec'] = sec

        if entry['kind'] == 'keys':
            for idx in entry['auto_ptr_indices']:
                auto_pointers[idx]['target_off'] = alloc_off

        line = (f"🆕\t自动分配({entry['kind']}): '{cn}' ({need}B) → 文件 0x{alloc_off:08X} "
                f"({sec['name']} VA=0x{alloc_va:X})")
        print(line); alloc_log.append(line)

# ===== 第五步：统一写入指针 =====
write_log = []

# 5a. pending_writes（键名模式）
# 若槽已指向目标（合并格式的常见情况），记录为 ℹ️ 而不是 ✅，避免误读为"改了但没变"
for w in pending_writes:
    idx = w['auto_ptr_idx']
    slot_off = w['slot_off']
    old_val = w['old_val']
    old_va = w['old_va']
    key_name = w['key_name']

    ap = auto_pointers[idx]
    target_off = ap['target_off']
    if target_off is None:
        line = f"⚠️\t写入: {key_name} -> 槽 0x{slot_off:08X} 目标地址未确定，跳过"
        print(line); write_log.append(line)
        continue

    try:
        target_va, _ = pe.file_off_to_va(target_off)
        target_ptr_bytes = target_va.to_bytes(8, 'little')
    except Exception as e:
        line = f"❌\t写入: {key_name} -> 槽 0x{slot_off:08X} 目标 0x{target_off:X} 算 VA 失败 {e}"
        print(line); write_log.append(line)
        continue

    new_data[slot_off:slot_off+8] = target_ptr_bytes
    desc = describe_file_off(pe, slot_off)
    if old_val == target_ptr_bytes:
        line = (f"ℹ️\t写入: {key_name} -> 槽 0x{slot_off:08X} ({desc}): "
                f"已指向目标 VA 0x{target_va:X}，无需修改")
    else:
        line = (f"✅\t写入: {key_name} -> 槽 0x{slot_off:08X} ({desc}): "
                f"目标 VA 0x{old_va:X} → 0x{target_va:X}\n"
                f"\t字节: {old_val.hex(' ')} → {target_ptr_bytes.hex(' ')}")
    print(line); write_log.append(line)

# 5b. auto_alloc_entries 的 ptr 模式
# 同样区分 no-op 与实际修改
for entry in auto_alloc_entries:
    if entry['kind'] != 'ptr':
        continue
    if 'alloc_off' not in entry:
        line = f"⚠️\t写入(指针): '{entry['cn']}' 未分配地址，跳过"
        print(line); write_log.append(line)
        continue

    orig_str_off = entry['orig_str_off']
    try:
        old_va, sec_old = pe.file_off_to_va(orig_str_off)
    except Exception as e:
        line = f"❌\t写入(指针): 原字符串 0x{orig_str_off:08X} 算 VA 失败 {e}"
        print(line); write_log.append(line)
        continue

    old_ptr_bytes = old_va.to_bytes(8, 'little')
    if entry['orig_ptr_bytes'] is not None and entry['orig_ptr_bytes'] != old_ptr_bytes:
        line = (f"⚠️\t写入(指针): 用户 hex {entry['orig_ptr_bytes'].hex()} "
                f"与 PE 算出 {old_ptr_bytes.hex()} 不一致，以 PE 为准")
        print(line); write_log.append(line)

    new_ptr_bytes = entry['alloc_va'].to_bytes(8, 'little')
    matches = find_all_bytes(new_data, old_ptr_bytes)
    if not matches:
        line = f"❌\t写入(指针): '{entry['cn']}' 找不到旧指针 {old_ptr_bytes.hex()}"
        print(line); write_log.append(line)
        continue

    for pos in matches:
        old = bytes(new_data[pos:pos+8])
        new_data[pos:pos+8] = new_ptr_bytes
        try:
            slot_va, slot_sec = pe.file_off_to_va(pos)
            slot_desc = f"槽VA 0x{slot_va:X} {slot_sec['name']}"
        except Exception:
            slot_desc = "槽VA 未知"
        if old == new_ptr_bytes:
            line = (f"ℹ️\t写入(指针): '{entry['cn']}' 槽 0x{pos:08X} [{slot_desc}]: "
                    f"已指向目标 VA 0x{entry['alloc_va']:X}，无需修改")
        else:
            line = (f"✅\t写入(指针): '{entry['cn']}' 槽 0x{pos:08X} [{slot_desc}]: "
                    f"目标 VA 0x{old_va:X} → 0x{entry['alloc_va']:X}\n"
                    f"\t字节: {old.hex(' ')} → {new_ptr_bytes.hex(' ')}")
        print(line); write_log.append(line)

# ===== 第六步：指针强写 =====
ptr_log = []
for item in pointer_forces:
    off = item['off']
    val = item['val']
    comment = item['comment']

    if off + 8 > len(new_data):
        line = f"❌\t指针强写 0x{off:08X}: 越界 (文件大小 0x{len(new_data):X})"
        print(line); ptr_log.append(line)
        continue

    old = bytes(new_data[off:off+8])
    desc = describe_file_off(pe, off)
    new_data[off:off+8] = val

    if old == val:
        line = (f"ℹ️\t指针强写 0x{off:08X} ({desc}): "
                f"{old.hex(' ')} == {val.hex(' ')}  (原值与新值相同)")
    else:
        line = (f"✅\t指针强写 0x{off:08X} ({desc}): "
                f"{old.hex(' ')} → {val.hex(' ')}")
    if comment:
        line += f"  # {comment}"
    print(line); ptr_log.append(line)

# ===== 写日志 =====
with open(log_file, 'w', encoding='utf-8') as f:
    f.write(f"=== 普通: 成功 {success}, 跳过 {skip_long}, 未找到 {not_found} ===\n\n")
    for off, en_s, cn_s, en_len, cn_len in skip_list:
        f.write(f"跳过 0x{off:08X}\t英({en_len}B): {en_s!r}\t中({cn_len}B): {cn_s!r}\n")
    for off, en_s, cn_s in notfound_list:
        f.write(f"未找到 0x{off:08X}\t{en_s!r}\n")
    f.write(f"\n=== 强制 {len(forces)} 条 ===\n\n")
    for line in force_log:
        f.write(line + '\n')
    f.write(f"\n=== 扫描 {len(auto_pointers)} 条 ===\n\n")
    for line in scan_log:
        f.write(line + '\n')
    f.write(f"\n=== 自动分配 {len(auto_alloc_entries)} 条 ===\n\n")
    for line in alloc_log:
        f.write(line + '\n')
    f.write(f"\n=== 写入 {len(pending_writes) + len([e for e in auto_alloc_entries if e['kind']=='ptr'])} 条 ===\n\n")
    for line in write_log:
        f.write(line + '\n')
    f.write(f"\n=== 指针强写 {len(pointer_forces)} 条 ===\n\n")
    for line in ptr_log:
        f.write(line + '\n')

print(f"\n普通: 成功 {success}, 跳过 {skip_long}, 未找到 {not_found}")
print(f"强制: {len(forces)} 条")
print(f"扫描: {len(pending_writes)} 条待写入")
print(f"自动分配: {len(auto_alloc_entries)} 条")
print(f"指针强写: {len(pointer_forces)} 条")
print(f"日志: {log_file}")

# 文件大小断言：本脚本只做原地补丁，绝不改变文件大小
# 若普通区逻辑将来被改动导致扩容，此断言会立即报错，避免生成损坏的 PE
assert len(new_data) == orig_size, f"文件大小变化: {orig_size} → {len(new_data)}"

# ===== 输出与图标注入 =====
# --dry-run：内存里照常执行所有写入（上面所有步骤都跑了），但不落盘、不调 02。
#            这样日志、自动分配空位、地址与真实执行完全一致，便于排查。
# --no-icon：只跳过 02 图标注入，仍然生成 Temp.exe。
if args.dry_run:
    print(f"[dry-run] 不写 {out_file}，也不调用 02")
else:
    with open(out_file, 'wb') as f:
        f.write(new_data)
    print(f"输出: {out_file}")

    if args.no_icon:
        print("[2/2] --no-icon: 跳过图标注入")
    else:
        print("[2/2] 正在执行图标注入脚本...")
        _script_dir = Path(__file__).resolve().parent
        _inject_script = _script_dir / "02.inject_rc图标_ctypes.py"
        try:
            subprocess.run([sys.executable, str(_inject_script)],
                           check=True, cwd=_script_dir)
        except subprocess.CalledProcessError as e:
            print(f"[-] 图标注入返回码 {e.returncode}")
            input("按回车键退出...")
        except FileNotFoundError:
            print(f"[-] 找不到注入脚本: {_inject_script}")
            input("按回车键退出...")
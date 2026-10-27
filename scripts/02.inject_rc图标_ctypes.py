import ctypes
from ctypes import wintypes
import struct
import shutil
import os

# ==========================================
# ★ 严格对应你的 .rc 文件和目录结构 ★
# ==========================================
INPUT_EXE = "Temp.exe"
OUTPUT_EXE = "sai2.exe"

ICONS = {
    "MAINICON": r"图标\MAINICON.ico",
    "SAI": r"图标\SAI.ico",
    "SAI2-FILE": r"图标\SAI2-FILE.ico"
}

# Win32 API 定义
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

BeginUpdateResourceW = kernel32.BeginUpdateResourceW
BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
BeginUpdateResourceW.restype = wintypes.HANDLE

UpdateResourceW = kernel32.UpdateResourceW
UpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.WORD, wintypes.LPVOID, wintypes.DWORD]
UpdateResourceW.restype = wintypes.BOOL

EndUpdateResourceW = kernel32.EndUpdateResourceW
EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
EndUpdateResourceW.restype = wintypes.BOOL

def MAKEINTRESOURCE(i):
    return ctypes.cast(ctypes.c_void_p(i), wintypes.LPCWSTR)

def inject_single_ico(h_update, ico_path, group_name, icon_start_id):
    with open(ico_path, 'rb') as f:
        ico_data = f.read()

    # 1. 解析 .ico 头部
    reserved, ico_type, count = struct.unpack_from('<HHH', ico_data, 0)
    if reserved != 0 or ico_type != 1:
        print(f"[-] {ico_path} 不是有效的 .ico 文件！")
        return False, icon_start_id

    group_entries = bytearray()
    
    # 2. 注入每个尺寸的像素数据 (RT_ICON = 3)
    for i in range(count):
        offset = 6 + i * 16
        width, height, color_count, reserved2, planes, bit_count, data_size, data_offset = struct.unpack_from('<BBBBHHII', ico_data, offset)
        
        icon_data = ico_data[data_offset : data_offset + data_size]
        
        lpType = MAKEINTRESOURCE(3)
        lpName = MAKEINTRESOURCE(icon_start_id + i) 
        
        # 语言填 0 (LANG_NEUTRAL)，如果失败则尝试 1033
        if not UpdateResourceW(h_update, lpType, lpName, 0, icon_data, data_size):
            if not UpdateResourceW(h_update, lpType, lpName, 1033, icon_data, data_size):
                print(f"[-] 注入 RT_ICON 失败 (尺寸: {width}x{height}, Err: {ctypes.get_last_error()})")
                return False, icon_start_id
            
        entry = struct.pack('<BBBBHHIH', width, height, color_count, reserved2, planes, bit_count, data_size, icon_start_id + i)
        group_entries.extend(entry)

    # 3. 构建 GRPICONDIR
    grp_icon_data = struct.pack('<HHH', 0, 1, count) + group_entries

    # 4. 注入图标组 (RT_GROUP_ICON = 14，使用字符串名称)
    lpType = MAKEINTRESOURCE(14)
    lpName = ctypes.c_wchar_p(group_name)
    
    if not UpdateResourceW(h_update, lpType, lpName, 0, grp_icon_data, len(grp_icon_data)):
        if not UpdateResourceW(h_update, lpType, lpName, 1033, grp_icon_data, len(grp_icon_data)):
            print(f"[-] 注入图标组 {group_name} 失败 (Err: {ctypes.get_last_error()})")
            return False, icon_start_id

    print(f"    [+] 成功注入图标组: {group_name} (包含 {count} 个尺寸)")
    return True, icon_start_id + count

def main():
    if not os.path.exists(INPUT_EXE):
        print(f"[-] 找不到 {INPUT_EXE}，请先运行 apply_cn.py 生成它。")
        return

    print(f"[*] 正在拷贝 {INPUT_EXE} -> {OUTPUT_EXE}")
    shutil.copy2(INPUT_EXE, OUTPUT_EXE)

    h_update = BeginUpdateResourceW(OUTPUT_EXE, False)
    if not h_update:
        print("[-] 无法打开资源句柄")
        return

    current_icon_id = 1
    for group_name, ico_file in ICONS.items():
        if not os.path.exists(ico_file):
            print(f"[-] 找不到图标文件 {ico_file}，跳过。")
            continue
            
        print(f"[*] 正在处理 {group_name} ({ico_file}) ...")
        success, current_icon_id = inject_single_ico(h_update, ico_file, group_name, current_icon_id)
        if not success:
            EndUpdateResourceW(h_update, True)
            return

    if EndUpdateResourceW(h_update, False):
        print(f"\n[+] 所有图标注入成功！已保存至 {OUTPUT_EXE}")
        try:
            os.remove(INPUT_EXE)
            print(f"[*] 已删除临时文件: {INPUT_EXE}")
        except Exception:
            pass
    else:
        print("[-] 提交修改失败")

if __name__ == '__main__':
    main()
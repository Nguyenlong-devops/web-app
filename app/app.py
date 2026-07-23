import os
import json
import base64
import csv
import io
import time
import secrets
import threading
import psycopg2
import paramiko
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session
from ldap3 import Server, Connection, ALL
import socket

app = Flask(__name__)

# ── Secret key: PHẢI lấy từ biến môi trường, không hard-code trong source ──
# (session Flask mặc định ký ở client — ai có key này có thể tự tạo cookie is_admin=True
# cho bất kỳ username nào, bỏ qua hoàn toàn xác thực AD). Nếu chưa set biến môi trường
# FLASK_SECRET_KEY, dùng tạm 1 key ngẫu nhiên sinh ra khi khởi động (session sẽ mất khi
# restart app — nên set FLASK_SECRET_KEY cố định trong production qua .env/docker secret).
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('FLASK_SECRET_KEY'):
    print("[WARNING] FLASK_SECRET_KEY chưa được set qua biến môi trường — đang dùng key "
          "ngẫu nhiên tạm thời, mọi session sẽ bị đăng xuất khi restart app. Nên set "
          "FLASK_SECRET_KEY cố định (vd: python -c \"import secrets; print(secrets.token_hex(32))\").")

# ── Tự động đăng xuất sau 5 phút không thao tác (đề phòng quên logout / tắt web) ──
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # mỗi request mới sẽ "làm mới" thời hạn 5 phút
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'       # giảm rủi ro CSRF cho cookie session
# Nếu web đã chạy sau HTTPS, nên bật thêm dòng dưới để trình duyệt chỉ gửi cookie qua kết nối mã hoá:
# app.config['SESSION_COOKIE_SECURE'] = True

@app.before_request
def _enforce_idle_session_timeout():
    session.permanent = True  # bắt buộc áp dụng PERMANENT_SESSION_LIFETIME ở trên cho mọi session

# ── CSRF protection: mọi request POST/PUT/PATCH/DELETE của user đã đăng nhập phải kèm đúng
# csrf_token của session đó (qua header X-CSRF-Token — tự động gắn bởi JS ở index.html — hoặc
# qua field 'csrf_token' cho 1 số form submit thẳng không qua fetch). Nếu chưa đăng nhập thì bỏ
# qua bước này, để các decorator login_required/admin_required của từng route tự xử lý (tránh
# lộ thông tin CSRF token không cần thiết trên các request công khai).
_CSRF_EXEMPT_PATHS = {'/login', '/connect-domain', '/disconnect-domain'}

@app.before_request
def _csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    if request.path in _CSRF_EXEMPT_PATHS:
        return
    session_token = session.get('csrf_token')
    if not session_token:
        return  # chưa đăng nhập -> để login_required/admin_required của route xử lý
    sent_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not sent_token and request.is_json:
        body = request.get_json(silent=True) or {}
        sent_token = body.get('csrf_token')
    if not sent_token or sent_token != session_token:
        return jsonify({
            "status": "error",
            "message": "Phiên làm việc đã hết hạn hoặc không hợp lệ (CSRF token sai). Vui lòng tải lại trang rồi thử lại."
        }), 403

app.config['JSON_AS_ASCII'] = False
@app.before_request
def fix_jinja_encoding():
    app.jinja_env.policies['json.dumps_kwargs'] = {'ensure_ascii': False}

def _dn_to_ou_path(dn: str) -> str:
    """Rút gọn 1 DistinguishedName thành đường dẫn OU dễ đọc, bỏ phần CN đối tượng lá và
    các DC=... — ví dụ 'CN=HANHCHINH,OU=GROUP,OU=PV,DC=pv,DC=local' -> 'PV › GROUP'.
    Trả về tên container (vd 'Users') nếu group nằm ngay dưới container hệ thống đó."""
    if not dn:
        return '—'
    parts = [p.strip() for p in dn.split(',')]
    ou_parts = [p.split('=', 1)[1] for p in parts if p.upper().startswith('OU=')]
    if ou_parts:
        return ' › '.join(reversed(ou_parts))
    container_parts = [p.split('=', 1)[1] for p in parts[1:] if p.upper().startswith('CN=')]
    return container_parts[0] if container_parts else '—'

app.jinja_env.filters['dn_to_ou'] = _dn_to_ou_path

# ─────────────────────────────────────────────
#  DB helpers
# ─────────────────────────────────────────────
def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'db'),
        database=os.environ.get('DB_NAME', 'it_dashboard'),
        user=os.environ.get('DB_USER', 'postgres'),
        password=os.environ.get('DB_PASS', 'AureoleIT@2026'),
        options='-c timezone=Asia/Ho_Chi_Minh'  # hiển thị mọi TIMESTAMPTZ (audit log, ...) theo giờ VN (+7)
    )

def init_db():
    """Khởi tạo tất cả bảng và constraint cần thiết.
    Mỗi bước dùng transaction riêng để lỗi một bước không ảnh hưởng bước khác."""

    steps = [
        # 1. Bảng software_inventory
        """CREATE TABLE IF NOT EXISTS software_inventory (
            id              SERIAL PRIMARY KEY,
            software_key    VARCHAR(255) NOT NULL UNIQUE,
            software_name   VARCHAR(255) NOT NULL,
            total_licenses  INTEGER NOT NULL DEFAULT 0,
            used_licenses   INTEGER NOT NULL DEFAULT 0
        )""",

        # 2. Bảng user_software
        """CREATE TABLE IF NOT EXISTS user_software (
            id               SERIAL PRIMARY KEY,
            sam_account_name VARCHAR(128) NOT NULL,
            software_key     VARCHAR(255) NOT NULL,
            quantity         INTEGER NOT NULL DEFAULT 1,
            assigned_at      TIMESTAMPTZ DEFAULT NOW()
        )""",

        # 3. UNIQUE constraint trên user_software (cần cho ON CONFLICT)
        """DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'uq_user_software_user_key'
            ) THEN
                ALTER TABLE user_software
                ADD CONSTRAINT uq_user_software_user_key
                UNIQUE (sam_account_name, software_key);
            END IF;
        END $$""",

        # 4. Bảng audit_log
        """CREATE TABLE IF NOT EXISTS audit_log (
            id          SERIAL PRIMARY KEY,
            ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            actor       VARCHAR(128) NOT NULL,
            action      VARCHAR(64)  NOT NULL,
            target      VARCHAR(256),
            detail      TEXT,
            ip_address  VARCHAR(64)
        )""",

        # 5. Bảng domain_config
        """CREATE TABLE IF NOT EXISTS domain_config (
            id              SERIAL PRIMARY KEY,
            ldap_host       VARCHAR(255) NOT NULL,
            domain_suffix   VARCHAR(255) NOT NULL,
            base_dn         VARCHAR(255) NOT NULL,
            admin_group_dn  VARCHAR(255) NOT NULL,
            ssh_host        VARCHAR(255) NOT NULL,
            ssh_user        VARCHAR(128) NOT NULL DEFAULT 'Administrator',
            ssh_pass        VARCHAR(512) NOT NULL,
            is_active       BOOLEAN NOT NULL DEFAULT TRUE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",

        # 6. Bảng tài sản máy tính
        """CREATE TABLE IF NOT EXISTS computers (
            id            SERIAL PRIMARY KEY,
            asset_code    VARCHAR(64),
            computer_name VARCHAR(255) NOT NULL,
            cpu           VARCHAR(255),
            ram           VARCHAR(64),
            ssd           VARCHAR(64),
            hdd           VARCHAR(64),
            os_windows    VARCHAR(128),
            project       VARCHAR(255),
            location      VARCHAR(255),
            status        VARCHAR(32) NOT NULL DEFAULT 'in_use',
            notes         TEXT,
            assigned_user VARCHAR(128),
            created_at    TIMESTAMPTZ DEFAULT NOW(),
            updated_at    TIMESTAMPTZ DEFAULT NOW()
        )""",

        # 7. Gán computer cho user (nhiều-nhiều)
        """CREATE TABLE IF NOT EXISTS user_computers (
            id               SERIAL PRIMARY KEY,
            sam_account_name VARCHAR(128) NOT NULL,
            computer_id      INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
            assigned_at      TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(sam_account_name, computer_id)
        )""",

        # 8. Migration: thêm cột còn thiếu nếu bảng computers đã tồn tại từ bản cũ
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS assigned_user VARCHAR(128)""",

        # 9. Migration: thêm cột asset_code nếu chưa có
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS asset_code VARCHAR(64)""",

        # 9b. Migration: thêm các cột Loại / Hãng / Model / Bitlocker
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS device_type VARCHAR(64)""",
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS brand VARCHAR(128)""",
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS model VARCHAR(128)""",
        """ALTER TABLE computers ADD COLUMN IF NOT EXISTS bitlocker VARCHAR(32)""",

        # 9c. Migration: đảm bảo Mã Tài Sản không trùng nhau (bỏ qua NULL/rỗng).
        #    Nếu DB đang có sẵn mã trùng, bước này sẽ tự bỏ qua (in log) — cần dọn dữ liệu trùng
        #    thủ công rồi restart app để index được tạo. Việc chặn trùng mới vẫn được áp dụng ở tầng ứng dụng.
        """CREATE UNIQUE INDEX IF NOT EXISTS uq_computers_asset_code
           ON computers (asset_code) WHERE asset_code IS NOT NULL AND TRIM(asset_code) <> ''""",

        # 10. Migration: chuyển dữ liệu assigned_user cũ (cột rời rạc) sang user_computers
        #    (nguồn chân lý duy nhất) — chỉ chạy 1 lần, không ảnh hưởng nếu đã rỗng/đã chuyển
        """INSERT INTO user_computers (sam_account_name, computer_id)
           SELECT TRIM(assigned_user), id FROM computers
           WHERE assigned_user IS NOT NULL AND TRIM(assigned_user) <> ''
           ON CONFLICT DO NOTHING""",

        # 10b. Migration: 1 máy chỉ được gán cho 1 user tại 1 thời điểm — nếu dữ liệu cũ
        #     có máy đang gán cho nhiều user cùng lúc, chỉ giữ lại lượt gán mới nhất
        #     (id lớn nhất) và xóa các lượt gán cũ hơn, trước khi tạo UNIQUE index bên dưới.
        """DELETE FROM user_computers a
           USING user_computers b
           WHERE a.computer_id = b.computer_id AND a.id < b.id""",

        # 10c. Ràng buộc DB: mỗi computer_id chỉ xuất hiện tối đa 1 lần trong user_computers
        #     (một máy không thể gán cho 2 user khác nhau cùng lúc)
        """CREATE UNIQUE INDEX IF NOT EXISTS uq_user_computers_computer_id
           ON user_computers (computer_id)""",

        # 11. Bảng lưu OU nào được chọn để hiển thị, theo từng khu vực (users / computers)
        """CREATE TABLE IF NOT EXISTS ou_filters (
            id         SERIAL PRIMARY KEY,
            section    VARCHAR(20)  NOT NULL,
            ou_dn      VARCHAR(512) NOT NULL,
            UNIQUE(section, ou_dn)
        )""",
    ]

    for sql in steps:
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(sql)
            conn.commit()
            print(f"[init_db] OK: {sql.strip()[:60]}...")
        except Exception as e:
            conn.rollback()
            print(f"[init_db] SKIP (already exists or error): {e}")
        finally:
            cur.close()
            conn.close()

def write_log(actor: str, action: str, target: str = None, detail: str = None):
    """Ghi một dòng audit log. Không raise exception để không làm hỏng luồng chính."""
    try:
        ip = request.remote_addr if request else None
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (actor, action, target, detail, ip_address) VALUES (%s,%s,%s,%s,%s)",
            (actor, action, target, detail, ip)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"write_log error: {e}")

# ─────────────────────────────────────────────
#  Domain config helpers
# ─────────────────────────────────────────────
def get_active_domain_config():
    """Trả về dict config domain đang active, hoặc None nếu chưa kết nối domain nào."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT id, ldap_host, domain_suffix, base_dn, admin_group_dn, ssh_host, ssh_user, ssh_pass
            FROM domain_config WHERE is_active = TRUE ORDER BY id DESC LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "ldap_host": row[1], "domain_suffix": row[2],
            "base_dn": row[3], "admin_group_dn": row[4],
            "ssh_host": row[5], "ssh_user": row[6], "ssh_pass": row[7],
        }
    except Exception as e:
        print(f"get_active_domain_config error: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def save_domain_config(cfg: dict):
    """Lưu 1 domain MỚI vào danh sách — KHÔNG deactivate các domain khác nữa (trước đây mỗi
    lần connect domain mới sẽ tắt hết domain cũ, chỉ cho phép dùng 1 domain duy nhất tại 1
    thời điểm cho cả hệ thống). Giờ hệ thống hỗ trợ nhiều domain cùng tồn tại song song —
    mỗi session đăng nhập (mỗi trình duyệt/mỗi admin) tự chọn domain riêng của mình khi login,
    độc lập với các session khác đang dùng domain khác."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO domain_config
                (ldap_host, domain_suffix, base_dn, admin_group_dn, ssh_host, ssh_user, ssh_pass, is_active)
            VALUES (%s,%s,%s,%s,%s,%s,%s,TRUE)
        """, (
            cfg['ldap_host'], cfg['domain_suffix'], cfg['base_dn'],
            cfg['admin_group_dn'], cfg['ssh_host'], cfg['ssh_user'], cfg['ssh_pass']
        ))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"save_domain_config error: {e}")
        return False
    finally:
        cur.close()
        conn.close()

def list_active_domain_configs():
    """Danh sách domain đang khả dụng để chọn khi đăng nhập (mỗi domain_suffix chỉ lấy bản
    ghi is_active mới nhất). Dùng cho dropdown chọn domain ở trang /login."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT DISTINCT ON (domain_suffix) id, ldap_host, domain_suffix
            FROM domain_config
            WHERE is_active = TRUE
            ORDER BY domain_suffix, id DESC
        """)
        rows = cur.fetchall()
        return [{"id": r[0], "ldap_host": r[1], "domain_suffix": r[2]} for r in rows]
    except Exception as e:
        print(f"list_active_domain_configs error: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def get_upn_suffixes(cfg):
    """Lấy danh sách UPN suffix khả dụng trong AD forest — vd domain mặc định @pv.local cộng
    thêm các suffix phụ như @aureole.local được cấu hình qua 'Active Directory Domains and
    Trusts'. Đây chính là danh sách hiện trong dropdown 'User logon name' ở tab Account của
    ADUC, dùng để chọn domain đăng nhập khi tạo/sửa user."""
    ps_cmd = (
        "Import-Module ActiveDirectory -DisableNameChecking; "
        "$primary = (Get-ADDomain).DNSRoot; "
        "$alt = (Get-ADForest).UPNSuffixes; "
        "$all = @($primary) + @($alt); "
        "$all | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { Write-Output $_ }"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    if ec != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def get_domain_config_by_id(domain_id):
    """Lấy 1 cấu hình domain cụ thể theo id — dùng khi admin chọn domain khác với domain
    đang active để thực hiện thao tác (vd tạo user ở domain phụ như Azure/O365 .vn
    trong khi domain chính đang kết nối là .local)."""
    if not domain_id:
        return None
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT id, ldap_host, domain_suffix, base_dn, admin_group_dn, ssh_host, ssh_user, ssh_pass
            FROM domain_config WHERE id = %s
        """, (domain_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "ldap_host": row[1], "domain_suffix": row[2],
            "base_dn": row[3], "admin_group_dn": row[4],
            "ssh_host": row[5], "ssh_user": row[6], "ssh_pass": row[7],
        }
    except Exception as e:
        print(f"get_domain_config_by_id error: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def current_domain_cfg():
    """Trả về config domain gắn với SESSION hiện tại (mỗi phiên đăng nhập độc lập với 1 domain
    riêng — đây là điểm khác biệt cốt lõi so với get_active_domain_config() cũ, vốn dùng chung
    1 "domain active" duy nhất cho toàn bộ hệ thống/mọi người dùng).
    Session được gán domain_id ngay lúc đăng nhập thành công ở /login. Nếu vì lý do nào đó
    session chưa có domain_id (vd phiên cũ trước khi nâng cấp multi-domain), fallback về domain
    active gần nhất để không phá vỡ session đang dùng dở."""
    domain_id = session.get('domain_id')
    if domain_id:
        cfg = get_domain_config_by_id(domain_id)
        if cfg:
            return cfg
    return get_active_domain_config()

def list_domain_configs():
    """Trả về danh sách các domain từng được kết nối (mỗi domain_suffix chỉ lấy bản ghi mới
    nhất — vì mỗi lần kết nối lại cùng 1 domain sẽ tạo thêm 1 dòng lịch sử mới).
    Dùng để admin chọn domain khi tạo tài khoản, hỗ trợ trường hợp có nhiều domain
    (vd domain nội bộ pv.local và domain Azure/O365 phongvu.vn)."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT DISTINCT ON (domain_suffix) id, ldap_host, domain_suffix, is_active
            FROM domain_config
            ORDER BY domain_suffix, id DESC
        """)
        rows = cur.fetchall()
        return [{"id": r[0], "ldap_host": r[1], "domain_suffix": r[2], "is_active": bool(r[3])} for r in rows]
    except Exception as e:
        print(f"list_domain_configs error: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def deactivate_domain_config(domain_id=None):
    """Ngắt kết nối 1 domain CỤ THỂ (domain_id). Nếu domain_id=None (giữ tương thích code cũ
    gọi không tham số), tắt hết mọi domain — chỉ nên dùng cho script quản trị/CLI, KHÔNG dùng
    trong route web thông thường nữa vì sẽ ảnh hưởng tới mọi admin khác đang dùng domain khác."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        if domain_id:
            cur.execute("UPDATE domain_config SET is_active = FALSE WHERE id = %s", (domain_id,))
        else:
            cur.execute("UPDATE domain_config SET is_active = FALSE WHERE is_active = TRUE")
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"deactivate_domain_config error: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# ─────────────────────────────────────────────
#  Escape giá trị trước khi nhét vào lệnh PowerShell
# ─────────────────────────────────────────────
import re as _re
def clean_ps_error(raw_err: str) -> str:
    """PowerShell qua SSH (không có console thật) đôi khi serialize progress/warning/error
    thành định dạng CLIXML (bắt đầu bằng '#< CLIXML') thay vì text thường, gây khó đọc.
    Hàm này ưu tiên lấy đúng nội dung luồng Error/Warning, bỏ hết rác progress/XML."""
    if not raw_err or '#< CLIXML' not in raw_err:
        return raw_err
    # Ưu tiên nội dung nằm trong <S S="Error">...</S> hoặc <S S="Warning">...</S> (thông điệp thật)
    pieces = _re.findall(r'<S S="(?:Error|Warning)"[^>]*>(.*?)</S>', raw_err, flags=_re.DOTALL)
    if not pieces:
        # Không có Error/Warning riêng -> lấy tất cả <S> (có thể lẫn vài dòng progress)
        pieces = _re.findall(r'<S[^>]*>(.*?)</S>', raw_err, flags=_re.DOTALL)
    text = ' '.join(pieces)
    text = _re.sub(r'_x000([0-9A-Da-d])_', lambda m: {'D':'\r','A':'\n','9':'\t'}.get(m.group(1).upper(), ''), text)
    text = _re.sub(r'<[^>]+>', '', text).strip()
    return text or raw_err  # nếu bóc không ra gì thì trả nguyên bản để không mất thông tin

def ps_quote(value) -> str:
    """Escape 1 giá trị để nhét an toàn vào bên trong cặp nháy đơn '...' của PowerShell.
    Trong PowerShell, chuỗi trong nháy đơn là literal string thuần túy — chỉ cần nhân đôi
    dấu ' bên trong là chặn được injection (mọi ký tự khác kể cả $, `, ; đều là ký tự thường,
    không có ý nghĩa đặc biệt bên trong nháy đơn). LUÔN dùng hàm này khi nội suy input người
    dùng (username, tên, OU, group, mật khẩu...) vào bên trong cặp '...' của lệnh PowerShell."""
    return str(value if value is not None else "").replace("'", "''")

def verify_current_user_password(cfg, password):
    """Bind LDAP lại bằng đúng tài khoản admin đang đăng nhập (session['user']) + mật khẩu vừa
    nhập, để xác nhận đúng là họ trước khi cho phép thực hiện thao tác nguy hiểm (xoá dữ liệu).
    Không dùng mật khẩu Administrator dùng chung lưu trong domain_config — mỗi admin xác nhận
    bằng CHÍNH mật khẩu AD của mình, vừa an toàn hơn (không ai cần biết mật khẩu dùng chung) vừa
    có thể truy vết đúng người thực hiện qua audit log."""
    if not password or not cfg:
        return False
    username = session.get('user')
    if not username:
        return False
    try:
        user_dn = f"{username}{cfg['domain_suffix']}"
        server  = Server(cfg['ldap_host'], get_info=None, connect_timeout=3)
        conn    = Connection(server, user=user_dn, password=password, authentication='SIMPLE')
        ok = conn.bind()
        if ok:
            conn.unbind()
        return ok
    except Exception as e:
        print(f"verify_current_user_password error: {e}")
        return False

# ─────────────────────────────────────────────
#  SSH / PowerShell — dùng config domain hiện tại
# ─────────────────────────────────────────────
def test_ssh_connectivity(host, user, password, timeout=8):
    """Test nhanh xem có SSH được vào Domain Controller không (dùng đúng credential vừa nhập
    ở bước Connect Domain). LDAP bind thành công KHÔNG có nghĩa SSH cũng thông — đây là 2 dịch
    vụ hoàn toàn khác nhau, khác cổng (389 vs 22). Nếu không test ở bước này, domain vẫn 'kết
    nối' được (vì login chỉ cần LDAP) nhưng toàn bộ tính năng Users/Groups/OU/Computer (chạy
    qua SSH+PowerShell) sẽ timeout âm thầm về sau — rất khó debug nếu không chặn ngay từ đầu."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, password=password,
                    timeout=timeout, look_for_keys=False, allow_agent=False)
        ssh.close()
        return True, None
    except paramiko.AuthenticationException:
        return False, "sai tài khoản/mật khẩu SSH (khác với LDAP dù dùng chung Administrator)"
    except Exception as e:
        err_str = str(e).lower()
        if 'timed out' in err_str or 'timeout' in err_str:
            return False, "timed out — SSH (OpenSSH Server) có thể chưa chạy hoặc firewall chưa mở port 22 trên Domain Controller này"
        return False, str(e)

# ─────────────────────────────────────────────
#  SSH connection pool — TÁI SỬ DỤNG kết nối SSH đã mở, thay vì mở-đóng mới cho MỖI lệnh
#  PowerShell. Trước đây mỗi hành động (thêm/xoá group, tạo user, đổi mật khẩu...) đều tự
#  connect() một kết nối SSH hoàn toàn mới rồi đóng ngay sau khi xong — tốn thêm 1-2s bắt tay
#  TCP+SSH mỗi lần, CỘNG DỒN với thời gian PowerShell tự nó đã chậm (nạp module ActiveDirectory)
#  khiến 1 thao tác đơn giản có thể mất 10-20s. Giữ lại kết nối đã xác thực thành công cho mỗi
#  domain, dùng lại ở các lệnh sau — chỉ mở lại khi kết nối cũ đã chết (mất mạng, DC restart...).
#  Lưu ý: dùng chung 1 kết nối cho nhiều lệnh CÙNG LÚC (nhiều tab/nhiều admin) vẫn an toàn vì
#  SSH hỗ trợ multiplex nhiều channel trên 1 transport — mỗi exec_command() vẫn là 1 channel
#  (1 tiến trình powershell.exe) riêng biệt, không lẫn output giữa các lệnh với nhau.
# ─────────────────────────────────────────────
_SSH_POOL = {}              # domain_key (ssh_host) -> paramiko.SSHClient đã connect
_SSH_POOL_LOCK = threading.Lock()  # bảo vệ việc tạo/thay thế connection trong pool (không tạo trùng)

def _get_pooled_ssh_client(cfg):
    """Trả về 1 SSHClient đã kết nối, tái sử dụng nếu còn sống; tự động mở lại nếu đã chết."""
    domain_key = cfg['ssh_host']
    with _SSH_POOL_LOCK:
        client = _SSH_POOL.get(domain_key)
        if client is not None:
            transport = client.get_transport()
            if transport is not None and transport.is_active():
                return client
            # Kết nối cũ đã chết (mất mạng, DC restart SSH service...) -> dọn đi, tạo lại bên dưới
            try:
                client.close()
            except Exception:
                pass
            _SSH_POOL.pop(domain_key, None)

        new_client = paramiko.SSHClient()
        new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        new_client.connect(
            hostname=cfg['ssh_host'], username=cfg['ssh_user'], password=cfg['ssh_pass'],
            timeout=10, look_for_keys=False, allow_agent=False
        )
        _SSH_POOL[domain_key] = new_client
        return new_client

def _evict_pooled_ssh_client(domain_key):
    """Loại bỏ 1 connection hỏng khỏi pool để lần gọi sau tự mở lại kết nối mới."""
    with _SSH_POOL_LOCK:
        client = _SSH_POOL.pop(domain_key, None)
    if client is not None:
        try:
            client.close()
        except Exception:
            pass

def run_powershell_ssh(command_block, cfg=None, return_stderr=False):
    if cfg is None:
        cfg = get_active_domain_config()
    if not cfg:
        return ("", "Chưa kết nối domain", 1) if return_stderr else ""

    domain_key = cfg['ssh_host']
    last_exc = None
    # Thử tối đa 2 lần: lỗi "No existing session" / kết nối SSH trong pool vừa chết đúng lúc
    # (DC restart, mất mạng chớp nhoáng...) đôi khi chỉ thoáng qua — thử lại 1 lần với kết nối
    # MỚI (đã evict kết nối hỏng ở lần thử trước) ổn định hơn là báo lỗi ngay.
    for attempt in range(2):
        try:
            ssh = _get_pooled_ssh_client(cfg)
            # Ép PowerShell xuất ra UTF-8 thay vì bảng mã console mặc định (OEM/ANSI) —
            # đây là nguyên nhân chính khiến tên user tiếng Việt (dấu) bị lỗi font khi đọc về.
            # $ProgressPreference = SilentlyContinue: chặn PowerShell serialize thông báo tiến trình
            # (vd "Loading Active Directory module...") thành CLIXML lẫn vào stderr — đây là nguyên
            # nhân khiến lỗi hiển thị cho người dùng bị rác đầy "#< CLIXML ..." khó đọc.
            encoding_prefix = (
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                "$OutputEncoding = [System.Text.Encoding]::UTF8; "
                "$ProgressPreference = 'SilentlyContinue'; "
            )
            encoded_cmd = base64.b64encode((encoding_prefix + command_block).encode('utf-16-le')).decode('utf-8')
            # Dùng $LASTEXITCODE và thêm exit code vào cuối stdout để detect lỗi chính xác
            # stderr của PowerShell thường có noise (progress, warning) dù thành công
            full_command = (
                f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"
            )
            stdin, stdout, stderr = ssh.exec_command(full_command)
            # Trước đây stdout.read()/stderr.read() KHÔNG có giới hạn thời gian — nếu PowerShell
            # phía DC phản hồi chậm bất thường (vd lần chạy đầu sau thời gian idle dài: module
            # ActiveDirectory phải load lại từ đầu, Windows Defender quét tiến trình powershell.exe
            # mới, DC vừa "ngủ" cần thời gian phản ứng...), lệnh read() sẽ chờ VÔ THỜI HẠN thay vì
            # báo lỗi — đây là nguyên nhân chính của hiện tượng "login/vào Dashboard rất lâu (30s+)
            # sau khi không dùng một thời gian". Đặt giới hạn 45s: đủ cho truy vấn AD full user/
            # group bình thường (kể cả domain vài nghìn user), nhưng vẫn chặn được tình huống treo
            # vô hạn thay vì để người dùng chờ không biết đến bao giờ.
            stdout.channel.settimeout(45)
            out      = stdout.read().decode('utf-8', errors='ignore')
            err      = stderr.read().decode('utf-8', errors='ignore')
            exitcode = stdout.channel.recv_exit_status()  # 0 = success
            err      = clean_ps_error(err)  # dọn CLIXML nếu vẫn còn sót (vd warning nghiêm trọng)

            # Nếu lệnh có thay đổi user/group AD (tạo/xóa/sửa/enable/disable/thêm-xóa thành viên),
            # xoá cache danh sách AD của ĐÚNG domain vừa thao tác để lần load Dashboard kế tiếp lấy
            # dữ liệu mới nhất ngay, thay vì phải chờ hết TTL cache (không đụng tới cache của các
            # domain khác đang được admin khác dùng song song).
            _mutating_keywords = ('New-AD', 'Remove-AD', 'Set-AD', 'Add-ADGroupMember',
                                  'Remove-ADGroupMember', 'Enable-ADAccount', 'Disable-ADAccount',
                                  'Move-ADObject', 'Rename-AD')
            if exitcode == 0 and any(k in command_block for k in _mutating_keywords):
                _AD_CACHE.pop(cfg.get('ssh_host'), None)

            if return_stderr:
                return out, err, exitcode
            return out
        except Exception as e:
            last_exc = e
            print(f"SSH Error (attempt {attempt + 1}/2): {e}")
            # Kết nối trong pool có thể đã hỏng (nguyên nhân gây lỗi) -> loại bỏ để lần thử
            # tiếp theo (hoặc lệnh kế tiếp) tự mở lại kết nối mới, thay vì tiếp tục dùng lại
            # 1 connection đã hỏng.
            _evict_pooled_ssh_client(domain_key)
            continue
        # Không còn "finally: ssh.close()" — kết nối được GIỮ LẠI trong pool để dùng cho lệnh
        # tiếp theo thay vì đóng ngay sau mỗi lệnh (đó là lý do chính khiến trước đây mỗi thao
        # tác đều phải trả thêm phí bắt tay SSH từ đầu).

    if return_stderr:
        return "", str(last_exc), 1
    return ""

# ─────────────────────────────────────────────
#  Cache Danh Sách User/Group AD
#  - Mỗi lần load Dashboard trước đây mở 2 kết nối SSH riêng (Get-ADUser + Get-ADGroup),
#    mỗi kết nối tốn 1-3s+ để handshake/PowerShell, cộng dồn khiến trang rất chậm khi
#    người dùng chuyển qua lại (vd: Đổi Mật Khẩu -> quay lại Dashboard).
#  - Gộp còn 1 kết nối SSH duy nhất lấy cả 2 loại dữ liệu, và cache tạm trong ít giây để
#    các lượt refresh liên tiếp không phải chờ AD trả lời lại từ đầu.
# ─────────────────────────────────────────────
_AD_CACHE = {}  # domain_key (ssh_host) -> {'users':..., 'groups':..., 'ts':...}
_AD_CACHE_TTL = 120  # giây — sau thời gian này, dữ liệu được coi là "cũ" (nhưng vẫn dùng tạm được)
_AD_CACHE_REFRESHING = set()  # domain_key nào đang có 1 luồng background refresh chạy dở

def get_ad_users_and_groups(cfg, force_refresh=False):
    """Trả về (ad_users, ad_groups, error). `error` là None khi lấy dữ liệu thành công (kể cả
    khi AD thực sự không có user/group nào) — chỉ khác None khi việc kết nối/thực thi PowerShell
    thất bại, để phân biệt rõ "0 vì AD trống" với "0 vì không lấy được dữ liệu" (trước đây 2
    trường hợp này hiển thị y hệt nhau — Dashboard hiện toàn số 0 mà không rõ lý do).

    CHIẾN LƯỢC CACHE (stale-while-revalidate): trước đây hễ cache hết hạn (>120s, chắc chắn xảy
    ra sau thời gian không dùng dài) là request HIỆN TẠI phải tự chờ chạy PowerShell sống qua SSH
    xong mới trả trang — nếu DC phản hồi chậm bất thường lần đầu (rất hay gặp sau thời gian idle
    dài), người dùng phải đợi ngay lúc đó, đây là nguyên nhân chính gây ra hiện tượng "login/vào
    Dashboard mất 30s+". Giờ nếu ĐÃ TỪNG có dữ liệu (dù cũ), trả về NGAY LẬP TỨC dữ liệu đó (dữ
    liệu cũ vài phút vẫn tốt hơn nhiều so với bắt người dùng đứng chờ), đồng thời âm thầm khởi
    một luồng nền để lấy dữ liệu mới — trang hiện tại vẫn dùng dữ liệu cũ, trang sau (vài giây
    sau đó) sẽ tự có dữ liệu mới khi luồng nền chạy xong. Chỉ khi CHƯA TỪNG có dữ liệu nào trong
    cache (lần đầu tiên truy cập kể từ khi app khởi động) mới thực sự phải chờ đồng bộ."""
    domain_key = cfg.get('ssh_host') if cfg else None
    now = time.time()
    entry = _AD_CACHE.get(domain_key)
    is_stale = not entry or entry.get('users') is None or (now - entry.get('ts', 0) >= _AD_CACHE_TTL)

    if not force_refresh and entry and entry.get('users') is not None:
        if is_stale and domain_key not in _AD_CACHE_REFRESHING:
            # Có dữ liệu cũ -> trả ngay, đồng thời âm thầm làm mới ở background cho lần sau.
            _AD_CACHE_REFRESHING.add(domain_key)
            import threading
            def _bg_refresh():
                try:
                    _fetch_and_cache_ad_data(cfg, domain_key)
                finally:
                    _AD_CACHE_REFRESHING.discard(domain_key)
            threading.Thread(target=_bg_refresh, daemon=True).start()
        return entry['users'], entry['groups'], entry.get('error')

    # Chưa từng có dữ liệu (hoặc force_refresh=True) -> chờ lấy đồng bộ như trước đây.
    return _fetch_and_cache_ad_data(cfg, domain_key)


def _fetch_and_cache_ad_data(cfg, domain_key):
    """Thực sự chạy PowerShell qua SSH để lấy user/group AD mới nhất, rồi lưu vào cache.
    Tách riêng khỏi get_ad_users_and_groups() để dùng chung được cho cả đường đồng bộ (chờ
    trực tiếp) lẫn đường background refresh (chạy trong thread riêng)."""
    now = time.time()

    ad_users, ad_groups = [], []
    error = None
    if not cfg:
        error = "Chưa xác định được domain cho phiên đăng nhập này."
    else:
        # Danh sách tên các group MẶC ĐỊNH do AD tự tạo sẵn khi dựng domain (RID 512-521 +
        # các group hệ thống khác) — LOẠI theo TÊN cụ thể, không loại theo container CN=Users,
        # vì admin hoàn toàn có thể tạo group thật (vd "MKT", "TCKT") ngay trong CN=Users
        # (đây là hành vi mặc định của "New-ADGroup" khi không chỉ định -Path) — loại theo
        # container sẽ ẩn nhầm các group đó, khiến chúng "biến mất" khỏi web dù vẫn tồn tại
        # trên AD thật (bug đã gặp: tạo group MKT/TCKT trong CN=Users -> web không hiển thị).
        _default_group_names = (
            "'Domain Computers','Domain Controllers','Domain Guests','Domain Users',"
            "'Domain Admins','Enterprise Admins','Schema Admins','Group Policy Creator Owners',"
            "'Read-only Domain Controllers','Enterprise Read-only Domain Controllers',"
            "'Cloneable Domain Controllers','Protected Users','Key Admins','Enterprise Key Admins',"
            "'DnsAdmins','DnsUpdateProxy','RAS and IAS Servers',"
            "'Allowed RODC Password Replication Group','Denied RODC Password Replication Group',"
            "'Cert Publishers'"
        )
        ps_cmd = (
            "$u = Get-ADUser -Filter * -Properties MemberOf | "
            "Select-Object SamAccountName, Name, Enabled, DistinguishedName, "
            "@{Name='Groups';Expression={($_.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=', ''}) -join ','}}; "
            f"$defaultNames = @({_default_group_names}); "
            "$g = Get-ADGroup -Filter * -Properties DistinguishedName,Description | "
            "Where-Object { $_.Name -eq 'Administrators' -or "
            "($_.DistinguishedName -notmatch ',CN=Builtin,' -and $_.Name -notin $defaultNames) } | "
            "Select-Object SamAccountName, Name, DistinguishedName, Description | Sort-Object Name; "
            "@{ users = @($u); groups = @($g) } | ConvertTo-Json -Compress -Depth 6"
        )
        out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
        if ec != 0:
            # Không kết nối được (SSH sai host/port/user/pass, timeout, DC tắt máy...) hoặc
            # PowerShell trả lỗi — trước đây bị nuốt âm thầm, giờ đưa ra ngoài để admin thấy
            # được lý do thật thay vì Dashboard cứ hiện toàn số 0 không rõ nguyên nhân.
            error = err.strip() or "Không kết nối được tới Domain Controller qua SSH."
        elif out.strip():
            try:
                parsed = json.loads(out)
                ad_users = parsed.get('users') or []
                ad_groups = parsed.get('groups') or []
                if isinstance(ad_users, dict): ad_users = [ad_users]
                if isinstance(ad_groups, dict): ad_groups = [ad_groups]
            except Exception as e:
                error = f"Lỗi phân tích dữ liệu trả về từ AD: {e}"
                print(f"JSON AD Error: {e}")

    # Ẩn các tài khoản hệ thống mặc định của AD (không phải nhân viên thật, không nên hiển
    # thị/thao tác trong tool quản trị này) — Guest bị disable sẵn theo policy AD chuẩn,
    # krbtgt là tài khoản nội bộ Kerberos KDC dùng, đổi/xoá có thể phá cả domain.
    _HIDDEN_BUILTIN_USERS = {'guest', 'krbtgt'}
    ad_users = [u for u in ad_users if (u.get('SamAccountName') or '').lower() not in _HIDDEN_BUILTIN_USERS]

    _AD_CACHE[domain_key] = {'users': ad_users, 'groups': ad_groups, 'ts': now, 'error': error}
    return ad_users, ad_groups, error

# ─────────────────────────────────────────────
#  Bộ lọc OU hiển thị (riêng cho từng khu vực: users / computers)
# ─────────────────────────────────────────────
_OU_FILTER_SECTIONS = ('users', 'computers', 'groups')

def get_ou_filter(section: str):
    """Trả về danh sách DistinguishedName các OU đang được chọn để hiển thị
    cho khu vực (section) tương ứng. Danh sách rỗng = không lọc (hiển thị tất cả)."""
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT ou_dn FROM ou_filters WHERE section=%s ORDER BY ou_dn", (section,))
        return [r[0] for r in cur.fetchall()]
    except Exception as e:
        print(f"get_ou_filter error: {e}")
        return []
    finally:
        cur.close(); conn.close()

def save_ou_filter(section: str, ou_list):
    """Ghi đè toàn bộ danh sách OU được chọn cho một khu vực."""
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM ou_filters WHERE section=%s", (section,))
        cleaned = sorted({ou.strip() for ou in ou_list if ou and ou.strip()})
        for ou_dn in cleaned:
            cur.execute("INSERT INTO ou_filters (section, ou_dn) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (section, ou_dn))
        conn.commit()
        return cleaned
    except Exception as e:
        conn.rollback()
        print(f"save_ou_filter error: {e}")
        return None
    finally:
        cur.close(); conn.close()

def _dn_matches_selected_ous(dn: str, selected_ous: list) -> bool:
    """True nếu 'dn' nằm trong một trong các OU đã chọn (bao gồm cả OU con bên trong)."""
    if not dn:
        return False
    dn_lower = dn.lower()
    for ou_dn in selected_ous:
        if dn_lower.endswith(ou_dn.lower()):
            return True
    return False

def filter_by_ou(items: list, selected_ous: list, dn_key):
    """Lọc danh sách item theo OU đã chọn. Nếu selected_ous rỗng -> trả về nguyên danh sách.
    dn_key: tên field chứa DN (dict) hoặc callable(item) -> dn."""
    if not selected_ous:
        return items
    getter = dn_key if callable(dn_key) else (lambda it: it.get(dn_key, ''))
    return [it for it in items if _dn_matches_selected_ous(getter(it), selected_ous)]

# ─────────────────────────────────────────────
#  Auth decorators
# ─────────────────────────────────────────────
def _is_ajax_request():
    """Nhận diện request gọi qua fetch()/JS (mọi fetch cùng origin trong index.html đều tự
    gắn header X-CSRF-Token) để trả lỗi dạng JSON đẹp thay vì text trần (hiện ra như 1 trang
    trắng tinh nếu bị load thẳng bằng form submit/điều hướng trình duyệt)."""
    return bool(request.headers.get('X-CSRF-Token')) or 'application/json' in (request.headers.get('Accept') or '')

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            if _is_ajax_request():
                return jsonify({"status": "error", "message": "Phiên đăng nhập đã hết hạn, vui lòng tải lại trang và đăng nhập lại."}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            if _is_ajax_request():
                return jsonify({"status": "error", "message": "Phiên đăng nhập đã hết hạn, vui lòng tải lại trang và đăng nhập lại."}), 401
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            message = "Bạn không có quyền thực hiện thao tác này (yêu cầu quyền Domain Admins)."
            if _is_ajax_request():
                return jsonify({"status": "error", "message": message}), 403
            return message, 403
        return f(*args, **kwargs)
    return decorated

def domain_required(f):
    """Chỉ cho phép truy cập nếu hệ thống đã có ít nhất 1 domain nào được cấu hình (không nhất
    thiết phải trùng domain của session hiện tại — mỗi session tự chọn domain riêng lúc login,
    xem current_domain_cfg())."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not list_active_domain_configs():
            return redirect(url_for('connect_domain'))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
#  TRANG KẾT NỐI DOMAIN  (Entry point)
# ─────────────────────────────────────────────
@app.route('/connect-domain', methods=['GET', 'POST'])
def connect_domain():
    """Trang khởi đầu: kết nối tới một Active Directory Domain.
    Chỉ cần IP/Host AD + tài khoản Administrator — mọi thông tin khác
    (domain suffix, base DN, admin group DN) được tự động phát hiện qua LDAP RootDSE.
    Hỗ trợ nhiều domain cùng tồn tại song song — thêm domain mới ở đây KHÔNG làm mất các
    domain đã kết nối trước đó, mỗi admin chọn domain muốn dùng riêng lúc đăng nhập."""
    error   = None
    domains = list_active_domain_configs()

    if request.method == 'POST':
        ldap_host = request.form.get('ldap_host', '').strip()
        admin_user = request.form.get('admin_user', '').strip()
        admin_pass = request.form.get('admin_pass', '')

        try:
            server = Server(ldap_host, get_info=ALL, connect_timeout=5)

            # Bước 1: lấy base_dn từ RootDSE (chưa cần đăng nhập)
            anon_conn = Connection(server)
            anon_conn.bind()
            base_dn = None
            if server.info and server.info.other.get('defaultNamingContext'):
                base_dn = server.info.other['defaultNamingContext'][0]
            anon_conn.unbind()

            if not base_dn:
                # Fallback: thử suy ra domain_suffix tạm từ input rồi bind trực tiếp
                base_dn = None

            # Suy ra domain_suffix dạng "@domain.com" từ base_dn (DC=domain,DC=com)
            domain_suffix = None
            if base_dn:
                parts = [p.split('=')[1] for p in base_dn.split(',') if p.upper().startswith('DC=')]
                if parts:
                    domain_suffix = '@' + '.'.join(parts)

            if not domain_suffix:
                error = "Không thể tự động xác định domain từ địa chỉ AD này. Vui lòng kiểm tra lại IP/Host."
            else:
                # Bước 2: bind thật bằng tài khoản admin để xác thực + lấy quyền
                user_dn = f"{admin_user}{domain_suffix}"
                conn = Connection(server, user=user_dn, password=admin_pass, authentication='SIMPLE')

                if conn.bind():
                    conn.unbind()
                    admin_group_dn = f"CN=Domain Admins,CN=Users,{base_dn}"

                    # LDAP OK không có nghĩa SSH cũng OK — test luôn ở đây để phát hiện ngay lúc
                    # kết nối, thay vì để domain "kết nối được" xong Users/Groups/OU timeout âm
                    # thầm về sau (đúng tình huống domain thứ 2 gặp phải).
                    ssh_ok, ssh_err = test_ssh_connectivity(ldap_host, admin_user, admin_pass)
                    if not ssh_ok:
                        error = (f"Đăng nhập LDAP thành công nhưng KHÔNG SSH được tới '{ldap_host}': {ssh_err}. "
                                 f"Toàn bộ tính năng Users/Groups/OU/Computer cần SSH (OpenSSH Server) chạy "
                                 f"trên Domain Controller này. Trên DC, kiểm tra bằng PowerShell: "
                                 f"Get-Service sshd (phải Running), và New-NetFirewallRule cho phép inbound "
                                 f"TCP port 22 nếu chưa có.")
                    else:
                        new_cfg = {
                            'ldap_host': ldap_host,
                            'domain_suffix': domain_suffix,
                            'base_dn': base_dn,
                            'admin_group_dn': admin_group_dn,
                            'ssh_host': ldap_host,
                            'ssh_user': admin_user,
                            'ssh_pass': admin_pass,
                        }
                        if save_domain_config(new_cfg):
                            write_log(admin_user, 'CONNECT_DOMAIN',
                                      target=ldap_host, detail=f"domain_suffix={domain_suffix}, base_dn={base_dn} (auto-detected)")
                            return redirect(url_for('login'))
                        else:
                            error = "Lưu cấu hình domain thất bại (DB error)."
                else:
                    error = "Không thể đăng nhập với tài khoản đã nhập. Vui lòng kiểm tra lại username/password."
        except Exception as e:
            err_str = str(e).lower()
            if 'no route to host' in err_str or 'errno 113' in err_str or 'timed out' in err_str or 'connection refused' in err_str:
                error = f"Không tìm thấy Active Directory tại địa chỉ '{ldap_host}'. Vui lòng kiểm tra lại IP/Hostname và đảm bảo máy chủ AD đang hoạt động."
            elif 'invalid credentials' in err_str or 'ldap_bind' in err_str:
                error = "Tài khoản hoặc mật khẩu không chính xác."
            else:
                error = f"Không thể kết nối tới Active Directory: {str(e)}"
        domains = list_active_domain_configs()

    return render_template('connect_domain.html', error=error, domains=domains)


@app.route('/disconnect-domain', methods=['POST'])
def disconnect_domain():
    """Ngắt kết nối 1 domain CỤ THỂ khỏi danh sách domain khả dụng (không còn ai đăng nhập
    được vào domain đó nữa, nhưng KHÔNG ảnh hưởng tới các domain khác).
    LƯU Ý BẢO MẬT: route này KHÔNG yêu cầu đăng nhập (giống /connect-domain) — để admin vẫn
    ngắt/dọn được domain cũ ngay cả khi không đăng nhập được vào domain đó (vd domain cũ không
    còn AD server thật, hoặc đang bị khoá ngoài). Đánh đổi: ai truy cập được vào địa chỉ web
    app cũng ngắt được bất kỳ domain nào trong danh sách. Nếu muốn khôi phục yêu cầu đăng nhập
    admin, thêm lại decorator @admin_required phía trên."""
    domain_id = request.form.get('domain_id', '').strip() or session.get('domain_id')
    cfg = get_domain_config_by_id(domain_id) if domain_id else None
    actor = session.get('user', 'anonymous')
    if domain_id and deactivate_domain_config(domain_id):
        write_log(actor, 'DISCONNECT_DOMAIN', target=cfg['ldap_host'] if cfg else str(domain_id))
        # Nếu domain vừa ngắt chính là domain của session hiện tại -> đăng xuất luôn phiên này.
        if str(session.get('domain_id')) == str(domain_id):
            session.clear()
        return jsonify({"status": "success", "redirect": url_for('connect_domain')})
    return jsonify({"status": "error", "message": "Không xác định được domain cần ngắt kết nối."}), 400

# ─────────────────────────────────────────────
#  Login / Logout
# ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@domain_required
def login():
    domains = list_active_domain_configs()

    # Xác định domain đang thao tác cho request này: ưu tiên domain_id gửi lên (dropdown chọn
    # domain ở form login), nếu không có thì nếu hệ thống chỉ có đúng 1 domain thì tự chọn luôn
    # domain đó (giữ trải nghiệm gọn cho trường hợp phổ biến nhất — chỉ dùng 1 domain).
    domain_id = request.values.get('domain_id', '').strip()
    if domain_id:
        cfg = get_domain_config_by_id(domain_id)
    elif len(domains) == 1:
        cfg = get_domain_config_by_id(domains[0]['id'])
    else:
        cfg = None

    error = None
    if request.method == 'POST':
        if not cfg:
            error = "Vui lòng chọn domain muốn đăng nhập."
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user_dn  = f"{username}{cfg['domain_suffix']}"
            try:
                # get_info=None: không load LDAP schema, tiết kiệm 2-3 giây
                server = Server(cfg['ldap_host'], get_info=None, connect_timeout=3)
                conn   = Connection(server, user=user_dn, password=password, authentication='SIMPLE')
                if conn.bind():
                    # Dùng server riêng có get_info để search (chỉ tốn 1 lần nhỏ)
                    s2   = Server(cfg['ldap_host'], get_info=None, connect_timeout=3)
                    conn2 = Connection(s2, user=user_dn, password=password, authentication='SIMPLE')
                    conn2.bind()
                    conn2.search(
                        search_base=cfg['base_dn'],
                        search_filter=f'(sAMAccountName={username})',
                        attributes=['memberOf', 'name']
                    )
                    is_admin     = False
                    display_name = username
                    if conn2.entries:
                        entry        = conn2.entries[0]
                        display_name = str(entry.name) if 'name' in entry else username
                        groups       = entry.memberOf.values if 'memberOf' in entry else []
                        admin_keywords = [
                            cfg['admin_group_dn'].lower(),
                            "cn=domain admins",
                            "cn=administrators,cn=builtin",
                        ]
                        for g in groups:
                            g_lower = g.lower()
                            if any(kw in g_lower for kw in admin_keywords):
                                is_admin = True
                                break
                    conn2.unbind()
                    conn.unbind()
                    session['user']         = username
                    session['display_name'] = display_name
                    session['is_admin']     = is_admin
                    # Domain riêng của PHIÊN NÀY — mỗi session/trình duyệt độc lập, không ảnh
                    # hưởng tới session của admin khác đang đăng nhập vào domain khác.
                    session['domain_id']    = cfg['id']
                    session['csrf_token']   = secrets.token_hex(16)  # dùng để chống CSRF cho các request POST sau khi đăng nhập
                    write_log(username, 'LOGIN', detail=f"is_admin={is_admin}, domain={cfg['ldap_host']}")

                    # Warm AD cache ngầm sau khi login — user sẽ thấy dashboard nhanh hơn
                    import threading
                    threading.Thread(target=get_ad_users_and_groups, args=(cfg, True), daemon=True).start()

                    return redirect(url_for('index'))
                else:
                    error = "Tài khoản hoặc mật khẩu AD không chính xác."
            except Exception as e:
                error = f"Không kết nối được tới Domain Controller: {str(e)}"

    return render_template(
        'login.html', error=error, domains=domains,
        selected_domain_id=(cfg['id'] if cfg else (domain_id or None)),
        domain_host=(cfg['ldap_host'] if cfg else None),
        domain_suffix=(cfg['domain_suffix'] if cfg else None),
    )


@app.route('/logout')
def logout():
    if 'user' in session:
        write_log(session['user'], 'LOGOUT')
    session.clear()
    # Nút "Đổi Domain" ở sidebar gọi /logout?next=connect_domain để quay thẳng về màn hình
    # danh sách domain (chọn domain khác) thay vì màn hình login của domain vừa thoát.
    if request.args.get('next') == 'connect_domain':
        return redirect(url_for('connect_domain'))
    return redirect(url_for('login'))

# ─────────────────────────────────────────────
#  Đổi mật khẩu
# ─────────────────────────────────────────────
@app.route('/change-password', methods=['GET', 'POST'])
@domain_required
@login_required
def change_password():
    cfg = current_domain_cfg()
    message = None
    status  = None
    if request.method == 'POST':
        old_password     = request.form.get('old_password')
        new_password     = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        username         = session['user']

        if new_password != confirm_password:
            message = "Mật khẩu mới và xác nhận không khớp."
            status  = "danger"
        elif len(new_password) < 8:
            message = "Mật khẩu mới phải từ 8 ký tự trở lên."
            status  = "danger"
        else:
            try:
                user_dn = f"{username}{cfg['domain_suffix']}"
                server  = Server(cfg['ldap_host'], connect_timeout=3)
                conn    = Connection(server, user=user_dn, password=old_password, authentication='SIMPLE')
                if not conn.bind():
                    message = "Mật khẩu hiện tại không chính xác."
                    status  = "danger"
                else:
                    conn.unbind()
                    ps_cmd = (
                        f"Import-Module ActiveDirectory -DisableNameChecking; "
                        f"$sec = ConvertTo-SecureString '{ps_quote(new_password)}' -AsPlainText -Force; "
                        f"Set-ADAccountPassword -Identity '{ps_quote(username)}' -NewPassword $sec -Reset"
                    )
                    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
                    if ec == 0:
                        write_log(username, 'CHANGE_PASSWORD', target=username, detail='Password changed via AD')
                        message = "Đổi mật khẩu Windows AD thành công!"
                        status  = "success"
                    else:
                        message = f"Đổi mật khẩu thất bại: {err.strip() or 'lỗi không rõ'}"
                        status  = "danger"
            except Exception as e:
                message = f"Lỗi hệ thống: {str(e)}"
                status  = "danger"
    return render_template('change_password.html', message=message, status=status)

# ─────────────────────────────────────────────
#  Dashboard
# ─────────────────────────────────────────────
@app.route('/')
@domain_required
@login_required
def index():
    cfg = current_domain_cfg()
    is_admin = session.get('is_admin', False)
    my_user  = session.get('user')

    ad_users, ad_groups = ([], [])
    ad_error = None
    if is_admin:
        ad_users, ad_groups, ad_error = get_ad_users_and_groups(cfg)
        # Áp dụng bộ lọc OU (nếu admin đã cấu hình) — không chọn OU nào = hiển thị tất cả
        users_ou_filter = get_ou_filter('users')
        if users_ou_filter:
            ad_users = filter_by_ou(ad_users, users_ou_filter, lambda u: u.get('DistinguishedName', ''))
        groups_ou_filter = get_ou_filter('groups')
        if groups_ou_filter:
            ad_groups = filter_by_ou(ad_groups, groups_ou_filter, lambda g: g.get('DistinguishedName', ''))

    software_list = []
    assigned_list = []
    audit_rows    = []
    my_computers  = []
    my_licenses   = []
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        if is_admin:
            cur.execute("""
                SELECT id, software_key, software_name, total_licenses, used_licenses,
                       (total_licenses - used_licenses) AS available_licenses
                FROM software_inventory ORDER BY id DESC
            """)
            software_list = cur.fetchall()

            cur.execute("""
                SELECT us.id, us.sam_account_name, us.software_key, COALESCE(us.quantity,1), us.assigned_at
                FROM user_software us ORDER BY us.id DESC
            """)
            assigned_list = cur.fetchall()

            # Chỉ hiển thị "License Assignment History" cho user thuộc DOMAIN ĐANG ĐĂNG NHẬP —
            # kho license (software_list) phía trên vẫn giữ nguyên dùng chung toàn hệ thống,
            # không lọc gì cả (đúng ý: gán cho user domain nào thì hiện theo domain đó, còn kho
            # là chung). sam_account_name không tự mang thông tin domain, nên lọc bằng cách đối
            # chiếu với danh sách user thật của domain hiện tại (ad_users vừa lấy ở trên).
            # Nếu ad_users rỗng do lỗi tải AD (ad_error) thì bỏ qua lọc để tránh hiểu nhầm
            # "mất lịch sử" trong lúc AD đang lỗi/timeout — chỉ lọc khi có dữ liệu domain thật.
            if ad_users:
                domain_usernames = {u.get('SamAccountName', '').lower() for u in ad_users if u.get('SamAccountName')}
                assigned_list = [row for row in assigned_list if row[1] and row[1].lower() in domain_usernames]

            cur.execute("""
                SELECT id, ts, actor, action, target, detail, ip_address
                FROM audit_log ORDER BY id DESC LIMIT 200
            """)
            audit_rows = cur.fetchall()
        else:
            # User thường: CHỈ lấy đúng computer/license của chính họ — không đụng tới
            # dữ liệu của người khác hay danh sách AD user/group toàn công ty.
            cur.execute("""
                SELECT c.id, c.computer_name, c.cpu, c.ram, c.status, c.asset_code,
                       c.device_type, c.brand, c.model, c.ssd, c.hdd, c.bitlocker, c.location
                FROM user_computers uc JOIN computers c ON c.id = uc.computer_id
                WHERE uc.sam_account_name = %s ORDER BY c.id DESC
            """, (my_user,))
            my_computers = cur.fetchall()

            cur.execute("""
                SELECT us.software_key, COALESCE(us.quantity,1), us.assigned_at
                FROM user_software us WHERE us.sam_account_name = %s ORDER BY us.id DESC
            """, (my_user,))
            my_licenses = cur.fetchall()
    except Exception as e:
        print(f"DB Fetch Error: {e}")
    finally:
        cur.close()
        conn.close()

    return render_template(
        'index.html',
        ad_users=ad_users,
        ad_groups=ad_groups,
        ad_error=ad_error,
        software_list=software_list,
        assigned_list=assigned_list,
        audit_rows=audit_rows,
        my_computers=my_computers,
        my_licenses=my_licenses,
        domain_info=cfg
    )

# ─────────────────────────────────────────────
#  Tạo user AD
# ─────────────────────────────────────────────
#  Street mặc định cho MỌI user được tạo qua portal này (theo yêu cầu công ty)
DEFAULT_USER_STREET = "AIT"

@app.route('/create-user', methods=['POST'])
@domain_required
@admin_required
def create_user():
    domain_id = request.form.get('domain_id', '').strip()
    # Nếu admin có chọn domain cụ thể (hỗ trợ nhiều domain, vd .local nội bộ và .vn Azure/O365)
    # thì dùng đúng domain đó; nếu không chọn thì fallback về domain đang active như trước.
    cfg = get_domain_config_by_id(domain_id) if domain_id else current_domain_cfg()
    if not cfg:
        return jsonify({"status": "error", "message": "Domain đã chọn không hợp lệ hoặc không còn tồn tại. Vui lòng chọn lại domain."})

    sam_account_name = request.form.get('sam_account_name')
    full_name        = request.form.get('full_name')
    password         = request.form.get('password')
    ou_dn            = request.form.get('ou_dn')
    upn_suffix       = request.form.get('upn_suffix', '').strip()
    group_ids        = request.form.getlist('group_ids[]')

    if not sam_account_name or not sam_account_name.strip():
        return jsonify({"status": "error", "message": "Vui lòng nhập SamAccountName."})
    if not ou_dn or not ou_dn.strip():
        return jsonify({"status": "error", "message": "Vui lòng chọn OU."})

    if not password or not password.strip():
        password = "AureoleIT@2026!@#"

    # Domain đăng nhập (UPN) — nếu admin chọn cụ thể (vd @aureole.local) thì dùng đúng suffix đó,
    # nếu không thì mặc định theo domain suffix của domain đang dùng.
    if upn_suffix:
        upn = f"{sam_account_name}@{upn_suffix.lstrip('@')}"
    else:
        upn = f"{sam_account_name}{cfg['domain_suffix']}"

    ps_cmd = (
        f"Import-Module ActiveDirectory -DisableNameChecking; "
        f"New-ADUser -SamAccountName '{ps_quote(sam_account_name)}' -Name '{ps_quote(full_name)}' "
        f"-AccountPassword (ConvertTo-SecureString '{ps_quote(password)}' -AsPlainText -Force) "
        f"-Path '{ps_quote(ou_dn)}' -UserPrincipalName '{ps_quote(upn)}' "
        f"-StreetAddress '{ps_quote(DEFAULT_USER_STREET)}' -Enabled $true"
    )
    for group_id in group_ids:
        if group_id and group_id.strip():
            ps_cmd += f" ; Add-ADGroupMember -Identity '{ps_quote(group_id)}' -Members '{ps_quote(sam_account_name)}'"

    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    write_log(
        session['user'], 'CREATE_USER',
        target=sam_account_name,
        detail=f"FullName={full_name}, OU={ou_dn}, Groups={','.join(group_ids)}, Domain={cfg.get('domain_suffix')}, exit={ec}"
    )
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Tạo user thất bại (không rõ lý do)."})
    return jsonify({"status": "success", "username": sam_account_name})

# ─────────────────────────────────────────────
#  Tạo Group AD
# ─────────────────────────────────────────────
@app.route('/create-group', methods=['POST'])
@domain_required
@admin_required
def create_group():
    cfg        = current_domain_cfg()
    group_name = request.form.get('group_name', '').strip()
    group_scope = request.form.get('group_scope', 'Global')   # Global/Universal/DomainLocal
    group_type  = request.form.get('group_type', 'Security')  # Security/Distribution
    ou_dn       = request.form.get('ou_dn', '').strip()
    description = request.form.get('description', '').strip()

    if not group_name:
        return jsonify({"status": "error", "message": "Vui lòng nhập tên Group."})

    if not cfg:
        return jsonify({"status": "error", "message": "Chưa kết nối domain."})

    # Nếu không chọn OU, dùng CN=Users
    if not ou_dn:
        base_dn = cfg['base_dn']
        ou_dn   = f"CN=Users,{base_dn}"

    ps_parts = [
        "Import-Module ActiveDirectory -DisableNameChecking",
        f"New-ADGroup -Name '{ps_quote(group_name)}' -SamAccountName '{ps_quote(group_name)}' "
        f"-GroupScope '{ps_quote(group_scope)}' -GroupCategory '{ps_quote(group_type)}' "
        f"-Path '{ps_quote(ou_dn)}'"
    ]
    if description:
        ps_parts[-1] += f" -Description '{ps_quote(description)}'"

    out, err, ec = run_powershell_ssh(' ; '.join(ps_parts), cfg, return_stderr=True)
    write_log(session['user'], 'CREATE_GROUP', target=group_name,
              detail=f"scope={group_scope}, type={group_type}, ou={ou_dn}, exit={ec}")
    # Trước đây lỗi thật từ AD (vd trùng tên, sai OU, thiếu quyền...) bị nuốt âm thầm —
    # trang vẫn redirect như thành công dù group KHÔNG được tạo. Giờ trả lỗi thật cho frontend.
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Tạo group thất bại (không rõ lý do)."})
    return jsonify({"status": "success", "group": group_name})

# ─────────────────────────────────────────────
#  Edit user AD
# ─────────────────────────────────────────────
@app.route('/edit-user-ad', methods=['POST'])
@domain_required
@admin_required
def edit_user_ad():
    cfg          = current_domain_cfg()
    username     = request.form.get('edit_username', '').strip()
    new_sam      = request.form.get('edit_new_sam', '').strip()
    display_name = request.form.get('edit_display_name', '').strip()
    password     = request.form.get('edit_password', '').strip()
    status       = request.form.get('edit_status', 'true')
    new_ou       = request.form.get('edit_ou_dn', '').strip()
    upn_suffix   = request.form.get('edit_upn_suffix', '').strip()
    details      = []
    errors       = []  # lỗi thực tế trả về cho frontend, KHÔNG âm thầm nuốt như trước

    # Identity dùng xuyên suốt — cập nhật sau mỗi bước đổi tên/OU
    current_identity = ps_quote(username)

    # 1. Đổi tên hiển thị (AD Rename — CN + DisplayName)
    if display_name:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; "
            f"$u = Get-ADUser -Identity '{current_identity}' -Properties DistinguishedName; "
            f"Rename-ADObject -Identity $u.DistinguishedName -NewName '{ps_quote(display_name)}'; "
            f"Set-ADUser -Identity '{current_identity}' -DisplayName '{ps_quote(display_name)}' -GivenName '{ps_quote(display_name)}'",
            cfg, return_stderr=True)
        details.append(f"rename_cn={display_name} exit={ec}")
        if ec != 0: errors.append(f"Đổi tên hiển thị thất bại: {err.strip() or 'lỗi không rõ'}")
        # SamAccountName không đổi khi Rename-ADObject, current_identity vẫn dùng được

    # 2. Đổi mật khẩu
    if password:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; Set-ADAccountPassword -Identity '{current_identity}' "
            f"-NewPassword (ConvertTo-SecureString '{ps_quote(password)}' -AsPlainText -Force) -Reset",
            cfg, return_stderr=True)
        details.append(f"password_reset exit={ec}")
        if ec != 0: errors.append(f"Đổi mật khẩu thất bại: {err.strip() or 'lỗi không rõ'} "
                                   f"(thường do mật khẩu không đủ độ phức tạp theo chính sách domain — "
                                   f"cần chữ hoa, chữ thường, số, ký tự đặc biệt, tối thiểu ~8 ký tự)")

    # 3. Enable/Disable
    if status == "true":
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; Enable-ADAccount -Identity '{current_identity}'",
            cfg, return_stderr=True)
        details.append(f"enabled=true exit={ec}")
        if ec != 0: errors.append(f"Enable account thất bại: {err.strip() or 'lỗi không rõ'}")
    else:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; Disable-ADAccount -Identity '{current_identity}'",
            cfg, return_stderr=True)
        details.append(f"enabled=false exit={ec}")
        if ec != 0: errors.append(f"Disable account thất bại: {err.strip() or 'lỗi không rõ'}")

    # 4. Di chuyển OU
    if new_ou:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; "
            f"$u = Get-ADUser -Identity '{current_identity}' -Properties DistinguishedName; "
            f"Move-ADObject -Identity $u.DistinguishedName -TargetPath '{ps_quote(new_ou)}'",
            cfg, return_stderr=True)
        details.append(f"move_ou={new_ou} exit={ec}")
        if ec != 0: errors.append(f"Di chuyển OU thất bại: {err.strip() or 'lỗi không rõ'}")

    # 5. Đổi SamAccountName (username đăng nhập) và/hoặc domain đăng nhập (UPN suffix) —
    #    hai việc này độc lập nhau: có thể chỉ đổi UPN (vd @pv.local -> @aureole.local) mà
    #    không cần đổi SamAccountName, giống thao tác ở tab Account trong ADUC.
    sam_changed = bool(new_sam and new_sam != username)
    if sam_changed or upn_suffix:
        final_sam = new_sam if sam_changed else username
        if upn_suffix:
            upn = f"{final_sam}@{upn_suffix.lstrip('@')}"
        else:
            upn = f"{final_sam}{cfg['domain_suffix']}"

        set_args = []
        if sam_changed:
            set_args.append(f"-SamAccountName '{ps_quote(final_sam)}'")
        set_args.append(f"-UserPrincipalName '{ps_quote(upn)}'")

        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory -DisableNameChecking; "
            f"Set-ADUser -Identity '{current_identity}' {' '.join(set_args)}",
            cfg, return_stderr=True)
        details.append(f"sam={username}->{final_sam}, upn={upn} exit={ec}")
        if ec != 0: errors.append(f"Đổi username/domain đăng nhập thất bại: {err.strip() or 'lỗi không rõ'}")

    write_log(session['user'], 'EDIT_USER', target=username, detail='; '.join(details))

    if errors:
        return jsonify({"status": "error", "message": " | ".join(errors)})
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  License inventory
# ─────────────────────────────────────────────
@app.route('/save-software-inventory', methods=['POST'])
@domain_required
@admin_required
def save_software_inventory():
    # Xác thực mật khẩu admin trước khi lưu
    admin_pass = request.form.get('admin_pass', '').strip()
    cfg        = current_domain_cfg()
    if not admin_pass or admin_pass != cfg['ssh_pass']:
        return "<script>alert('Mật khẩu Administrator không chính xác!');history.back();</script>", 403

    row_id        = request.form.get('row_id')
    software_key  = request.form.get('software_key')
    software_name = request.form.get('software_name')
    total_licenses = int(request.form.get('total_licenses', 0))

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        if row_id and row_id.strip():
            cur.execute("""
                UPDATE software_inventory
                SET software_key=%s, software_name=%s, total_licenses=%s
                WHERE id=%s
            """, (software_key, software_name, total_licenses, int(row_id)))
            write_log(session['user'], 'EDIT_LICENSE', target=software_key,
                      detail=f"name={software_name}, total={total_licenses}, id={row_id}")
        else:
            cur.execute("""
                INSERT INTO software_inventory (software_key, software_name, total_licenses, used_licenses)
                VALUES (%s, %s, %s, 0)
                ON CONFLICT (software_key)
                DO UPDATE SET total_licenses=EXCLUDED.total_licenses, software_name=EXCLUDED.software_name
            """, (software_key, software_name, total_licenses))
            write_log(session['user'], 'ADD_LICENSE', target=software_key,
                      detail=f"name={software_name}, total={total_licenses}")
        conn.commit()
    except Exception as e:
        print(f"Inventory Save Error: {e}")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
#  Delete license
# ─────────────────────────────────────────────
@app.route('/delete-software/<int:row_id>', methods=['POST'])
@domain_required
@admin_required
def delete_software(row_id):
    cfg        = current_domain_cfg()
    data       = request.get_json()
    input_pass = data.get('admin_pass')
    correct    = cfg['ssh_pass']

    if input_pass != correct:
        return jsonify({"status": "error", "message": "Mật khẩu Admin không chính xác!"}), 403

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT software_key, software_name FROM software_inventory WHERE id=%s", (row_id,))
        row = cur.fetchone()
        cur.execute("DELETE FROM software_inventory WHERE id=%s", (row_id,))
        conn.commit()
        if row:
            write_log(session['user'], 'DELETE_LICENSE', target=row[0],
                      detail=f"name={row[1]}, id={row_id}")
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cur.close()
        conn.close()

# ─────────────────────────────────────────────
#  Assign license
# ─────────────────────────────────────────────
@app.route('/assign-software-direct', methods=['POST'])
@domain_required
@admin_required
def assign_software_direct():
    sam_account_name = request.form.get('sam_account_name')
    software_key     = request.form.get('software_key')
    quantity         = int(request.form.get('quantity', 1))

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT (total_licenses - used_licenses) FROM software_inventory WHERE software_key=%s",
            (software_key,)
        )
        row = cur.fetchone()
        if not row or row[0] < quantity:
            return redirect(url_for('index'))

        cur.execute("""
            INSERT INTO user_software (sam_account_name, software_key, quantity, assigned_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (sam_account_name, software_key)
            DO UPDATE SET
                quantity    = user_software.quantity + EXCLUDED.quantity,
                assigned_at = NOW()
        """, (sam_account_name, software_key, quantity))

        cur.execute("""
            UPDATE software_inventory SET used_licenses = used_licenses + %s
            WHERE software_key=%s
        """, (quantity, software_key))

        conn.commit()
        write_log(session['user'], 'ASSIGN_LICENSE', target=sam_account_name,
                  detail=f"key={software_key}, qty={quantity}")
    except Exception as e:
        conn.rollback()
        print(f"Assign Error: {e}")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
#  Export CSV
# ─────────────────────────────────────────────
@app.route('/export-licenses-csv')
@domain_required
@admin_required
def export_licenses_csv():
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT sam_account_name, software_key, quantity, assigned_at FROM user_software ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['User tài khoản', 'Mã Bản Quyền', 'Số Lượng', 'Thời Gian Gắn'])
    for r in rows:
        cw.writerow([r[0], r[1], r[2], r[3].strftime('%Y-%m-%d %H:%M:%S') if r[3] else ''])

    write_log(session['user'], 'EXPORT_CSV', detail='Exported license assignment CSV')
    output = make_response(si.getvalue().encode('utf-8-sig'))
    output.headers["Content-Disposition"] = "attachment; filename=assigned_licenses.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

# ─────────────────────────────────────────────
#  Export Audit Log CSV
# ─────────────────────────────────────────────
@app.route('/export-audit-csv')
@domain_required
@admin_required
def export_audit_csv():
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT id, ts, actor, action, target, detail, ip_address FROM audit_log ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Thời Gian', 'Người Thực Hiện', 'Hành Động', 'Đối Tượng', 'Chi Tiết', 'IP'])
    for r in rows:
        cw.writerow([r[0], r[1].strftime('%Y-%m-%d %H:%M:%S') if r[1] else '', r[2], r[3], r[4], r[5], r[6]])

    output = make_response(si.getvalue().encode('utf-8-sig'))
    output.headers["Content-Disposition"] = "attachment; filename=audit_log.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

# ─────────────────────────────────────────────
#  Xóa toàn bộ Audit Log
# ─────────────────────────────────────────────
@app.route('/api/clear-audit-log', methods=['POST'])
@domain_required
@admin_required
def api_clear_audit_log():
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM audit_log")
        total = cur.fetchone()[0]
        cur.execute("DELETE FROM audit_log")
        conn.commit()
        # Ghi lại chính hành động xóa log — để vẫn còn dấu vết ai đã xóa log lúc nào
        write_log(session['user'], 'CLEAR_AUDIT_LOG', detail=f"Đã xóa {total} dòng log cũ")
        return jsonify({"status":"success","deleted":total})
    except Exception as e:
        conn.rollback(); return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

# ─────────────────────────────────────────────
#  Log hành động In/Xuất Biên Bản Bàn Giao Thiết Bị
# ─────────────────────────────────────────────
@app.route('/api/log-handover', methods=['POST'])
@domain_required
@admin_required
def api_log_handover():
    data = request.get_json() or {}
    username  = data.get('username', '')
    full_name = data.get('full_name', '')
    devices   = data.get('devices', [])  # ["PC1 (Laptop Dell)", ...]
    device_summary = ', '.join(devices) if devices else 'không có thiết bị (chỉ tài khoản)'
    write_log(session['user'], 'HANDOVER_DEVICE', target=f"{full_name} ({username})",
              detail=f"In biên bản bàn giao — Thiết bị: {device_summary}")
    return jsonify({"status":"success"})

# ─────────────────────────────────────────────
#  API — user licenses
# ─────────────────────────────────────────────
@app.route('/api/cache-status')
@domain_required
@login_required
def api_cache_status():
    """Trả về trạng thái cache AD của domain thuộc session hiện tại — dùng để biết khi nào
    data sẵn sàng."""
    cfg = current_domain_cfg()
    entry = _AD_CACHE.get(cfg.get('ssh_host')) if cfg else None
    age = (time.time() - entry['ts']) if entry else None
    ready = bool(entry and entry.get('users') is not None and age is not None and age < _AD_CACHE_TTL)
    return jsonify({
        "ready": ready,
        "user_count": len(entry['users']) if entry and entry.get('users') else 0,
        "group_count": len(entry['groups']) if entry and entry.get('groups') else 0,
        "cache_age_sec": round(age, 1) if age else None,
    })

@app.route('/api/refresh-cache', methods=['POST'])
@domain_required
@login_required
def api_refresh_cache():
    """Force refresh AD cache trong background."""
    cfg = current_domain_cfg()
    import threading
    threading.Thread(target=get_ad_users_and_groups, args=(cfg, True), daemon=True).start()
    return jsonify({"status": "refreshing"})

@app.route('/api/user-licenses/<username>')
@domain_required
@login_required
def api_user_licenses(username):
    # Chỉ admin mới được xem license của người khác; user thường chỉ xem được của chính mình.
    if not session.get('is_admin', False) and username != session.get('user'):
        return jsonify({"status": "error", "message": "Bạn không có quyền xem license của tài khoản khác."}), 403
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT software_key, quantity FROM user_software WHERE sam_account_name=%s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"licenses": [{"key": r[0], "quantity": r[1]} for r in rows]})

# ─────────────────────────────────────────────
#  Export Users CSV
# ─────────────────────────────────────────────
@app.route('/export-users-csv')
@domain_required
@admin_required
def export_users_csv():
    cfg = current_domain_cfg()
    ps_cmd = (
        "Get-ADUser -Filter * -Properties MemberOf,Enabled | "
        "Select-Object SamAccountName,Name,Enabled,"
        "@{Name='Groups';Expression={($_.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=',''}) -join ';'}} | "
        "ConvertTo-Json -Compress"
    )
    raw = run_powershell_ssh(ps_cmd, cfg)
    users = []
    try:
        parsed = json.loads(raw)
        users = [parsed] if isinstance(parsed, dict) else parsed
    except Exception:
        pass
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Username', 'Full Name', 'Status', 'Groups'])
    for u in users:
        cw.writerow([u.get('SamAccountName',''), u.get('Name',''),
                     'Active' if u.get('Enabled') else 'Disabled', u.get('Groups','')])
    write_log(session['user'], 'EXPORT_CSV', detail='Exported AD users CSV')
    output = make_response(si.getvalue().encode('utf-8-sig'))
    output.headers["Content-Disposition"] = "attachment; filename=ad_users.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

# ─────────────────────────────────────────────
#  API — get group members
# ─────────────────────────────────────────────
@app.route('/api/group-members/<group_name>')
@domain_required
@admin_required
def api_group_members(group_name):
    cfg    = current_domain_cfg()
    ps_cmd = (
        f"Get-ADGroupMember -Identity '{ps_quote(group_name)}' | "
        f"Select-Object SamAccountName, Name | "
        f"Sort-Object Name | ConvertTo-Json -Compress"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    try:
        members = json.loads(out.strip())
        if isinstance(members, dict): members = [members]
        elif not isinstance(members, list): members = []
        result = [{"sam": m.get("SamAccountName",""), "name": m.get("Name","")} for m in members]
    except Exception:
        result = []
    return jsonify({"members": result, "group": group_name})

# ─────────────────────────────────────────────
#  API — get AD groups (custom only)
# ─────────────────────────────────────────────
@app.route('/api/upn-suffixes')
@domain_required
@admin_required
def api_get_upn_suffixes():
    domain_id = request.args.get('domain_id', '').strip()
    cfg = get_domain_config_by_id(domain_id) if domain_id else current_domain_cfg()
    if not cfg:
        return jsonify({"suffixes": []})
    return jsonify({"suffixes": get_upn_suffixes(cfg)})

@app.route('/api/domains')
@domain_required
@admin_required
def api_get_domains():
    """Danh sách các domain đã từng kết nối — dùng cho dropdown chọn domain lúc tạo user
    (hỗ trợ trường hợp công ty có nhiều domain, vd .local nội bộ và .vn Azure/O365)."""
    return jsonify({"domains": list_domain_configs()})

@app.route('/api/active-domains')
@domain_required
@login_required
def api_get_active_domains():
    """Danh sách domain ĐANG active (đã kết nối, sẵn sàng đăng nhập) — dùng cho popup
    'Chuyển Domain Nhanh' ở sidebar. Khác với /api/domains (toàn bộ lịch sử, chỉ admin xem
    được), route này cho MỌI user đã đăng nhập xem, vì chỉ là danh sách để chọn domain khác
    đăng nhập vào, không phải dữ liệu quản trị nhạy cảm."""
    return jsonify({"domains": list_active_domain_configs()})

@app.route('/api/groups')
@domain_required
@admin_required
def api_get_groups():
    domain_id = request.args.get('domain_id', '').strip()
    cfg = get_domain_config_by_id(domain_id) if domain_id else current_domain_cfg()
    # Cùng logic loại trừ như get_ad_users_and_groups() ở trên: loại theo TÊN group hệ thống
    # mặc định, không loại theo container CN=Users (admin có thể tạo group thật ở đó).
    _default_group_names = (
        "'Domain Computers','Domain Controllers','Domain Guests','Domain Users',"
        "'Domain Admins','Enterprise Admins','Schema Admins','Group Policy Creator Owners',"
        "'Read-only Domain Controllers','Enterprise Read-only Domain Controllers',"
        "'Cloneable Domain Controllers','Protected Users','Key Admins','Enterprise Key Admins',"
        "'DnsAdmins','DnsUpdateProxy','RAS and IAS Servers',"
        "'Allowed RODC Password Replication Group','Denied RODC Password Replication Group',"
        "'Cert Publishers'"
    )
    ps_cmd = (
        f"$defaultNames = @({_default_group_names}); "
        "Get-ADGroup -Filter * -Properties DistinguishedName | "
        "Where-Object { $_.Name -eq 'Administrators' -or "
        "($_.DistinguishedName -notmatch 'CN=Builtin' -and $_.Name -notin $defaultNames) } | "
        "Select-Object -ExpandProperty Name | Sort-Object | ConvertTo-Json -Compress"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    try:
        groups = json.loads(out.strip())
        if isinstance(groups, str): groups = [groups]
        elif not isinstance(groups, list): groups = []
    except Exception:
        groups = []
    return jsonify({"groups": groups})

# ─────────────────────────────────────────────
#  API — get all OUs
# ─────────────────────────────────────────────
@app.route('/api/ous')
@domain_required
@admin_required
def api_get_ous():
    domain_id = request.args.get('domain_id', '').strip()
    cfg = get_domain_config_by_id(domain_id) if domain_id else current_domain_cfg()
    # Ngoài các OU thật, bổ sung 2 container mặc định của AD — không phải OU thật nên
    # Get-ADOrganizationalUnit không trả về, phải lấy riêng qua Get-ADDomain:
    #  - "Computers": nơi máy mới join domain tự rơi vào (ComputersContainer)
    #  - "Users":     nơi user/group mặc định của AD nằm khi không được đặt OU cụ thể
    #                 (vd group "Administrators", "Domain Admins"... và cả group admin tự
    #                 tạo mà không chỉ định -Path) (UsersContainer)
    # Cả 2 đều tôn trọng trường hợp đã bị redirect bằng redircmp.exe / redirusr.exe.
    ps_cmd = (
        "Import-Module ActiveDirectory -DisableNameChecking; "
        "$ou = @(Get-ADOrganizationalUnit -Filter * -Properties Name,DistinguishedName | "
        "Select-Object Name,DistinguishedName,@{Name='IsContainer';Expression={$false}}); "
        "$cc = (Get-ADDomain).ComputersContainer; "
        "$uc = (Get-ADDomain).UsersContainer; "
        "$computersContainer = [PSCustomObject]@{ Name='Computers'; DistinguishedName=$cc; IsContainer=$true }; "
        "$usersContainer     = [PSCustomObject]@{ Name='Users';     DistinguishedName=$uc; IsContainer=$true }; "
        "$all = @($computersContainer) + @($usersContainer) + $ou; "
        "$all | Sort-Object DistinguishedName | ConvertTo-Json -Compress"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    try:
        ous = json.loads(out.strip())
        if isinstance(ous, dict): ous = [ous]
        elif not isinstance(ous, list): ous = []
        result = [{"name": o.get("Name",""), "dn": o.get("DistinguishedName",""),
                   "is_container": bool(o.get("IsContainer"))} for o in ous if o.get("DistinguishedName")]
    except Exception:
        result = []
    return jsonify({"ous": result})

# ─────────────────────────────────────────────
#  API — bộ lọc OU hiển thị (theo khu vực: users / computers)
# ─────────────────────────────────────────────
@app.route('/api/ou-filter/<section>', methods=['GET'])
@domain_required
@admin_required
def api_get_ou_filter(section):
    if section not in _OU_FILTER_SECTIONS:
        return jsonify({"status": "error", "message": "Khu vực không hợp lệ"}), 400
    return jsonify({"section": section, "selected": get_ou_filter(section)})

@app.route('/api/ou-filter/<section>', methods=['POST'])
@domain_required
@admin_required
def api_save_ou_filter(section):
    if section not in _OU_FILTER_SECTIONS:
        return jsonify({"status": "error", "message": "Khu vực không hợp lệ"}), 400
    data = request.get_json() or {}
    ou_list = data.get('ous') or []
    if not isinstance(ou_list, list):
        return jsonify({"status": "error", "message": "Dữ liệu không hợp lệ"}), 400

    saved = save_ou_filter(section, ou_list)
    if saved is None:
        return jsonify({"status": "error", "message": "Lưu cấu hình thất bại (DB error)"})

    section_label = 'Users' if section == 'users' else 'Computers'
    write_log(session['user'], 'SAVE_OU_FILTER', target=section,
              detail=f"{section_label}: {len(saved)} OU được chọn" + (f" ({', '.join(saved)})" if saved else " (bỏ lọc, hiện tất cả)"))
    return jsonify({"status": "success", "selected": saved})

# ─────────────────────────────────────────────
#  API — move computer sang OU khác trong AD
# ─────────────────────────────────────────────
@app.route('/api/move-domain-computer', methods=['POST'])
@domain_required
@admin_required
def api_move_domain_computer():
    cfg = current_domain_cfg()
    data = request.get_json() or {}
    dn      = (data.get('dn') or '').strip()
    new_ou  = (data.get('new_ou') or '').strip()
    name    = (data.get('name') or '').strip()

    if not dn or not new_ou:
        return jsonify({"status": "error", "message": "Thiếu Distinguished Name hoặc OU đích"})

    ps_cmd = (
        f"Import-Module ActiveDirectory -DisableNameChecking; "
        f"Move-ADObject -Identity '{ps_quote(dn)}' -TargetPath '{ps_quote(new_ou)}'"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Move thất bại"})

    write_log(session['user'], 'MOVE_COMPUTER', target=name or dn,
              detail=f"Chuyển '{name or dn}' sang OU: {new_ou}")
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  API — move group sang OU khác trong AD
# ─────────────────────────────────────────────
@app.route('/api/move-group', methods=['POST'])
@domain_required
@admin_required
def api_move_group():
    cfg = current_domain_cfg()
    data = request.get_json() or {}
    dn      = (data.get('dn') or '').strip()
    new_ou  = (data.get('new_ou') or '').strip()
    name    = (data.get('name') or '').strip()

    if not dn or not new_ou:
        return jsonify({"status": "error", "message": "Thiếu Distinguished Name hoặc OU đích"})

    ps_cmd = (
        f"Import-Module ActiveDirectory -DisableNameChecking; "
        f"Move-ADObject -Identity '{ps_quote(dn)}' -TargetPath '{ps_quote(new_ou)}'"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Move thất bại"})

    write_log(session['user'], 'MOVE_GROUP', target=name or dn,
              detail=f"Chuyển group '{name or dn}' sang OU: {new_ou}")
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  API — sửa tên / description của group
# ─────────────────────────────────────────────
@app.route('/api/edit-group', methods=['POST'])
@domain_required
@admin_required
def api_edit_group():
    cfg = current_domain_cfg()
    data = request.get_json() or {}
    dn          = (data.get('dn') or '').strip()
    old_name    = (data.get('old_name') or '').strip()
    new_name    = (data.get('name') or '').strip()
    description = data.get('description', '') or ''

    if not dn:
        return jsonify({"status": "error", "message": "Thiếu Distinguished Name của group"})
    if not new_name:
        return jsonify({"status": "error", "message": "Tên group không được để trống"})

    # Dùng ObjectGUID để định danh group xuyên suốt các lệnh — vì Rename-ADObject đổi cả DN
    # của group (CN=<tên cũ> -> CN=<tên mới>), nếu vẫn dùng DN cũ cho các lệnh SAU rename sẽ
    # báo lỗi "object không tồn tại". ObjectGUID không đổi bất kể đổi tên/di chuyển OU.
    desc_cmd = (
        f"Set-ADGroup -Identity $grp.ObjectGUID -Description '{ps_quote(description)}'"
        if description.strip()
        else "Set-ADGroup -Identity $grp.ObjectGUID -Clear Description"
    )
    ps_cmd = (
        "Import-Module ActiveDirectory -DisableNameChecking; "
        f"$grp = Get-ADGroup -Identity '{ps_quote(dn)}'; "
    )
    if new_name != old_name:
        ps_cmd += f"Rename-ADObject -Identity $grp.ObjectGUID -NewName '{ps_quote(new_name)}'; "
    ps_cmd += desc_cmd

    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Cập nhật group thất bại"})

    write_log(session['user'], 'EDIT_GROUP', target=new_name,
              detail=f"dn={dn}, old_name={old_name}, new_name={new_name}, description={description[:200]}")
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  API — remove user from group
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  Computer Asset CRUD
# ─────────────────────────────────────────────
@app.route('/api/computers', methods=['GET'])
@domain_required
@admin_required
def api_get_computers():
    conn = get_db_connection(); cur = conn.cursor()
    try:
        # Lấy assigned_user từ bảng user_computers (nguồn chân lý duy nhất),
        # gộp nhiều user thành chuỗi nếu 1 máy gán cho nhiều người
        cur.execute("""
            SELECT c.id, c.asset_code, c.device_type, c.computer_name, c.location, c.brand, c.model,
                   c.cpu, c.ram, c.ssd, c.hdd, c.bitlocker, c.status, c.notes, c.updated_at,
                   COALESCE(string_agg(uc.sam_account_name, ', ' ORDER BY uc.sam_account_name), '') AS assigned_users
            FROM computers c
            LEFT JOIN user_computers uc ON uc.computer_id = c.id
            GROUP BY c.id
            ORDER BY c.id DESC
        """)
        rows = cur.fetchall()
        cols = ['id','asset_code','device_type','computer_name','location','brand','model',
                'cpu','ram','ssd','hdd','bitlocker','status','notes','updated_at','assigned_user']
        result = []
        for r in rows:
            d = dict(zip(cols, r))
            if d['updated_at']: d['updated_at'] = d['updated_at'].strftime('%d/%m/%Y')
            result.append(d)
        return jsonify({"computers": result})
    finally: cur.close(); conn.close()

@app.route('/api/computers', methods=['POST'])
@domain_required
@admin_required
def api_create_computer():
    data = request.get_json()
    asset_code = (data.get('asset_code') or '').strip()
    conn = get_db_connection(); cur = conn.cursor()
    try:
        if asset_code:
            cur.execute("SELECT computer_name FROM computers WHERE TRIM(asset_code)=%s", (asset_code,))
            dup = cur.fetchone()
            if dup:
                return jsonify({"status":"error","message":f"Mã tài sản \"{asset_code}\" đã tồn tại (máy: {dup[0]}). Vui lòng nhập mã khác."})

        cur.execute("""
            INSERT INTO computers
              (asset_code,device_type,computer_name,location,brand,model,cpu,ram,ssd,hdd,bitlocker,status,notes,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()) RETURNING id
        """, (asset_code, data.get('device_type',''), data.get('computer_name',''),
              data.get('location',''), data.get('brand',''), data.get('model',''),
              data.get('cpu',''), data.get('ram',''), data.get('ssd',''), data.get('hdd',''),
              data.get('bitlocker',''), data.get('status','in_use'), data.get('notes','')))
        new_id = cur.fetchone()[0]

        # Nếu có gán user ngay lúc tạo, ghi vào user_computers (nguồn chân lý duy nhất)
        assigned_user = (data.get('assigned_user') or '').strip()
        if assigned_user:
            cur.execute(
                "INSERT INTO user_computers (sam_account_name, computer_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                (assigned_user, new_id)
            )

        conn.commit()
        detail_parts = [f"Model: {data.get('model') or '—'}", f"CPU: {data.get('cpu') or '—'}", f"RAM: {data.get('ram') or '—'}"]
        if assigned_user: detail_parts.append(f"Gán cho: {assigned_user}")
        write_log(session['user'], 'CREATE_COMPUTER', target=data.get('computer_name'),
                  detail=f"Tạo máy mới ({', '.join(detail_parts)})")
        return jsonify({"status":"success","id":new_id})
    except Exception as e:
        conn.rollback(); return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

@app.route('/api/computers/<int:cid>', methods=['PUT'])
@domain_required
@admin_required
def api_update_computer(cid):
    data = request.get_json()
    asset_code = (data.get('asset_code') or '').strip()
    conn = get_db_connection(); cur = conn.cursor()
    try:
        if asset_code:
            cur.execute("SELECT computer_name FROM computers WHERE TRIM(asset_code)=%s AND id<>%s", (asset_code, cid))
            dup = cur.fetchone()
            if dup:
                return jsonify({"status":"error","message":f"Mã tài sản \"{asset_code}\" đã tồn tại (máy: {dup[0]}). Vui lòng nhập mã khác."})

        # Lấy dữ liệu cũ để so sánh, phục vụ ghi log chi tiết những gì đã thay đổi
        field_labels = {
            'asset_code':'Mã TS','device_type':'Thiết bị','computer_name':'Tên','location':'Vị trí',
            'brand':'Hãng','model':'Model','cpu':'CPU','ram':'RAM','ssd':'SSD','hdd':'HDD',
            'bitlocker':'Bitlocker','status':'Trạng thái','notes':'Ghi chú'
        }
        cur.execute(f"SELECT {','.join(field_labels.keys())} FROM computers WHERE id=%s", (cid,))
        old_row = cur.fetchone()
        old_values = dict(zip(field_labels.keys(), old_row)) if old_row else {}

        new_values = {
            'asset_code': asset_code, 'device_type': data.get('device_type',''), 'computer_name': data.get('computer_name',''),
            'location': data.get('location',''), 'brand': data.get('brand',''), 'model': data.get('model',''),
            'cpu': data.get('cpu',''), 'ram': data.get('ram',''), 'ssd': data.get('ssd',''), 'hdd': data.get('hdd',''),
            'bitlocker': data.get('bitlocker',''), 'status': data.get('status','in_use'), 'notes': data.get('notes','')
        }

        cur.execute("""
            UPDATE computers SET asset_code=%s,device_type=%s,computer_name=%s,location=%s,brand=%s,model=%s,
            cpu=%s,ram=%s,ssd=%s,hdd=%s,bitlocker=%s,status=%s,notes=%s,updated_at=NOW()
            WHERE id=%s
        """, (asset_code, data.get('device_type',''), data.get('computer_name',''),
              data.get('location',''), data.get('brand',''), data.get('model',''),
              data.get('cpu',''), data.get('ram',''), data.get('ssd',''), data.get('hdd',''),
              data.get('bitlocker',''), data.get('status','in_use'), data.get('notes',''), cid))

        # Đồng bộ assigned_user vào user_computers — nguồn chân lý duy nhất.
        # Form Edit Computer chỉ cho gán 1 user nên xóa hết liên kết cũ rồi gán lại.
        old_assigned = None
        if 'assigned_user' in data:
            cur.execute("SELECT string_agg(sam_account_name, ', ') FROM user_computers WHERE computer_id=%s", (cid,))
            r = cur.fetchone(); old_assigned = r[0] if r else None
            assigned_user = (data.get('assigned_user') or '').strip()
            cur.execute("DELETE FROM user_computers WHERE computer_id=%s", (cid,))
            if assigned_user:
                cur.execute(
                    "INSERT INTO user_computers (sam_account_name, computer_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (assigned_user, cid)
                )

        conn.commit()

        # Chỉ liệt kê những trường thực sự thay đổi, cho log dễ đọc
        changes = []
        for key, label in field_labels.items():
            old_v = (old_values.get(key) or '').strip()
            new_v = (new_values.get(key) or '').strip()
            if old_v != new_v:
                changes.append(f"{label}: '{old_v or '—'}' → '{new_v or '—'}'")
        if 'assigned_user' in data:
            new_assigned = (data.get('assigned_user') or '').strip()
            if (old_assigned or '') != new_assigned:
                changes.append(f"User: '{old_assigned or '—'}' → '{new_assigned or '—'}'")

        detail = "; ".join(changes) if changes else "Không có thay đổi"
        write_log(session['user'], 'EDIT_COMPUTER', target=data.get('computer_name'), detail=detail)
        return jsonify({"status":"success"})
    except Exception as e:
        conn.rollback(); return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

@app.route('/api/computers/<int:cid>', methods=['DELETE'])
@domain_required
@admin_required
def api_delete_computer(cid):
    cfg  = current_domain_cfg()
    data = request.get_json(silent=True) or {}
    if not verify_current_user_password(cfg, data.get('password', '')):
        return jsonify({"status": "error", "message": "Mật khẩu không chính xác. Vui lòng nhập lại mật khẩu Administrator để xác nhận xoá."}), 403

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT computer_name FROM computers WHERE id=%s", (cid,))
        row = cur.fetchone()
        cur.execute("DELETE FROM computers WHERE id=%s", (cid,))
        conn.commit()
        write_log(session['user'], 'DELETE_COMPUTER', target=row[0] if row else str(cid))
        return jsonify({"status":"success"})
    except Exception as e:
        conn.rollback(); return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

@app.route('/api/computers/bulk-delete', methods=['POST'])
@domain_required
@admin_required
def api_bulk_delete_computers():
    """Xoá nhiều tài sản máy tính cùng lúc — dùng cho tính năng tick chọn nhiều dòng + Xoá đã
    chọn trong bảng Quản Lý Computer. Yêu cầu xác nhận lại mật khẩu admin trước khi xoá."""
    data = request.get_json() or {}
    if not verify_current_user_password(cfg=current_domain_cfg(), password=data.get('password', '')):
        return jsonify({"status": "error", "message": "Mật khẩu không chính xác. Vui lòng nhập lại mật khẩu Administrator để xác nhận xoá."}), 403

    ids = data.get('ids') or []
    try:
        ids = [int(i) for i in ids]
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Danh sách ID không hợp lệ"})
    if not ids:
        return jsonify({"status": "error", "message": "Chưa chọn dòng nào để xoá"})

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT computer_name FROM computers WHERE id = ANY(%s)", (ids,))
        names = [r[0] for r in cur.fetchall()]
        cur.execute("DELETE FROM computers WHERE id = ANY(%s)", (ids,))
        deleted_count = cur.rowcount
        conn.commit()
        write_log(session['user'], 'BULK_DELETE_COMPUTERS',
                  detail=f"Xoá {deleted_count} máy: {', '.join(names[:20])}" + (f" +{len(names)-20} khác" if len(names) > 20 else ""))
        return jsonify({"status": "success", "deleted_count": deleted_count})
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cur.close(); conn.close()

@app.route('/api/domain-computers')
@domain_required
@admin_required
def api_domain_computers():
    cfg = current_domain_cfg()
    ps  = ("Get-ADComputer -Filter * -Properties OperatingSystem,DistinguishedName | "
           "Select-Object Name,OperatingSystem,DistinguishedName | "
           "Sort-Object Name | ConvertTo-Json -Compress")
    out, err, ec = run_powershell_ssh(ps, cfg, return_stderr=True)
    try:
        comps = json.loads(out.strip())
        if isinstance(comps, dict): comps = [comps]
        elif not isinstance(comps, list): comps = []
        result = [{"name":c.get("Name",""), "os":c.get("OperatingSystem",""), "dn":c.get("DistinguishedName","")} for c in comps]
    except: result = []

    # Áp dụng bộ lọc OU (nếu đã cấu hình) — không chọn OU nào = hiển thị tất cả
    computers_ou_filter = get_ou_filter('computers')
    if computers_ou_filter:
        result = filter_by_ou(result, computers_ou_filter, 'dn')

    return jsonify({"computers": result})

@app.route('/api/domain-computers', methods=['DELETE'])
@domain_required
@admin_required
def api_delete_domain_computer():
    """Xóa 1 computer object khỏi AD — dùng khi máy cần rejoin domain nhưng
    báo lỗi 'đã có trong domain' do computer account cũ chưa được dọn."""
    data = request.get_json() or {}
    dn   = (data.get('dn') or '').strip()
    name = (data.get('name') or '').strip()
    if not dn:
        return jsonify({"status":"error","message":"Thiếu Distinguished Name của máy cần xóa"})

    cfg = current_domain_cfg()
    ps = f"Remove-ADComputer -Identity '{ps_quote(dn)}' -Confirm:$false"
    out, err, ec = run_powershell_ssh(ps, cfg, return_stderr=True)

    if ec == 0:
        write_log(session['user'], 'DELETE_DOMAIN_COMPUTER', target=name or dn,
                  detail=f"Xóa computer object khỏi AD: {dn}")
        return jsonify({"status":"success"})
    return jsonify({"status":"error","message":err.strip() or "Xóa thất bại (kiểm tra quyền hoặc kết nối domain)"})

@app.route('/export-computers-csv')
@domain_required
@admin_required
def export_computers_csv():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT c.asset_code,c.device_type,c.computer_name,c.location,c.brand,c.model,c.cpu,c.ram,c.ssd,c.hdd,c.bitlocker,c.status,
               COALESCE(string_agg(uc.sam_account_name, ', ' ORDER BY uc.sam_account_name), '') AS assigned_user,
               c.notes
        FROM computers c
        LEFT JOIN user_computers uc ON uc.computer_id = c.id
        GROUP BY c.id ORDER BY c.id
    """)
    rows = cur.fetchall(); cur.close(); conn.close()
    si = io.StringIO(); cw = csv.writer(si)
    cw.writerow(['Mã Tài Sản','Thiết Bị','Tên','Vị Trí','Hãng','Model','CPU','RAM','SSD','HDD','Bitlocker','Trạng Thái','User','Ghi Chú'])
    smap = {'in_use':'Đang sử dụng','storage':'Lưu kho'}
    for r in rows:
        row = list(r); row[11] = smap.get(row[11], row[11]); cw.writerow(row)
    write_log(session['user'], 'EXPORT_CSV', detail='Exported computers CSV')
    csv_bytes = si.getvalue().encode('utf-8-sig')  # thêm BOM thật để Excel nhận đúng UTF-8
    output = make_response(csv_bytes)
    output.headers["Content-Disposition"] = "attachment; filename=computers.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

@app.route('/api/import-computers', methods=['POST'])
@domain_required
@admin_required
def api_import_computers():
    if 'file' not in request.files:
        return jsonify({"status":"error","message":"Không có file"})
    import csv as csv_mod, io as io_mod
    f = request.files['file']
    conn = None; cur = None
    try:
        raw = f.stream.read()
        # Excel khi lưu lại CSV tiếng Việt thường không giữ UTF-8 (có thể ra ANSI/Windows-1258/1252).
        # Thử lần lượt các bảng mã phổ biến để tránh crash toàn bộ request.
        text = None
        for enc in ('utf-8-sig', 'utf-8', 'cp1258', 'cp1252', 'latin-1'):
            try:
                text = raw.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue
        if text is None:
            text = raw.decode('utf-8', errors='replace')

        stream = io_mod.StringIO(text)
        reader = csv_mod.DictReader(stream)
        if not reader.fieldnames:
            return jsonify({"status":"error","message":"File CSV rỗng hoặc không đúng định dạng"})

        conn = get_db_connection(); cur = conn.cursor()

        # Lấy trước các mã tài sản đã tồn tại trong DB (kèm id) để biết dòng nào cần UPDATE thay
        # vì INSERT mới. Trước đây gặp mã trùng là bỏ qua hẳn dòng đó (không cập nhật gì) — giờ
        # đổi sang: mã đã tồn tại -> cập nhật lại các cột của đúng bản ghi đó bằng dữ liệu mới
        # trong file import (không tạo thêm dòng mới, không tạo trùng mã).
        cur.execute("SELECT id, TRIM(asset_code) FROM computers WHERE asset_code IS NOT NULL AND TRIM(asset_code) <> ''")
        existing_id_by_code = {code: cid for cid, code in cur.fetchall()}
        created = 0
        updated = 0
        updated_codes = []  # [(asset_code, computer_name)] — để báo cáo lại cho người dùng

        for row in reader:
            asset_code = (row.get('Mã Tài Sản') or row.get('Mã') or '').strip()
            computer_name = row.get('Tên') or row.get('Tên Máy') or ''
            st = 'in_use' if 'dụng' in row.get('Trạng Thái', row.get('Tình Trạng','') or '') else 'storage'
            values = (row.get('Thiết Bị') or row.get('Loại') or '', computer_name,
                      row.get('Vị Trí') or '', row.get('Hãng') or '', row.get('Model') or '',
                      row.get('CPU') or '', row.get('RAM') or '', row.get('SSD') or '', row.get('HDD') or '',
                      row.get('Bitlocker') or '', st, row.get('Ghi Chú') or '')

            existing_id = existing_id_by_code.get(asset_code) if asset_code else None
            if existing_id:
                # Mã tài sản đã có sẵn trong hệ thống (hoặc đã được UPDATE/INSERT ở 1 dòng trước
                # đó trong CÙNG file này) -> cập nhật lại các cột thay vì tạo dòng mới.
                cur.execute("""
                    UPDATE computers SET device_type=%s, computer_name=%s, location=%s, brand=%s,
                        model=%s, cpu=%s, ram=%s, ssd=%s, hdd=%s, bitlocker=%s, status=%s, notes=%s,
                        updated_at=NOW()
                    WHERE id=%s
                """, values + (existing_id,))
                new_id = existing_id
                updated += 1
                updated_codes.append((asset_code, computer_name))
            else:
                cur.execute("""
                    INSERT INTO computers (asset_code,device_type,computer_name,location,brand,model,cpu,ram,ssd,hdd,bitlocker,status,notes,updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()) RETURNING id
                """, (asset_code,) + values)
                new_id = cur.fetchone()[0]
                created += 1
                if asset_code:
                    existing_id_by_code[asset_code] = new_id  # để các dòng SAU trong cùng file (nếu trùng mã) sẽ UPDATE thay vì insert trùng

            # Cột User trong CSV có thể chứa nhiều user cách nhau dấu phẩy
            users_str = (row.get('User','') or '').strip()
            if users_str:
                for u in [x.strip() for x in users_str.split(',') if x.strip()]:
                    cur.execute(
                        "INSERT INTO user_computers (sam_account_name, computer_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (u, new_id)
                    )
        conn.commit()
        update_detail = f", cập nhật {updated} dòng đã có sẵn mã tài sản" if updated else ""
        write_log(session['user'], 'IMPORT_COMPUTERS', detail=f"tạo mới {created} dòng{update_detail}")
        return jsonify({
            "status": "success",
            "count": created,
            "updated_count": updated,
            "updated": [{"asset_code": a, "computer_name": n} for a, n in updated_codes]
        })
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"status":"error","message":str(e)})
    finally:
        if cur: cur.close()
        if conn: conn.close()

# ─────────────────────────────────────────────
#  User-Computer assignment
# ─────────────────────────────────────────────
@app.route('/api/user-computers/<username>')
@domain_required
@login_required
def api_get_user_computers(username):
    # Chỉ admin mới được xem computer của người khác; user thường chỉ xem được của chính mình.
    if not session.get('is_admin', False) and username != session.get('user'):
        return jsonify({"status": "error", "message": "Bạn không có quyền xem computer của tài khoản khác."}), 403
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            SELECT c.id, c.computer_name, c.cpu, c.ram, c.status,
                   c.asset_code, c.device_type, c.brand, c.model, c.ssd, c.hdd, c.bitlocker, c.location
            FROM user_computers uc JOIN computers c ON c.id=uc.computer_id
            WHERE uc.sam_account_name=%s
            ORDER BY c.id DESC
        """, (username,))
        rows = cur.fetchall()
        return jsonify({"computers": [{
            "id":r[0],"computer_name":r[1],"cpu":r[2],"ram":r[3],"status":r[4],
            "asset_code":r[5],"device_type":r[6],"brand":r[7],"model":r[8],
            "ssd":r[9],"hdd":r[10],"bitlocker":r[11],"location":r[12]
        } for r in rows]})
    finally: cur.close(); conn.close()

@app.route('/api/user-computers', methods=['POST'])
@domain_required
@admin_required
def api_assign_computer():
    data = request.get_json()
    username    = data.get('username')
    computer_id = data.get('computer_id')
    if not username or not computer_id:
        return jsonify({"status":"error","message":"Thiếu username hoặc computer_id"})

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT computer_name, asset_code FROM computers WHERE id=%s", (computer_id,))
        crow = cur.fetchone()
        device_label = f"{crow[0]}" + (f" (Mã: {crow[1]})" if crow and crow[1] else "") if crow else f"id={computer_id}"

        # Một máy chỉ được gán cho 1 user tại 1 thời điểm — kiểm tra trước khi gán
        cur.execute("SELECT sam_account_name FROM user_computers WHERE computer_id=%s", (computer_id,))
        existing = cur.fetchone()
        if existing and existing[0] != username:
            return jsonify({
                "status": "error",
                "message": f"Thiết bị {device_label} đang được gán cho user \"{existing[0]}\". "
                           f"Vui lòng thu hồi khỏi \"{existing[0]}\" trước khi gán cho user khác."
            })
        if existing and existing[0] == username:
            return jsonify({"status": "success"})  # đã gán sẵn cho đúng user này, không cần làm gì thêm

        cur.execute("INSERT INTO user_computers (sam_account_name,computer_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (username, computer_id))
        conn.commit()
        write_log(session['user'], 'ASSIGN_COMPUTER', target=username,
                  detail=f"Gán thiết bị {device_label} cho user {username}")
        return jsonify({"status":"success"})
    except Exception as e:
        conn.rollback()
        # Trường hợp race condition: 2 request gán cùng 1 máy gần như đồng thời,
        # unique index (computer_id) trên DB sẽ chặn request tới sau
        err_str = str(e).lower()
        if 'uq_user_computers_computer_id' in err_str or 'duplicate key' in err_str:
            return jsonify({"status":"error","message":"Thiết bị này vừa được gán cho user khác. Vui lòng tải lại và thử lại."})
        return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

@app.route('/api/user-computers', methods=['DELETE'])
@domain_required
@admin_required
def api_unassign_computer():
    data = request.get_json()
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT computer_name, asset_code FROM computers WHERE id=%s", (data['computer_id'],))
        row = cur.fetchone()
        device_label = f"{row[0]}" + (f" (Mã: {row[1]})" if row and row[1] else "") if row else f"id={data['computer_id']}"
        cur.execute("DELETE FROM user_computers WHERE sam_account_name=%s AND computer_id=%s",
                    (data['username'], data['computer_id']))
        conn.commit()
        write_log(session['user'], 'UNASSIGN_COMPUTER', target=data['username'],
                  detail=f"Thu hồi thiết bị {device_label} từ user {data['username']}")
        return jsonify({"status":"success"})
    except Exception as e:
        conn.rollback(); return jsonify({"status":"error","message":str(e)})
    finally: cur.close(); conn.close()

@app.route('/api/remove-user-group', methods=['POST'])
@domain_required
@admin_required
def api_remove_user_group():
    cfg      = current_domain_cfg()
    data     = request.get_json()
    username = data.get('username')
    group    = data.get('group')
    ps_cmd = f"Import-Module ActiveDirectory -DisableNameChecking; Remove-ADGroupMember -Identity '{ps_quote(group)}' -Members '{ps_quote(username)}' -Confirm:0"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    write_log(session['user'], 'REMOVE_FROM_GROUP', target=username, detail=f"group={group} exit={exitcode}")
    # Trước đây luôn trả "success" bất kể exitcode — nếu PowerShell thất bại (vd hết quyền,
    # group/user không tồn tại, SSH lỗi), người dùng vẫn thấy giao diện báo thành công dù group
    # thực ra chưa bị xoá thật trên AD. Giờ kiểm tra đúng exitcode trước khi báo success.
    if exitcode != 0:
        return jsonify({"status": "error", "message": err.strip() or "Xoá khỏi group thất bại (không rõ lý do)."})
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  API — test SSH (debug only)
# ─────────────────────────────────────────────
@app.route('/api/test-ssh', methods=['POST'])
@domain_required
@admin_required
def api_test_ssh():
    cfg  = current_domain_cfg()
    data = request.get_json()
    cmd  = data.get('cmd', 'Get-Date')
    out, err, exitcode = run_powershell_ssh(cmd, cfg, return_stderr=True)
    return jsonify({
        "cmd": cmd,
        "out": out[:2000],
        "err": err[:2000],
        "exitcode": exitcode,
        "cfg_host": cfg['ssh_host'] if cfg else None,
        "cfg_user": cfg['ssh_user'] if cfg else None,
    })

# ─────────────────────────────────────────────
#  API — add user to group
# ─────────────────────────────────────────────
@app.route('/api/add-user-group', methods=['POST'])
@domain_required
@admin_required
def api_add_user_group():
    cfg      = current_domain_cfg()
    data     = request.get_json()
    username = data.get('username')
    group    = data.get('group')

    if not group or not group.strip():
        return jsonify({"status": "error", "message": "Vui lòng chọn group."})

    group = group.strip()
    ps_cmd = f"Import-Module ActiveDirectory -DisableNameChecking; Add-ADGroupMember -Identity '{ps_quote(group)}' -Members '{ps_quote(username)}' -Confirm:0"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    write_log(session['user'], 'ADD_TO_GROUP', target=username, detail=f"group={group} exit={exitcode}")
    # Trước đây luôn trả "success" bất kể exitcode — xem giải thích ở api_remove_user_group.
    if exitcode != 0:
        return jsonify({"status": "error", "message": err.strip() or "Thêm vào group thất bại (không rõ lý do)."})
    return jsonify({"status": "success", "group": group})

# ─────────────────────────────────────────────
#  API — revoke license
# ─────────────────────────────────────────────
@app.route('/api/revoke-license-direct', methods=['POST'])
@domain_required
@admin_required
def api_revoke_license_direct():
    data          = request.get_json()
    username      = data.get('username')
    software_key  = data.get('key')
    qty_to_revoke = int(data.get('quantity', 0))

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT id, quantity FROM user_software WHERE sam_account_name=%s AND software_key=%s ORDER BY id DESC LIMIT 1",
            (username, software_key)
        )
        row = cur.fetchone()
        if row:
            record_id, current_qty = row
            if current_qty > qty_to_revoke:
                cur.execute("UPDATE user_software SET quantity=quantity-%s WHERE id=%s", (qty_to_revoke, record_id))
            else:
                cur.execute("DELETE FROM user_software WHERE id=%s", (record_id,))
            cur.execute(
                "UPDATE software_inventory SET used_licenses=GREATEST(0,used_licenses-%s) WHERE software_key=%s",
                (qty_to_revoke, software_key)
            )
            conn.commit()
            write_log(session['user'], 'REVOKE_LICENSE', target=username,
                      detail=f"key={software_key}, qty_revoked={qty_to_revoke}")
            return jsonify({"status": "success"})
    except Exception as e:
        conn.rollback()
        print(f"Revoke Error: {e}")
    finally:
        cur.close()
        conn.close()
    return jsonify({"status": "error", "message": "Thu hồi thất bại"})

# Chạy init_db() ở module level với retry — đảm bảo chạy được dù
# PostgreSQL container chưa sẵn sàng ngay khi Flask khởi động.
import time as _time
for _attempt in range(10):
    try:
        init_db()
        print(f"[startup] init_db OK (attempt {_attempt + 1})")
        break
    except Exception as _e:
        print(f"[startup] init_db attempt {_attempt + 1}/10 failed: {_e}")
        if _attempt < 9:
            _time.sleep(3)
        else:
            print("[startup] init_db gave up after 10 attempts — DB may be unavailable")

if __name__ == '__main__':
    # debug=False: tắt Werkzeug interactive debugger — nếu bật, khi có lỗi chưa được
    # bắt (unhandled exception) sẽ hiện console Python tương tác ngay trên trình duyệt,
    # có thể dẫn tới thực thi mã tuỳ ý (RCE) nếu ai đó truy cập được vào lúc đó.
    app.run(host='0.0.0.0', port=5000, debug=False)
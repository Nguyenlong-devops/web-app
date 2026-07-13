import os
import json
import base64
import csv
import io
import time
import secrets
import psycopg2
import paramiko
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session
from ldap3 import Server, Connection, ALL

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
_CSRF_EXEMPT_PATHS = {'/login', '/connect-domain'}

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
    """Lưu config domain mới, deactivate config cũ."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE domain_config SET is_active = FALSE WHERE is_active = TRUE")
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

def get_upn_suffixes(cfg):
    """Lấy danh sách UPN suffix khả dụng trong AD forest — vd domain mặc định @pv.local cộng
    thêm các suffix phụ như @aureole.local được cấu hình qua 'Active Directory Domains and
    Trusts'. Đây chính là danh sách hiện trong dropdown 'User logon name' ở tab Account của
    ADUC, dùng để chọn domain đăng nhập khi tạo/sửa user."""
    ps_cmd = (
        "Import-Module ActiveDirectory; "
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

def deactivate_domain_config():
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
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

# ─────────────────────────────────────────────
#  SSH / PowerShell — dùng config domain hiện tại
# ─────────────────────────────────────────────
def run_powershell_ssh(command_block, cfg=None, return_stderr=False):
    if cfg is None:
        cfg = get_active_domain_config()
    if not cfg:
        return ("", "Chưa kết nối domain", 1) if return_stderr else ""

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=cfg['ssh_host'], username=cfg['ssh_user'], password=cfg['ssh_pass'], timeout=10)
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
        out      = stdout.read().decode('utf-8', errors='ignore')
        err      = stderr.read().decode('utf-8', errors='ignore')
        exitcode = stdout.channel.recv_exit_status()  # 0 = success
        err      = clean_ps_error(err)  # dọn CLIXML nếu vẫn còn sót (vd warning nghiêm trọng)

        # Nếu lệnh có thay đổi user/group AD (tạo/xóa/sửa/enable/disable/thêm-xóa thành viên),
        # xoá cache danh sách AD để lần load Dashboard kế tiếp lấy dữ liệu mới nhất ngay,
        # thay vì phải chờ hết TTL cache.
        _mutating_keywords = ('New-AD', 'Remove-AD', 'Set-AD', 'Add-ADGroupMember',
                              'Remove-ADGroupMember', 'Enable-ADAccount', 'Disable-ADAccount')
        if exitcode == 0 and any(k in command_block for k in _mutating_keywords):
            _AD_CACHE['ts'] = 0

        if return_stderr:
            return out, err, exitcode
        return out
    except Exception as e:
        print(f"SSH Error: {e}")
        if return_stderr:
            return "", str(e), 1
        return ""
    finally:
        ssh.close()

# ─────────────────────────────────────────────
#  Cache Danh Sách User/Group AD
#  - Mỗi lần load Dashboard trước đây mở 2 kết nối SSH riêng (Get-ADUser + Get-ADGroup),
#    mỗi kết nối tốn 1-3s+ để handshake/PowerShell, cộng dồn khiến trang rất chậm khi
#    người dùng chuyển qua lại (vd: Đổi Mật Khẩu -> quay lại Dashboard).
#  - Gộp còn 1 kết nối SSH duy nhất lấy cả 2 loại dữ liệu, và cache tạm trong ít giây để
#    các lượt refresh liên tiếp không phải chờ AD trả lời lại từ đầu.
# ─────────────────────────────────────────────
_AD_CACHE = {'users': None, 'groups': None, 'ts': 0, 'domain_key': None}
_AD_CACHE_TTL = 120  # giây — tăng từ 20s lên 120s

def get_ad_users_and_groups(cfg, force_refresh=False):
    domain_key = cfg.get('ssh_host') if cfg else None
    now = time.time()
    if (not force_refresh and _AD_CACHE['users'] is not None
            and _AD_CACHE['domain_key'] == domain_key
            and now - _AD_CACHE['ts'] < _AD_CACHE_TTL):
        return _AD_CACHE['users'], _AD_CACHE['groups']

    ad_users, ad_groups = [], []
    ps_cmd = (
        "$u = Get-ADUser -Filter * -Properties MemberOf | "
        "Select-Object SamAccountName, Name, Enabled, DistinguishedName, "
        "@{Name='Groups';Expression={($_.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=', ''}) -join ','}}; "
        "$g = Get-ADGroup -Filter * -Properties DistinguishedName | "
        "Where-Object { $_.DistinguishedName -notmatch ',CN=Builtin,' -and "
        "$_.DistinguishedName -notmatch ',CN=Users,DC=' } | "
        "Select-Object SamAccountName, Name, DistinguishedName | Sort-Object Name; "
        "@{ users = @($u); groups = @($g) } | ConvertTo-Json -Compress -Depth 6"
    )
    raw = run_powershell_ssh(ps_cmd, cfg)
    if raw.strip():
        try:
            parsed = json.loads(raw)
            ad_users = parsed.get('users') or []
            ad_groups = parsed.get('groups') or []
            if isinstance(ad_users, dict): ad_users = [ad_users]
            if isinstance(ad_groups, dict): ad_groups = [ad_groups]
        except Exception as e:
            print(f"JSON AD Error: {e}")

    _AD_CACHE.update({'users': ad_users, 'groups': ad_groups, 'ts': now, 'domain_key': domain_key})
    return ad_users, ad_groups

# ─────────────────────────────────────────────
#  Bộ lọc OU hiển thị (riêng cho từng khu vực: users / computers)
# ─────────────────────────────────────────────
_OU_FILTER_SECTIONS = ('users', 'computers')

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
    """Chỉ cho phép truy cập nếu đã kết nối tới một domain."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        cfg = get_active_domain_config()
        if not cfg:
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
    (domain suffix, base DN, admin group DN) được tự động phát hiện qua LDAP RootDSE."""
    error   = None
    cfg     = get_active_domain_config()

    # Trước đây route này KHÔNG yêu cầu đăng nhập — bất kỳ ai (kể cả chưa xác thực) cũng có
    # thể POST lên đây để ghi đè domain đang active thành 1 LDAP server giả do họ dựng lên.
    # Hậu quả: mọi nhân viên đăng nhập vào tool sau đó sẽ vô tình gửi username/password AD
    # thật của mình sang server giả đó (vì /login luôn bind vào domain đang active).
    # Chỉ cho phép bỏ qua đăng nhập khi CHƯA từng kết nối domain nào (lần setup đầu tiên) —
    # một khi đã có domain, bắt buộc phải là admin đã đăng nhập mới được đổi sang domain khác.
    if cfg and not (session.get('user') and session.get('is_admin')):
        return redirect(url_for('login'))

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

    return render_template('connect_domain.html', error=error, cfg=cfg)


@app.route('/disconnect-domain', methods=['POST'])
@admin_required
def disconnect_domain():
    """Thoát khỏi domain hiện tại — xoá cấu hình active và session.
    Yêu cầu admin đã đăng nhập — trước đây route này không có xác thực, ai cũng có
    thể gọi để ngắt domain của cả công ty (DoS) chỉ bằng 1 POST request trần."""
    cfg = get_active_domain_config()
    actor = session.get('user', 'system')
    if deactivate_domain_config():
        write_log(actor, 'DISCONNECT_DOMAIN', target=cfg['ldap_host'] if cfg else None)
    session.clear()
    return jsonify({"status": "success", "redirect": url_for('connect_domain')})

# ─────────────────────────────────────────────
#  Login / Logout
# ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@domain_required
def login():
    cfg = get_active_domain_config()
    error = None
    if request.method == 'POST':
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
    return render_template('login.html', error=error, domain_host=cfg['ldap_host'], domain_suffix=cfg['domain_suffix'])


@app.route('/logout')
def logout():
    if 'user' in session:
        write_log(session['user'], 'LOGOUT')
    session.clear()
    return redirect(url_for('login'))

# ─────────────────────────────────────────────
#  Đổi mật khẩu
# ─────────────────────────────────────────────
@app.route('/change-password', methods=['GET', 'POST'])
@domain_required
@login_required
def change_password():
    cfg = get_active_domain_config()
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
                        f"Import-Module ActiveDirectory; "
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
    cfg = get_active_domain_config()
    is_admin = session.get('is_admin', False)
    my_user  = session.get('user')

    ad_users, ad_groups = ([], [])
    if is_admin:
        ad_users, ad_groups = get_ad_users_and_groups(cfg)
        # Áp dụng bộ lọc OU (nếu admin đã cấu hình) — không chọn OU nào = hiển thị tất cả
        users_ou_filter = get_ou_filter('users')
        if users_ou_filter:
            ad_users = filter_by_ou(ad_users, users_ou_filter, lambda u: u.get('DistinguishedName', ''))

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
    cfg = get_domain_config_by_id(domain_id) if domain_id else get_active_domain_config()
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
        f"Import-Module ActiveDirectory; "
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
    cfg        = get_active_domain_config()
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
        "Import-Module ActiveDirectory",
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
    cfg          = get_active_domain_config()
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
            f"Import-Module ActiveDirectory; "
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
            f"Import-Module ActiveDirectory; Set-ADAccountPassword -Identity '{current_identity}' "
            f"-NewPassword (ConvertTo-SecureString '{ps_quote(password)}' -AsPlainText -Force) -Reset",
            cfg, return_stderr=True)
        details.append(f"password_reset exit={ec}")
        if ec != 0: errors.append(f"Đổi mật khẩu thất bại: {err.strip() or 'lỗi không rõ'} "
                                   f"(thường do mật khẩu không đủ độ phức tạp theo chính sách domain — "
                                   f"cần chữ hoa, chữ thường, số, ký tự đặc biệt, tối thiểu ~8 ký tự)")

    # 3. Enable/Disable
    if status == "true":
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{current_identity}'",
            cfg, return_stderr=True)
        details.append(f"enabled=true exit={ec}")
        if ec != 0: errors.append(f"Enable account thất bại: {err.strip() or 'lỗi không rõ'}")
    else:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; Disable-ADAccount -Identity '{current_identity}'",
            cfg, return_stderr=True)
        details.append(f"enabled=false exit={ec}")
        if ec != 0: errors.append(f"Disable account thất bại: {err.strip() or 'lỗi không rõ'}")

    # 4. Di chuyển OU
    if new_ou:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; "
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
            f"Import-Module ActiveDirectory; "
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
    cfg        = get_active_domain_config()
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
    cfg        = get_active_domain_config()
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
    """Trả về trạng thái cache AD — dùng để biết khi nào data sẵn sàng."""
    age = time.time() - _AD_CACHE['ts'] if _AD_CACHE['ts'] else None
    ready = (_AD_CACHE['users'] is not None and age is not None and age < _AD_CACHE_TTL)
    return jsonify({
        "ready": ready,
        "user_count": len(_AD_CACHE['users']) if _AD_CACHE['users'] else 0,
        "group_count": len(_AD_CACHE['groups']) if _AD_CACHE['groups'] else 0,
        "cache_age_sec": round(age, 1) if age else None,
    })

@app.route('/api/refresh-cache', methods=['POST'])
@domain_required
@login_required
def api_refresh_cache():
    """Force refresh AD cache trong background."""
    cfg = get_active_domain_config()
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
    cfg = get_active_domain_config()
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
    cfg    = get_active_domain_config()
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
    cfg = get_domain_config_by_id(domain_id) if domain_id else get_active_domain_config()
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

@app.route('/api/groups')
@domain_required
@admin_required
def api_get_groups():
    domain_id = request.args.get('domain_id', '').strip()
    cfg = get_domain_config_by_id(domain_id) if domain_id else get_active_domain_config()
    ps_cmd = (
        "Get-ADGroup -Filter * -Properties DistinguishedName | "
        "Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' -and "
        "$_.DistinguishedName -notmatch ',CN=Users,' } | "
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
    cfg = get_domain_config_by_id(domain_id) if domain_id else get_active_domain_config()
    # Ngoài các OU thật, bổ sung container mặc định "Computers" (CN=Computers,...) —
    # đây là nơi các máy mới join domain tự động rơi vào (không phải OU nên
    # Get-ADOrganizationalUnit không trả về), lấy qua (Get-ADDomain).ComputersContainer
    # để đúng cả trường hợp container này đã bị redirect bằng redircmp.exe.
    ps_cmd = (
        "Import-Module ActiveDirectory; "
        "$ou = @(Get-ADOrganizationalUnit -Filter * -Properties Name,DistinguishedName | "
        "Select-Object Name,DistinguishedName,@{Name='IsContainer';Expression={$false}}); "
        "$cc = (Get-ADDomain).ComputersContainer; "
        "$container = [PSCustomObject]@{ Name='Computers'; DistinguishedName=$cc; IsContainer=$true }; "
        "$all = @($container) + $ou; "
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
    cfg = get_active_domain_config()
    data = request.get_json() or {}
    dn      = (data.get('dn') or '').strip()
    new_ou  = (data.get('new_ou') or '').strip()
    name    = (data.get('name') or '').strip()

    if not dn or not new_ou:
        return jsonify({"status": "error", "message": "Thiếu Distinguished Name hoặc OU đích"})

    ps_cmd = (
        f"Import-Module ActiveDirectory; "
        f"Move-ADObject -Identity '{ps_quote(dn)}' -TargetPath '{ps_quote(new_ou)}'"
    )
    out, err, ec = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    if ec != 0:
        return jsonify({"status": "error", "message": err.strip() or "Move thất bại"})

    write_log(session['user'], 'MOVE_COMPUTER', target=name or dn,
              detail=f"Chuyển '{name or dn}' sang OU: {new_ou}")
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

@app.route('/api/domain-computers')
@domain_required
@admin_required
def api_domain_computers():
    cfg = get_active_domain_config()
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

    cfg = get_active_domain_config()
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
    conn = None; cur = None; count = 0
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

        # Lấy trước các mã tài sản đã tồn tại trong DB để phát hiện trùng (không tính mã rỗng)
        cur.execute("SELECT TRIM(asset_code) FROM computers WHERE asset_code IS NOT NULL AND TRIM(asset_code) <> ''")
        existing_codes = {r[0] for r in cur.fetchall()}
        seen_in_file = set()
        skipped = []  # [(asset_code, computer_name, lý do)]

        for row in reader:
            asset_code = (row.get('Mã Tài Sản') or row.get('Mã') or '').strip()
            computer_name = row.get('Tên') or row.get('Tên Máy') or ''

            if asset_code:
                if asset_code in existing_codes:
                    skipped.append((asset_code, computer_name, 'đã tồn tại trong hệ thống'))
                    continue
                if asset_code in seen_in_file:
                    skipped.append((asset_code, computer_name, 'trùng lặp ngay trong file import'))
                    continue

            st = 'in_use' if 'dụng' in row.get('Trạng Thái', row.get('Tình Trạng','') or '') else 'storage'
            cur.execute("""
                INSERT INTO computers (asset_code,device_type,computer_name,location,brand,model,cpu,ram,ssd,hdd,bitlocker,status,notes,updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()) RETURNING id
            """, (asset_code, row.get('Thiết Bị') or row.get('Loại') or '', computer_name,
                  row.get('Vị Trí') or '', row.get('Hãng') or '', row.get('Model') or '',
                  row.get('CPU') or '', row.get('RAM') or '', row.get('SSD') or '', row.get('HDD') or '',
                  row.get('Bitlocker') or '', st, row.get('Ghi Chú') or ''))
            new_id = cur.fetchone()[0]
            if asset_code: seen_in_file.add(asset_code)

            # Cột User trong CSV có thể chứa nhiều user cách nhau dấu phẩy
            users_str = (row.get('User','') or '').strip()
            if users_str:
                for u in [x.strip() for x in users_str.split(',') if x.strip()]:
                    cur.execute(
                        "INSERT INTO user_computers (sam_account_name, computer_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (u, new_id)
                    )
            count += 1
        conn.commit()
        skip_detail = f", bỏ qua {len(skipped)} dòng trùng mã tài sản" if skipped else ""
        write_log(session['user'], 'IMPORT_COMPUTERS', detail=f"imported {count} rows{skip_detail}")
        return jsonify({
            "status": "success",
            "count": count,
            "skipped_count": len(skipped),
            "skipped": [{"asset_code": a, "computer_name": n, "reason": r} for a, n, r in skipped]
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
    cfg      = get_active_domain_config()
    data     = request.get_json()
    username = data.get('username')
    group    = data.get('group')
    ps_cmd = f"Import-Module ActiveDirectory; Remove-ADGroupMember -Identity '{ps_quote(group)}' -Members '{ps_quote(username)}' -Confirm:0"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    write_log(session['user'], 'REMOVE_FROM_GROUP', target=username, detail=f"group={group} exit={exitcode}")
    return jsonify({"status": "success"})

# ─────────────────────────────────────────────
#  API — test SSH (debug only)
# ─────────────────────────────────────────────
@app.route('/api/test-ssh', methods=['POST'])
@domain_required
@admin_required
def api_test_ssh():
    cfg  = get_active_domain_config()
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
    cfg      = get_active_domain_config()
    data     = request.get_json()
    username = data.get('username')
    group    = data.get('group')

    if not group or not group.strip():
        return jsonify({"status": "error", "message": "Vui lòng chọn group."})

    group = group.strip()
    ps_cmd = f"Import-Module ActiveDirectory; Add-ADGroupMember -Identity '{ps_quote(group)}' -Members '{ps_quote(username)}' -Confirm:0"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)
    write_log(session['user'], 'ADD_TO_GROUP', target=username, detail=f"group={group} exit={exitcode}")
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
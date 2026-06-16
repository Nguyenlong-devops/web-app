import os
import json
import base64
import csv
import io
import psycopg2
import paramiko
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session
from ldap3 import Server, Connection, ALL

app = Flask(__name__)
app.secret_key = "pv_local_secret_key_automation"

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
        password=os.environ.get('DB_PASS', 'AureoleIT@2026')
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
        encoded_cmd = base64.b64encode(command_block.encode('utf-16-le')).decode('utf-8')
        # Dùng $LASTEXITCODE và thêm exit code vào cuối stdout để detect lỗi chính xác
        # stderr của PowerShell thường có noise (progress, warning) dù thành công
        full_command = (
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"
        )
        stdin, stdout, stderr = ssh.exec_command(full_command)
        out      = stdout.read().decode('utf-8', errors='ignore')
        err      = stderr.read().decode('utf-8', errors='ignore')
        exitcode = stdout.channel.recv_exit_status()  # 0 = success
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
#  Auth decorators
# ─────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            return "Không có quyền truy cập (Yêu cầu Domain Admins).", 403
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
            error = f"Lỗi kết nối: {str(e)}"

    return render_template('connect_domain.html', error=error, cfg=cfg)


@app.route('/disconnect-domain', methods=['POST'])
def disconnect_domain():
    """Thoát khỏi domain hiện tại — xoá cấu hình active và session."""
    cfg = get_active_domain_config()
    actor = session.get('user', 'system')
    if deactivate_domain_config():
        write_log(actor, 'DISCONNECT_DOMAIN', target=cfg['ldap_host'] if cfg else None)
    session.clear()
    return redirect(url_for('connect_domain'))

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
            server = Server(cfg['ldap_host'], get_info=ALL, connect_timeout=5)
            conn   = Connection(server, user=user_dn, password=password, authentication='SIMPLE')
            if conn.bind():
                conn.search(
                    search_base=cfg['base_dn'],
                    search_filter=f'(sAMAccountName={username})',
                    attributes=['memberOf', 'name']
                )
                is_admin     = False
                display_name = username
                if conn.entries:
                    entry        = conn.entries[0]
                    display_name = str(entry.name) if 'name' in entry else username
                    groups       = entry.memberOf.values if 'memberOf' in entry else []
                    admin_keywords = [
                        cfg['admin_group_dn'].lower(),
                        "cn=domain admins",
                        "cn=administrators,cn=builtin",  # Built-in Administrators group
                    ]
                    for g in groups:
                        g_lower = g.lower()
                        if any(kw in g_lower for kw in admin_keywords):
                            is_admin = True
                            break
                session['user']         = username
                session['display_name'] = display_name
                session['is_admin']     = is_admin
                conn.unbind()
                write_log(username, 'LOGIN', detail=f"is_admin={is_admin}, domain={cfg['ldap_host']}")
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
                        f"$sec = ConvertTo-SecureString '{new_password}' -AsPlainText -Force; "
                        f"Set-ADAccountPassword -Identity '{username}' -NewPassword $sec -Reset $true"
                    )
                    run_powershell_ssh(ps_cmd, cfg)
                    write_log(username, 'CHANGE_PASSWORD', target=username, detail='Password changed via AD')
                    message = "Đổi mật khẩu Windows AD thành công!"
                    status  = "success"
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
    ad_users  = []
    ad_groups = []

    ps_user_cmd = (
        "Get-ADUser -Filter * -Properties MemberOf | "
        "Select-Object SamAccountName, Name, Enabled, DistinguishedName, "
        "@{Name='Groups';Expression={($_.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=', ''}) -join ','}} | "
        "ConvertTo-Json -Compress"
    )
    raw_users = run_powershell_ssh(ps_user_cmd, cfg)
    if raw_users.strip():
        try:
            parsed   = json.loads(raw_users)
            ad_users = [parsed] if isinstance(parsed, dict) else parsed
        except Exception as e:
            print(f"JSON User Error: {e}")

    ps_group_cmd = "Get-ADGroup -Filter * | Select-Object SamAccountName, Name, DistinguishedName | ConvertTo-Json -Compress"
    raw_groups   = run_powershell_ssh(ps_group_cmd, cfg)
    if raw_groups.strip():
        try:
            parsed_groups = json.loads(raw_groups)
            ad_groups     = [parsed_groups] if isinstance(parsed_groups, dict) else parsed_groups
        except Exception as e:
            print(f"JSON Group Error: {e}")

    software_list = []
    assigned_list = []
    audit_rows    = []
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
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
        domain_info=cfg
    )

# ─────────────────────────────────────────────
#  Tạo user AD
# ─────────────────────────────────────────────
@app.route('/create-user', methods=['POST'])
@domain_required
@admin_required
def create_user():
    cfg = get_active_domain_config()
    sam_account_name = request.form.get('sam_account_name')
    full_name        = request.form.get('full_name')
    password         = request.form.get('password')
    ou_dn            = request.form.get('ou_dn')
    group_ids        = request.form.getlist('group_ids[]')

    if not password or not password.strip():
        password = "AureoleIT@2026!@#"

    ps_cmd = (
        f"Import-Module ActiveDirectory; "
        f"New-ADUser -SamAccountName '{sam_account_name}' -Name '{full_name}' "
        f"-AccountPassword (ConvertTo-SecureString '{password}' -AsPlainText -Force) "
        f"-Path '{ou_dn}' -Enabled $true"
    )
    for group_id in group_ids:
        if group_id and group_id.strip():
            ps_cmd += f" ; Add-ADGroupMember -Identity '{group_id}' -Members '{sam_account_name}'"

    run_powershell_ssh(ps_cmd, cfg)
    write_log(
        session['user'], 'CREATE_USER',
        target=sam_account_name,
        detail=f"FullName={full_name}, OU={ou_dn}, Groups={','.join(group_ids)}"
    )
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
#  Edit user AD
# ─────────────────────────────────────────────
@app.route('/edit-user-ad', methods=['POST'])
@domain_required
@admin_required
def edit_user_ad():
    cfg = get_active_domain_config()
    username   = request.form.get('edit_username')
    password   = request.form.get('edit_password')
    status     = request.form.get('edit_status')
    add_groups = [g.strip() for g in request.form.getlist('edit_add_groups') if g.strip()]

    details = []

    if password and password.strip():
        out, err, ec = run_powershell_ssh(
            "Import-Module ActiveDirectory; "
            f"try {{ Set-ADAccountPassword -Identity '{username}' "
            f"-NewPassword (ConvertTo-SecureString '{password}' -AsPlainText -Force) -Reset $true; exit 0 }} "
            f"catch {{ Write-Host $_.Exception.Message; exit 1 }}",
            cfg, return_stderr=True
        )
        details.append(f"password_reset ({'OK' if ec==0 else 'ERROR: '+(out.strip() or err.strip())[:100]})")

    if status == "true":
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; "
            f"try {{ Enable-ADAccount -Identity '{username}'; exit 0 }} "
            f"catch {{ Write-Host $_.Exception.Message; exit 1 }}",
            cfg, return_stderr=True
        )
        details.append(f"enabled=true ({'OK' if ec==0 else 'ERROR: '+(out.strip() or err.strip())[:100]})")
    else:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; "
            f"try {{ Disable-ADAccount -Identity '{username}'; exit 0 }} "
            f"catch {{ Write-Host $_.Exception.Message; exit 1 }}",
            cfg, return_stderr=True
        )
        details.append(f"enabled=false ({'OK' if ec==0 else 'ERROR: '+(out.strip() or err.strip())[:100]})")

    for g in add_groups:
        out, err, ec = run_powershell_ssh(
            f"Import-Module ActiveDirectory; "
            f"Add-ADGroupMember -Identity '{g}' -Members '{username}'; "
            f"catch {{ Write-Host $_.Exception.Message; exit 1 }}",
            cfg, return_stderr=True
        )
        details.append(f"add_group={g} ({'OK' if ec==0 else 'ERROR: '+(out.strip() or err.strip())[:100]})")

    write_log(session['user'], 'EDIT_USER', target=username, detail='; '.join(details))
    return redirect(url_for('index'))

# ─────────────────────────────────────────────
#  License inventory
# ─────────────────────────────────────────────
@app.route('/save-software-inventory', methods=['POST'])
@domain_required
@admin_required
def save_software_inventory():
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
    output = make_response(si.getvalue())
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

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=audit_log.csv"
    output.headers["Content-type"] = "text/csv; charset=utf-8"
    return output

# ─────────────────────────────────────────────
#  API — user licenses
# ─────────────────────────────────────────────
@app.route('/api/user-licenses/<username>')
@domain_required
@admin_required
def api_user_licenses(username):
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT software_key, quantity FROM user_software WHERE sam_account_name=%s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"licenses": [{"key": r[0], "quantity": r[1]} for r in rows]})

# ─────────────────────────────────────────────
#  API — remove user from group
# ─────────────────────────────────────────────
@app.route('/api/remove-user-group', methods=['POST'])
@domain_required
@admin_required
def api_remove_user_group():
    cfg      = get_active_domain_config()
    data     = request.get_json()
    username = data.get('username')
    group    = data.get('group')
    ps_cmd = f"Import-Module ActiveDirectory; Remove-ADGroupMember -Identity '{group}' -Members '{username}'"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)

    if exitcode != 0:
        import re
        errors = re.findall(r'<S S="Error">(.*?)</S>', err, re.DOTALL)
        error_msg = ' '.join(errors).replace('_x000D__x000A_', ' ').strip()[:200] if errors else f"exit={exitcode}"
        write_log(session['user'], 'REMOVE_FROM_GROUP', target=username,
                  detail=f"group={group} (ERROR: {error_msg})")
        return jsonify({"status": "error", "message": f"Lỗi AD: {error_msg}"})

    write_log(session['user'], 'REMOVE_FROM_GROUP', target=username, detail=f"group={group} (OK)")
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
    ps_cmd = f"Import-Module ActiveDirectory; Add-ADGroupMember -Identity '{group}' -Members '{username}'"
    out, err, exitcode = run_powershell_ssh(ps_cmd, cfg, return_stderr=True)

    # Dùng exitcode làm chuẩn — stderr luôn chứa CLIXML progress noise dù thành công
    if exitcode != 0:
        import re
        errors = re.findall(r'<S S="Error">(.*?)</S>', err, re.DOTALL)
        error_msg = ' '.join(errors).replace('_x000D__x000A_', ' ').strip()[:200] if errors else f"exit={exitcode}"
        write_log(session['user'], 'ADD_TO_GROUP', target=username,
                  detail=f"group={group} (ERROR: {error_msg})")
        return jsonify({"status": "error", "message": f"Lỗi AD: {error_msg}"})

    write_log(session['user'], 'ADD_TO_GROUP', target=username, detail=f"group={group} (OK)")
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

# Chạy init_db() ở module level — đảm bảo luôn được gọi dù
# khởi động bằng Gunicorn, Flask dev server, hay bất kỳ WSGI nào.
try:
    init_db()
except Exception as _e:
    print(f"[startup] init_db warning: {_e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

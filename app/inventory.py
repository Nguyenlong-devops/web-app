"""Asset stocktakes: frozen scope, optimistic locking and transactional history."""
import hashlib
import io
import json
from datetime import date, datetime
from functools import wraps

from flask import Blueprint, abort, jsonify, render_template, request, session, send_file
from psycopg2.extras import RealDictCursor, Json
from psycopg2 import IntegrityError
from date_formats import display_date, display_time, display_changes

FIELDS = {
    'asset_code': 'Mã tài sản', 'computer_name': 'Tên máy',
    'device_type': 'Loại thiết bị', 'location': 'Vị trí', 'brand': 'Hãng',
    'model': 'Model', 'cpu': 'CPU', 'ram': 'RAM', 'ssd': 'SSD', 'hdd': 'HDD',
    'os_windows': 'Hệ điều hành', 'project': 'Dự án', 'status': 'Trạng thái sử dụng',
    'purchase_date': 'Ngày mua', 'warranty_expiry_date': 'Ngày hết hạn bảo hành',
    'notes': 'Ghi chú',
}
OUTCOMES = {'normal': 'Bình thường', 'damaged': 'Hỏng',
            'missing': 'Không tìm thấy', 'verify': 'Chờ xác minh'}
SCHEMA = [
    'ALTER TABLE computers ADD COLUMN IF NOT EXISTS purchase_date DATE',
    'ALTER TABLE computers ADD COLUMN IF NOT EXISTS warranty_expiry_date DATE',
    """CREATE TABLE IF NOT EXISTS inventory_rounds (
        id SERIAL PRIMARY KEY, name VARCHAR(200) NOT NULL, notes TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL DEFAULT '', status VARCHAR(16) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','closed')), created_by VARCHAR(128) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), closed_at TIMESTAMPTZ,
        version INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS inventory_items (
        id SERIAL PRIMARY KEY, round_id INTEGER NOT NULL REFERENCES inventory_rounds(id),
        computer_id INTEGER REFERENCES computers(id) ON DELETE SET NULL,
        baseline JSONB NOT NULL, observed JSONB NOT NULL,
        completed BOOLEAN NOT NULL DEFAULT FALSE,
        outcome VARCHAR(16) NOT NULL DEFAULT 'normal'
        CHECK (outcome IN ('normal','damaged','missing','verify')),
        note TEXT NOT NULL DEFAULT '', completed_by VARCHAR(128), completed_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), version INTEGER NOT NULL DEFAULT 0,
        UNIQUE(round_id, computer_id))""",
    """CREATE TABLE IF NOT EXISTS inventory_events (
        id BIGSERIAL PRIMARY KEY, round_id INTEGER NOT NULL REFERENCES inventory_rounds(id),
        item_id INTEGER REFERENCES inventory_items(id), actor VARCHAR(128) NOT NULL,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(), action VARCHAR(32) NOT NULL,
        changes JSONB NOT NULL DEFAULT '{}', note TEXT NOT NULL DEFAULT '')""",
    'CREATE INDEX IF NOT EXISTS inventory_events_round_idx ON inventory_events(round_id, id)',
]


def parse_asset_date(value):
    """Accept ISO dates and Vietnamese CSV dates; empty means unknown."""
    if value is None or value == '':
        return None
    if not isinstance(value, str):
        raise ValueError('Ngày phải có dạng YYYY-MM-DD hoặc DD/MM/YYYY.')
    for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            pass
    raise ValueError('Ngày không hợp lệ: dùng YYYY-MM-DD hoặc DD/MM/YYYY.')


def validate_dates(purchase, expiry):
    if purchase and expiry and expiry < purchase:
        raise ValueError('Ngày hết hạn bảo hành không được trước ngày mua.')


def snapshot(row):
    return {k: (row.get(k).isoformat() if isinstance(row.get(k), (date, datetime))
                else row.get(k) or '') for k in FIELDS}


def revision(row):
    # Include every editable inventory field, but never recovery keys.
    return hashlib.sha256(json.dumps(snapshot(row), sort_keys=True).encode()).hexdigest()


def register_inventory(app, get_db_connection, login_required):
    bp = Blueprint('inventory', __name__)

    def permitted(f):
        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            # Reuse existing AD authorization for the first release.
            if not session.get('is_admin'):
                abort(403)
            return f(*args, **kwargs)
        return wrapped

    @bp.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(message=str(exc)), 400

    @bp.errorhandler(IntegrityError)
    def conflict(exc):
        return jsonify(message='Dữ liệu bị trùng hoặc đã thay đổi. Hãy mở lại thông tin máy.'), 409

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError('Nội dung yêu cầu không hợp lệ.')
        return data

    def event(cur, rid, action, item_id=None, changes=None, note=''):
        cur.execute('''INSERT INTO inventory_events
            (round_id,item_id,actor,action,changes,note) VALUES (%s,%s,%s,%s,%s,%s)''',
                    (rid, item_id, session['user'], action, Json(changes or {}), note))

    @bp.route('/inventory')
    @permitted
    def page():
        return render_template('inventory.html', fields=FIELDS, outcomes=OUTCOMES)

    @bp.route('/api/inventory/rounds', methods=['GET', 'POST'])
    @permitted
    def rounds():
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                if request.method == 'GET':
                    cur.execute('''SELECT r.*, COUNT(i.id)::int AS total,
                        COUNT(i.id) FILTER (WHERE i.completed)::int AS checked
                        FROM inventory_rounds r LEFT JOIN inventory_items i ON i.round_id=r.id
                        GROUP BY r.id ORDER BY r.id DESC''')
                    return jsonify(rounds=cur.fetchall())
                data = body()
                name = str(data.get('name', '')).strip()
                location = str(data.get('location', '')).strip()
                if not name or len(name) > 200:
                    raise ValueError('Tên đợt cần từ 1 đến 200 ký tự.')
                cur.execute('SELECT * FROM computers WHERE (%s=\'\' OR location=%s) ORDER BY id',
                            (location, location))
                computers = cur.fetchall()
                if not computers:
                    raise ValueError('Không có thiết bị trong phạm vi đã chọn. Hãy nhập CSV trước.')
                cur.execute('''INSERT INTO inventory_rounds(name,notes,location,created_by)
                    VALUES (%s,%s,%s,%s) RETURNING id''',
                            (name, str(data.get('notes', '')), location, session['user']))
                rid = cur.fetchone()['id']
                for computer in computers:
                    saved = snapshot(computer)
                    cur.execute('''INSERT INTO inventory_items(round_id,computer_id,baseline,observed)
                        VALUES (%s,%s,%s,%s)''', (rid, computer['id'], Json(saved), Json(saved)))
                event(cur, rid, 'CREATE', changes={'total': len(computers), 'location': location})
                return jsonify(id=rid), 201
        finally:
            conn.close()

    @bp.route('/api/inventory/rounds/<int:rid>/status', methods=['POST'])
    @permitted
    def round_status(rid):
        data = body()
        status = data.get('status')
        reason = str(data.get('reason', '')).strip()
        if status not in ('open', 'closed') or not reason:
            raise ValueError('Chọn trạng thái và nhập lý do đóng/mở lại đợt.')
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM inventory_rounds WHERE id=%s FOR UPDATE', (rid,))
                r = cur.fetchone()
                if not r:
                    abort(404)
                if data.get('version') != r['version']:
                    return jsonify(message='Đợt đã thay đổi. Hãy tải lại.'), 409
                if status == r['status']:
                    raise ValueError('Đợt đã ở trạng thái này.')
                cur.execute('''UPDATE inventory_rounds SET status=%s, version=version+1,
                    closed_at=CASE WHEN %s='closed' THEN NOW() ELSE NULL END WHERE id=%s''',
                            (status, status, rid))
                event(cur, rid, 'CLOSE' if status == 'closed' else 'REOPEN', note=reason)
                return jsonify(status='success')
        finally:
            conn.close()

    @bp.route('/api/inventory/rounds/<int:rid>/items')
    @permitted
    def items(rid):
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM inventory_rounds WHERE id=%s', (rid,))
                r = cur.fetchone()
                if not r:
                    abort(404)
                cur.execute('SELECT * FROM inventory_items WHERE round_id=%s ORDER BY id', (rid,))
                rows = cur.fetchall()
                return jsonify(round=r, items=rows)
        finally:
            conn.close()

    @bp.route('/api/inventory/items/<int:iid>', methods=['GET', 'PUT'])
    @permitted
    def item(iid):
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Always lock round before item so closing cannot race with a save.
                cur.execute('SELECT round_id FROM inventory_items WHERE id=%s', (iid,))
                link = cur.fetchone()
                if not link:
                    abort(404)
                cur.execute('SELECT * FROM inventory_rounds WHERE id=%s FOR UPDATE', (link['round_id'],))
                r = cur.fetchone()
                cur.execute('SELECT * FROM inventory_items WHERE id=%s FOR UPDATE', (iid,))
                old = cur.fetchone()
                cur.execute('SELECT * FROM computers WHERE id=%s FOR UPDATE', (old['computer_id'],))
                computer = cur.fetchone()
                current = snapshot(computer) if computer else None
                if request.method == 'GET':
                    return jsonify(item=old, current=current,
                                   revision=revision(computer) if computer else None, round=r)
                data = body()
                if r['status'] != 'open':
                    return jsonify(message='Đợt đã đóng; không thể sửa.'), 409
                if data.get('version') != old['version']:
                    return jsonify(message='Máy đã được người khác cập nhật. Hãy mở lại thông tin máy.'), 409
                if computer and data.get('revision') != revision(computer):
                    return jsonify(message='Thông tin gốc đã thay đổi. Hãy mở lại máy trước khi lưu.'), 409
                action = data.get('action')
                if action not in ('save', 'complete', 'reopen'):
                    raise ValueError('Thao tác không hợp lệ.')
                note = str(data.get('note', '')).strip()
                outcome = data.get('outcome', old['outcome'])
                if outcome not in OUTCOMES:
                    raise ValueError('Kết quả kiểm kê không hợp lệ.')
                values = data.get('values')
                if not isinstance(values, dict) or set(values) != set(FIELDS):
                    raise ValueError('Thông tin thiết bị chưa đầy đủ.')
                if any(not isinstance(v, str) or len(v) > (10000 if k == 'notes' else 255)
                       for k, v in values.items()):
                    raise ValueError('Giá trị thông tin thiết bị không hợp lệ hoặc quá dài.')
                values = {k: v.strip() for k, v in values.items()}
                if not values['computer_name']:
                    raise ValueError('Tên máy không được trống.')
                if len(values['asset_code']) > 64 or len(values['status']) > 32:
                    raise ValueError('Mã tài sản hoặc trạng thái quá dài.')
                if values['status'] not in ('in_use', 'storage'):
                    raise ValueError('Trạng thái sử dụng không hợp lệ.')
                for k in ('ram', 'ssd', 'hdd', 'device_type'):
                    if len(values[k]) > 64:
                        raise ValueError(FIELDS[k] + ' tối đa 64 ký tự.')
                if len(values['os_windows']) > 128:
                    raise ValueError('Hệ điều hành tối đa 128 ký tự.')
                purchase = parse_asset_date(values['purchase_date'])
                expiry = parse_asset_date(values['warranty_expiry_date'])
                validate_dates(purchase, expiry)
                values['purchase_date'] = purchase.isoformat() if purchase else ''
                values['warranty_expiry_date'] = expiry.isoformat() if expiry else ''
                if not computer and action != 'reopen':
                    raise ValueError('Thiết bị đã xóa khỏi danh mục; chỉ có thể xem lịch sử hoặc mở lại kết quả.')
                if action == 'reopen' and (not old['completed'] or not note):
                    raise ValueError('Mở lại máy đã hoàn thành cần có lý do.')
                if computer and action != 'reopen':
                    if values['asset_code']:
                        cur.execute('SELECT id FROM computers WHERE TRIM(asset_code)=%s AND id<>%s',
                                    (values['asset_code'], computer['id']))
                        if cur.fetchone():
                            raise ValueError('Mã tài sản đã tồn tại.')
                    # Only whitelisted columns can enter this SQL.
                    assignments = ','.join(k + '=%s' for k in FIELDS)
                    params = [purchase if k == 'purchase_date' else expiry if k == 'warranty_expiry_date'
                              else values[k] for k in FIELDS]
                    cur.execute('UPDATE computers SET ' + assignments + ',updated_at=NOW() WHERE id=%s',
                                params + [computer['id']])
                changes = {k: {'before': old['observed'].get(k, ''), 'after': values[k]}
                           for k in FIELDS if old['observed'].get(k, '') != values[k]}
                master_changes = {k: {'before': current[k], 'after': values[k]}
                                  for k in FIELDS if current and current[k] != values[k]}
                completed = old['completed'] if action == 'save' else action == 'complete'
                # A repeated scan/save preserves the original completion identity.
                cur.execute('''UPDATE inventory_items SET observed=%s, outcome=%s, note=%s,
                    completed=%s, completed_by=CASE WHEN %s THEN NULL
                        WHEN NOT completed AND %s THEN %s ELSE completed_by END,
                    completed_at=CASE WHEN %s THEN NULL WHEN NOT completed AND %s THEN NOW()
                        ELSE completed_at END, updated_at=NOW(), version=version+1 WHERE id=%s''',
                            (Json(old['observed'] if action == 'reopen' else values),
                             old['outcome'] if action == 'reopen' else outcome, note,
                             completed, action == 'reopen', completed, session['user'],
                             action == 'reopen', completed, iid))
                event(cur, old['round_id'], action.upper(), iid,
                      {'fields': changes if action != 'reopen' else {},
                       'master_fields': master_changes if action != 'reopen' else {},
                       'completed': {'before': old['completed'], 'after': completed},
                       'outcome': {'before': old['outcome'], 'after': outcome if action != 'reopen' else old['outcome']},
                       'note': {'before': old['note'], 'after': note}}, note)
                return jsonify(status='success')
        finally:
            conn.close()

    @bp.route('/api/inventory/rounds/<int:rid>/history')
    @permitted
    def history(rid):
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('''SELECT e.*, i.baseline->>'computer_name' AS computer_name
                    FROM inventory_events e LEFT JOIN inventory_items i ON i.id=e.item_id
                    WHERE e.round_id=%s ORDER BY e.id DESC''', (rid,))
                return jsonify(events=cur.fetchall())
        finally:
            conn.close()

    @bp.route('/inventory/rounds/<int:rid>/export.xlsx')
    @permitted
    def export(rid):
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM inventory_rounds WHERE id=%s', (rid,))
                r = cur.fetchone()
                if not r:
                    abort(404)
                cur.execute('SELECT * FROM inventory_items WHERE round_id=%s ORDER BY id', (rid,))
                rows = cur.fetchall()
                cur.execute('SELECT * FROM inventory_events WHERE round_id=%s ORDER BY id', (rid,))
                events = cur.fetchall()
            wb = Workbook()
            ws = wb.active
            ws.title = 'Kết quả'
            ws.append(['Đợt', 'Trạng thái kiểm kê', 'Kết quả', 'Người hoàn thành',
                       'Thời gian hoàn thành', 'Ghi chú kiểm kê'] + list(FIELDS.values()))
            for row in rows:
                ws.append([r['name'], 'Hoàn thành' if row['completed'] else 'Chưa kiểm kê',
                           OUTCOMES[row['outcome']], row['completed_by'],
                           display_time(row['completed_at']), row['note']]
                          + [display_date(row['observed'].get(k, '')) if k.endswith('_date') else row['observed'].get(k, '') for k in FIELDS])
            base = wb.create_sheet('Thông tin đầu đợt')
            base.append(['ID kết quả'] + list(FIELDS.values()))
            for row in rows:
                base.append([row['id']] + [display_date(row['baseline'].get(k, '')) if k.endswith('_date') else row['baseline'].get(k, '') for k in FIELDS])
            log = wb.create_sheet('Lịch sử')
            log.append(['Thời gian', 'Người thao tác', 'Thao tác', 'ID kết quả', 'Thay đổi', 'Ghi chú'])
            for e in events:
                log.append([display_time(e['ts']), e['actor'], e['action'], e['item_id'],
                            json.dumps(display_changes(e['changes']), ensure_ascii=False), e['note']])
            for sheet in wb:
                sheet.freeze_panes = 'A2'
                sheet.auto_filter.ref = sheet.dimensions
                for cell in sheet[1]:
                    cell.font = Font(bold=True, color='FFFFFF')
                    cell.fill = PatternFill('solid', fgColor='175CD3')
                for col in sheet.columns:
                    sheet.column_dimensions[col[0].column_letter].width = 24
                    for cell in col:
                        if cell.data_type == 'f':
                            cell.data_type = 's'  # untrusted names must never become Excel formulas
            output = io.BytesIO()
            wb.save(output)
            output.seek(0)
            return send_file(output, as_attachment=True, download_name=f'kiem-ke-{rid}.xlsx')
        finally:
            conn.close()

    app.register_blueprint(bp)

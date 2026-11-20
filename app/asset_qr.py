"""Stable internal asset links and printable SVG QR labels."""
import io
import base64
import os
from urllib.parse import urlsplit
from datetime import datetime, timedelta

from flask import Blueprint, abort, redirect, render_template, request, send_file, session, url_for, jsonify
from psycopg2.extras import RealDictCursor

from inventory import FIELDS
from date_formats import display_date, LOCAL_TZ


def asset_link(cid):
    base = os.environ.get('ASSET_PUBLIC_BASE_URL', '').strip().rstrip('/') or request.host_url.rstrip('/')
    parts = urlsplit(base)
    if parts.scheme not in ('http', 'https') or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment or parts.path:
        abort(400, 'ASSET_PUBLIC_BASE_URL cần có dạng https://portal.noibo hoặc http://IP:port')
    return f'{base}/assets/{cid}'


def register_asset_qr(app, get_db_connection, admin_required):
    bp = Blueprint('asset_qr', __name__)
    app.jinja_env.filters['date_display'] = display_date

    @bp.route('/api/assets/warranty-alerts')
    @admin_required
    def warranty_alerts():
        today = datetime.now(LOCAL_TZ).date()
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('''SELECT
                    COUNT(*) FILTER (WHERE warranty_expiry_date < %s)::int AS expired,
                    COUNT(*) FILTER (WHERE warranty_expiry_date BETWEEN %s AND %s)::int AS due
                    FROM computers''', (today, today, today + timedelta(days=30)))
                summary = dict(cur.fetchone())
            return jsonify(**summary, today=today.isoformat(), warning_days=30)
        finally:
            conn.close()

    def qr_bytes(link):
        import qrcode
        from qrcode.image.svg import SvgPathImage
        output = io.BytesIO()
        qrcode.make(link, image_factory=SvgPathImage, box_size=10, border=4).save(output)
        return output.getvalue()

    @bp.route('/assets/qr/print')
    @admin_required
    def bulk_labels():
        raw = request.args.get('ids', '').split(',')
        if not raw or len(raw) > 500 or any(not x.isascii() or not x.isdigit() or len(x) > 10 for x in raw):
            abort(400, 'Chọn từ 1 đến 500 thiết bị để in QR.')
        ids = list(dict.fromkeys(int(x) for x in raw))
        if any(x < 1 or x > 2147483647 for x in ids):
            abort(400, 'ID thiết bị không hợp lệ.')
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT id,computer_name,asset_code FROM computers WHERE id=ANY(%s)', (ids,))
                found = {row['id']: row for row in cur.fetchall()}
        finally:
            conn.close()
        if len(found) != len(ids):
            abort(400, 'Một số thiết bị đã bị xóa. Hãy tải lại danh sách trước khi in.')
        labels = []
        for cid in ids:
            link = asset_link(cid)
            labels.append({**found[cid], 'qr_src': 'data:image/svg+xml;base64,' + base64.b64encode(qr_bytes(link)).decode('ascii')})
        return render_template('asset_qr_bulk.html', sheets=[labels[i:i+12] for i in range(0,len(labels),12)],
                               count=len(labels), base_link=asset_link(ids[0]))

    def get_computer(cid):
        conn = get_db_connection()
        try:
            with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Whitelist information fields; recovery keys never enter this view.
                columns = ','.join('c.' + k for k in FIELDS)
                cur.execute('SELECT c.id,' + columns + ' FROM computers c WHERE c.id=%s', (cid,))
                computer = cur.fetchone()
                if not computer:
                    abort(404)
                cur.execute('SELECT sam_account_name FROM user_computers WHERE computer_id=%s ORDER BY sam_account_name', (cid,))
                users = [r['sam_account_name'] for r in cur.fetchall()]
                return computer, users
        finally:
            conn.close()

    @bp.route('/assets/<int:cid>')
    def detail(cid):
        if not session.get('user'):
            session['asset_return_to'] = url_for('asset_qr.detail', cid=cid)
            return redirect(url_for('login'))
        computer, users = get_computer(cid)
        if not session.get('is_admin') and session['user'].casefold() not in {u.casefold() for u in users}:
            abort(403, 'Bạn chỉ được xem thiết bị được cấp cho mình. Liên hệ quản trị viên để xem thiết bị khác.')
        open_rounds = []
        if session.get('is_admin'):
            conn = get_db_connection()
            try:
                with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''SELECT r.id, r.name, i.id AS item_id, i.completed
                        FROM inventory_rounds r JOIN inventory_items i ON i.round_id=r.id
                        WHERE i.computer_id=%s AND r.status='open'
                        ORDER BY r.created_at DESC, r.id DESC''', (cid,))
                    open_rounds = cur.fetchall()
            finally:
                conn.close()
        return render_template('asset_detail.html', computer=computer, users=users, fields=FIELDS, open_rounds=open_rounds)

    @bp.route('/assets/<int:cid>/qr')
    @admin_required
    def label(cid):
        computer, _ = get_computer(cid)
        return render_template('asset_qr.html', computer=computer, link=asset_link(cid), embedded=request.args.get('embedded') == '1')

    @bp.route('/assets/<int:cid>/qr.svg')
    @admin_required
    def svg(cid):
        get_computer(cid)
        output = io.BytesIO(qr_bytes(asset_link(cid)))
        return send_file(output, mimetype='image/svg+xml', as_attachment=request.args.get('download') == '1',
                         download_name=f'asset-{cid}-qr.svg', max_age=0)

    app.register_blueprint(bp)

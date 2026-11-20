"""QR rendering and access rules; no production database required."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from functools import wraps

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from flask import Flask, abort, session
from asset_qr import asset_link, register_asset_qr


class Cursor:
    open_rounds = []
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, params):
        self.sql = sql
        self.cid = params[0]
        if 'FROM computers' in sql:
            assert 'bitlocker_c' not in sql

    def fetchone(self):
        if 'COUNT(*) FILTER' in self.sql:
            return {'expired':2,'due':3}
        return {'id': 7, 'computer_name': 'PC-<test>', 'asset_code': 'TS-007',
                'cpu':'Core i5', 'ram':'16 GB', 'bitlocker_c':'SECRET-RECOVERY-KEY'} if self.cid == 7 else None

    def fetchall(self):
        if 'FROM inventory_rounds' in self.sql:
            assert "r.status='open'" in self.sql
            assert 'i.computer_id=%s' in self.sql
            return self.open_rounds
        if 'id=ANY' in self.sql:
            return [{'id':cid, 'computer_name':f'PC-{cid}', 'asset_code':f'TS-{cid:03}'}
                    for cid in self.cid if cid <= 25]
        return [{'sam_account_name':'alice'}]


class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def cursor(self, **kwargs):
        return Cursor()

    def close(self):
        pass


class QRTests(unittest.TestCase):
    def setUp(self):
        Cursor.open_rounds = []
        self.app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app/templates'))
        self.app.secret_key = 'test-only'
        self.app.testing = True
        self.app.add_url_rule('/inventory', endpoint='inventory.page', view_func=lambda: 'Inventory')

        @self.app.route('/login')
        def login():
            return 'Login'

        def admin_required(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                if not session.get('is_admin'):
                    abort(403)
                return f(*args, **kwargs)
            return wrapped

        register_asset_qr(self.app, Connection, admin_required)
        self.client = self.app.test_client()
        self.env = patch.dict(os.environ, {'ASSET_PUBLIC_BASE_URL':''})
        self.env.start()
        self.addCleanup(self.env.stop)

    def as_user(self, name, admin=False):
        with self.client.session_transaction() as sess:
            sess.update(user=name, is_admin=admin)

    def test_anonymous_scan_returns_to_same_device(self):
        response = self.client.get('/assets/7')
        self.assertEqual(response.status_code,302)
        self.assertTrue(response.location.endswith('/login'))
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['asset_return_to'],'/assets/7')

    def test_detail_permissions_escaping_and_no_recovery_key(self):
        self.as_user('bob')
        self.assertEqual(self.client.get('/assets/7').status_code,403)
        self.as_user('ALICE')
        response = self.client.get('/assets/7')
        self.assertEqual(response.status_code,200)
        html = response.get_data(as_text=True)
        self.assertIn('PC-&lt;test&gt;',html)
        self.assertIn('showModal()',html)
        self.assertNotIn('SECRET-RECOVERY-KEY',html)
        self.assertEqual(self.client.get('/assets/7/qr').status_code,403)
        self.as_user('admin',True)
        self.assertEqual(self.client.get('/assets/7').status_code,200)
        self.assertEqual(self.client.get('/assets/999').status_code,404)

    def test_warranty_alert_summary_requires_admin(self):
        self.as_user('alice')
        self.assertEqual(self.client.get('/api/assets/warranty-alerts').status_code,403)
        self.as_user('admin',True)
        result=self.client.get('/api/assets/warranty-alerts')
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json['due'],3)
        self.assertEqual(result.json['expired'],2)
        self.assertEqual(result.json['warning_days'],30)
        self.assertRegex(result.json['today'],r'^\d{4}-\d{2}-\d{2}$')

    def test_bulk_print_permissions_validation_and_pagination(self):
        self.as_user('alice')
        self.assertEqual(self.client.get('/assets/qr/print?ids=7,8').status_code,403)
        self.as_user('admin',True)
        for ids in ('','0','-1','abc','7,,8','2147483648',','.join(['7']*501)):
            self.assertEqual(self.client.get('/assets/qr/print',query_string={'ids':ids}).status_code,400)
        self.assertEqual(self.client.get('/assets/qr/print?ids=7,999').status_code,400)
        response = self.client.get('/assets/qr/print?ids=8,7,8')
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code,200)
        self.assertEqual(html.count('class="qr-label"'),2)
        self.assertLess(html.index('title="PC-8"'),html.index('title="PC-7"'))
        self.assertIn('data:image/svg+xml;base64,',html)
        self.assertIn('window.print()',html)
        response = self.client.get('/assets/qr/print',query_string={'ids':','.join(map(str,range(1,14)))})
        html = response.get_data(as_text=True)
        self.assertEqual(html.count('class="sheet"'),2)
        self.assertEqual(html.count('class="qr-label"'),13)

    def test_scan_shows_inventory_only_for_open_matching_rounds(self):
        self.as_user('admin',True)
        html=self.client.get('/assets/7').get_data(as_text=True)
        self.assertNotIn('id="scanInventoryForm"',html)
        Cursor.open_rounds=[{'id':10,'name':'Đợt tháng 11','item_id':42,'completed':False}]
        html=self.client.get('/assets/7').get_data(as_text=True)
        self.assertIn('id="scanInventoryForm"',html)
        self.assertIn('name="round_id" value="10"',html)
        self.assertIn('name="item_id" value="42"',html)
        self.assertIn('Kiểm kê tài sản',html)
        self.assertNotIn('id="scanRoundSelect"',html)
        Cursor.open_rounds.append({'id':11,'name':'Đợt IT','item_id':43,'completed':True})
        html=self.client.get('/assets/7').get_data(as_text=True)
        self.assertIn('id="scanRoundSelect"',html)
        self.assertIn('value="11" data-item-id="43"',html)
        self.as_user('alice')
        self.assertNotIn('id="scanInventoryForm"',self.client.get('/assets/7').get_data(as_text=True))

    def test_embedded_qr_keeps_download_and_frame_scoped_print(self):
        self.as_user('admin',True)
        result=self.client.get('/assets/7/qr?embedded=1')
        self.assertEqual(result.status_code,200)
        html=result.get_data(as_text=True)
        self.assertIn('class="qr-embedded"',html)
        self.assertIn('data-qr-page',html)
        self.assertIn('download=1',html)
        self.assertIn('window.print()',html)
        self.assertNotIn('← Portal',html)
        self.assertIn('parent.closeAssetQrModal',html)
        plain=self.client.get('/assets/7/qr').get_data(as_text=True)
        self.assertNotIn('class="qr-embedded"',plain)
        self.assertIn('← Portal',plain)
        self.as_user('alice')
        self.assertEqual(self.client.get('/assets/7/qr?embedded=1').status_code,403)

    def test_qr_label_download_and_internal_base_url(self):
        self.as_user('admin',True)
        with patch.dict(os.environ, {'ASSET_PUBLIC_BASE_URL':'http://192.168.99.10:8080/'}):
            response = self.client.get('/assets/7/qr')
            self.assertEqual(response.status_code,200)
            self.assertIn('http://192.168.99.10:8080/assets/7',response.get_data(as_text=True))
            self.assertIn('window.print()',response.get_data(as_text=True))
            svg = self.client.get('/assets/7/qr.svg?download=1')
            self.assertEqual(svg.status_code,200)
            self.assertEqual(svg.mimetype,'image/svg+xml')
            self.assertIn('attachment',svg.headers['Content-Disposition'])
            self.assertIn(b'<svg',svg.data)
            self.assertIn(b'<path',svg.data)
        with self.app.test_request_context(base_url='http://192.168.1.10:80'):
            self.assertEqual(asset_link(7),'http://192.168.1.10/assets/7')
        for invalid in ('javascript:alert(1)', 'https://a/b', 'https://user:pass@a', 'https://a?b=1'):
            with patch.dict(os.environ, {'ASSET_PUBLIC_BASE_URL':invalid}):
                self.assertEqual(self.client.get('/assets/7/qr').status_code,400)


if __name__ == '__main__':
    unittest.main()

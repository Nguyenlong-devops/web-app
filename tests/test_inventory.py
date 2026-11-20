"""Integration tests against an isolated PostgreSQL database.

Set INVENTORY_TEST_DSN to an EMPTY disposable database before running unittest.
These tests create/drop a dedicated schema; they never use the application's DB.
"""
import io
import os
import sys
import unittest
from datetime import date
from functools import wraps
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import psycopg2
from flask import Flask, jsonify, session
from openpyxl import load_workbook
from inventory import SCHEMA, register_inventory, parse_asset_date, validate_dates


class DateTests(unittest.TestCase):
    def test_dates(self):
        self.assertEqual(parse_asset_date('18/11/2026'), date(2026, 11, 18))
        self.assertEqual(parse_asset_date('2024-02-29'), date(2024, 2, 29))
        self.assertIsNone(parse_asset_date(''))
        for value in ('2026-02-29', '18-11-2026', 'bad', 123):
            with self.assertRaises(ValueError):
                parse_asset_date(value)
        with self.assertRaises(ValueError):
            validate_dates(date(2026, 1, 1), date(2025, 1, 1))


@unittest.skipUnless(os.environ.get('INVENTORY_TEST_DSN'), 'Set INVENTORY_TEST_DSN for PostgreSQL tests')
class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = 'inventory_test_' + uuid4().hex
        cls.dsn = os.environ['INVENTORY_TEST_DSN']
        with psycopg2.connect(cls.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute('CREATE SCHEMA ' + cls.schema)
        cls.app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'app/templates'))
        cls.app.secret_key = 'integration-test-only'
        cls.app.testing = True

        def connection():
            conn = psycopg2.connect(cls.dsn)
            with conn.cursor() as cur:
                cur.execute('SET search_path TO ' + cls.schema)
            return conn
        cls.connection = staticmethod(connection)
        with connection() as conn, conn.cursor() as cur:
            cur.execute('''CREATE TABLE computers (
                id SERIAL PRIMARY KEY, asset_code VARCHAR(64) UNIQUE, computer_name VARCHAR(255),
                device_type VARCHAR(64), location VARCHAR(255), brand VARCHAR(128), model VARCHAR(128),
                cpu VARCHAR(255),ram VARCHAR(64),ssd VARCHAR(64),hdd VARCHAR(64),os_windows VARCHAR(128),
                project VARCHAR(255),status VARCHAR(32) DEFAULT 'in_use',notes TEXT,updated_at TIMESTAMPTZ DEFAULT NOW())''')
            for sql in SCHEMA:
                cur.execute(sql)
            # Migrations must be safe on the second restart.
            for sql in SCHEMA:
                cur.execute(sql)

        def login_required(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                return f(*args, **kwargs) if session.get('user') else (jsonify(message='Login required'), 401)
            return wrapped
        register_inventory(cls.app, connection, login_required)

    @classmethod
    def tearDownClass(cls):
        with psycopg2.connect(cls.dsn) as conn, conn.cursor() as cur:
            cur.execute('DROP SCHEMA ' + cls.schema + ' CASCADE')

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess.update(user='tester', is_admin=True, csrf_token='test')
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute('TRUNCATE inventory_events,inventory_items,inventory_rounds,computers RESTART IDENTITY CASCADE')
            cur.execute("INSERT INTO computers(asset_code,computer_name,ram,location) VALUES ('TS-01','PC-01','8GB','IT'),('TS-02','PC-02','16GB','HR')")

    def create_round(self, location=''):
        response = self.client.post('/api/inventory/rounds', json={'name':'Đợt thử', 'location':location})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.json['id']

    def get_item(self, rid):
        iid = self.client.get(f'/api/inventory/rounds/{rid}/items').json['items'][0]['id']
        return self.client.get(f'/api/inventory/items/{iid}').json

    def save(self, detail, action='complete', **changes):
        values = dict(detail['current'])
        values.update(changes)
        return self.client.put(f"/api/inventory/items/{detail['item']['id']}", json={
            'action':action, 'values':values, 'version':detail['item']['version'],
            'revision':detail['revision'], 'outcome':'normal', 'note':'Kiểm tra thực tế'})

    def test_lifecycle_history_export_and_round_isolation(self):
        rid = self.create_round()
        first = self.get_item(rid)
        self.assertEqual(self.save(first, ram='32GB', purchase_date='2025-01-01', warranty_expiry_date='2028-01-01').status_code, 200)
        updated = self.get_item(rid)
        self.assertTrue(updated['item']['completed'])
        self.assertEqual(updated['item']['baseline']['ram'], '8GB')
        self.assertEqual(updated['current']['ram'], '32GB')
        self.assertEqual(self.save(first, ram='64GB').status_code, 409)
        completed_at = updated['item']['completed_at']
        self.assertEqual(self.save(updated, action='save', ram='48GB').status_code, 200)
        updated = self.get_item(rid)
        self.assertEqual(updated['item']['completed_at'], completed_at)
        rounds = self.client.get('/api/inventory/rounds').json['rounds']
        self.assertEqual((rounds[0]['total'], rounds[0]['checked']), (2, 1))
        events = self.client.get(f'/api/inventory/rounds/{rid}/history').json['events']
        self.assertEqual(len(events), 3)
        self.assertEqual(events[1]['changes']['fields']['ram'], {'before':'8GB','after':'32GB'})
        response = self.client.get(f'/inventory/rounds/{rid}/export.xlsx')
        self.assertEqual(response.status_code, 200)
        wb = load_workbook(io.BytesIO(response.data))
        self.assertEqual(wb.sheetnames, ['Kết quả','Thông tin đầu đợt','Lịch sử'])
        self.assertEqual(wb['Lịch sử'].max_row, 4)
        second = self.create_round('IT')
        new_item = self.get_item(second)
        self.assertFalse(new_item['item']['completed'])
        self.assertEqual(new_item['item']['baseline']['ram'], '48GB')
        self.assertEqual(self.get_item(rid)['item']['baseline']['ram'], '8GB')

    def test_close_reopen_and_master_conflict(self):
        rid = self.create_round()
        detail = self.get_item(rid)
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute("UPDATE computers SET cpu='new CPU' WHERE id=1")
        self.assertEqual(self.save(detail).status_code, 409)
        response = self.client.post(f'/api/inventory/rounds/{rid}/status', json={'status':'closed','reason':'Kết thúc','version':0})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.save(self.get_item(rid)).status_code, 409)
        self.assertEqual(self.client.post(f'/api/inventory/rounds/{rid}/status', json={'status':'open','reason':'Kiểm tra lại','version':1}).status_code, 200)
        self.assertEqual(self.save(self.get_item(rid)).status_code, 200)
        self.assertEqual(self.save(self.get_item(rid), action='reopen').status_code, 200)
        reopened = self.get_item(rid)['item']
        self.assertFalse(reopened['completed'])
        self.assertIsNone(reopened['completed_at'])

    def test_validation_rollback_and_duplicate_asset(self):
        rid = self.create_round()
        detail = self.get_item(rid)
        self.assertEqual(self.save(detail, purchase_date='2026-01-01', warranty_expiry_date='2025-01-01').status_code, 400)
        self.assertEqual(self.save(detail, asset_code='TS-02').status_code, 400)
        self.assertEqual(self.get_item(rid)['current']['ram'], '8GB')
        self.assertEqual(len(self.client.get(f'/api/inventory/rounds/{rid}/history').json['events']), 1)
        self.assertEqual(self.client.post('/api/inventory/rounds', json={'name':'empty','location':'UNKNOWN'}).status_code, 400)
        # History survives removal from the live inventory.
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute('DELETE FROM computers WHERE id=1')
        deleted = self.get_item(rid)
        self.assertIsNone(deleted['current'])
        self.assertEqual(deleted['item']['baseline']['computer_name'], 'PC-01')

    def test_history_failure_rolls_back_device_update(self):
        rid = self.create_round()
        detail = self.get_item(rid)
        with self.connection() as conn, conn.cursor() as cur:
            cur.execute("""CREATE FUNCTION reject_inventory_event() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'test history failure'; END; $$ LANGUAGE plpgsql""")
            cur.execute('CREATE TRIGGER reject_event BEFORE INSERT ON inventory_events FOR EACH ROW EXECUTE FUNCTION reject_inventory_event()')
        try:
            with self.assertRaises(psycopg2.Error):
                self.save(detail, ram='64GB')
            unchanged = self.get_item(rid)
            self.assertEqual(unchanged['current']['ram'], '8GB')
            self.assertFalse(unchanged['item']['completed'])
        finally:
            with self.connection() as conn, conn.cursor() as cur:
                cur.execute('DROP TRIGGER reject_event ON inventory_events')
                cur.execute('DROP FUNCTION reject_inventory_event()')

    def test_permissions_and_page(self):
        self.assertEqual(self.client.get('/inventory').status_code, 200)
        with self.client.session_transaction() as sess:
            sess['is_admin'] = False
        self.assertEqual(self.client.get('/inventory').status_code, 403)
        self.assertEqual(self.client.post('/api/inventory/rounds', json={'name':'no'}).status_code, 403)
        with self.client.session_transaction() as sess:
            sess.clear()
        self.assertEqual(self.client.get('/api/inventory/rounds').status_code, 401)


if __name__ == '__main__':
    unittest.main()

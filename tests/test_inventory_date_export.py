import io
import json
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from flask import Flask
from openpyxl import load_workbook
from inventory import register_inventory

class ExportConnection:
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def cursor(self,**kwargs): return self
    def close(self): pass
    def execute(self,sql,args): self.sql=sql
    def fetchone(self): return {'name':'Test'}
    def fetchall(self):
        if 'inventory_items' in self.sql:
            return [dict(id=1,completed=True,outcome='normal',completed_by='admin',completed_at=datetime(2026,11,19,20,30,tzinfo=timezone.utc),note='',observed={'purchase_date':'2025-01-02','warranty_expiry_date':'2028-03-04'},baseline={'purchase_date':'2024-01-02'})]
        return [dict(ts=datetime(2026,11,19,20,30,tzinfo=timezone.utc),actor='admin',action='SAVE',item_id=1,changes={'fields':{'purchase_date':{'before':'2024-01-02','after':'2025-01-02'}}},note='')]

class InventoryDateExportTests(unittest.TestCase):
    def test_all_sheets_use_day_month_year(self):
        app=Flask(__name__);app.secret_key='test'
        register_inventory(app,ExportConnection,lambda f:f)
        client=app.test_client()
        with client.session_transaction() as session: session.update(user='admin',is_admin=True)
        response=client.get('/inventory/rounds/1/export.xlsx')
        self.assertEqual(response.status_code,200)
        wb=load_workbook(io.BytesIO(response.data))
        headers=[c.value for c in wb['Kết quả'][1]]
        self.assertEqual(wb['Kết quả'].cell(2,headers.index('Ngày mua')+1).value,'02/01/2025')
        self.assertEqual(wb['Kết quả'].cell(2,5).value,'20/11/2026 03:30:00')
        headers=[c.value for c in wb['Thông tin đầu đợt'][1]]
        self.assertEqual(wb['Thông tin đầu đợt'].cell(2,headers.index('Ngày mua')+1).value,'02/01/2024')
        self.assertEqual(wb['Lịch sử'].cell(2,1).value,'20/11/2026 03:30:00')
        changes=json.loads(wb['Lịch sử'].cell(2,5).value)
        self.assertEqual(changes['fields']['purchase_date']['after'],'02/01/2025')

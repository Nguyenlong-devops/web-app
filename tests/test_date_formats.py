import sys
import unittest
from pathlib import Path
from datetime import date, datetime, timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from date_formats import display_date, display_time, display_changes


class DateFormatTests(unittest.TestCase):
    def test_date_and_unknown_values(self):
        self.assertEqual(display_date(date(2026,11,19)), '19/11/2026')
        self.assertEqual(display_date('2024-02-29'), '29/02/2024')
        self.assertEqual(display_date('19/11/2026'), '19/11/2026')
        self.assertEqual(display_date(None), '')
        self.assertEqual(display_date('2026-02-30'), '2026-02-30')

    def test_local_timestamp_and_history(self):
        self.assertEqual(display_time(datetime(2026,11,19,20,30,tzinfo=timezone.utc)), '20/11/2026 03:30:00')
        original={'fields':{'purchase_date':{'before':'2025-01-02','after':'2026-03-04'},'notes':{'after':'2025-01-02'}}}
        formatted=display_changes(original)
        self.assertEqual(formatted['fields']['purchase_date']['before'],'02/01/2025')
        self.assertEqual(formatted['fields']['purchase_date']['after'],'04/03/2026')
        self.assertEqual(formatted['fields']['notes']['after'],'2025-01-02')
        self.assertEqual(original['fields']['purchase_date']['before'],'2025-01-02')

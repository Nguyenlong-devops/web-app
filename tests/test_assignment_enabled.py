"""Exercise the actual assignment guard without starting AD or PostgreSQL."""
import ast
import unittest
from pathlib import Path
from types import SimpleNamespace


class ReachedDatabase(Exception):
    pass


class AssignmentEnabledTests(unittest.TestCase):
    def check_request(self, users, username='alice', error=None):
        source=Path(__file__).resolve().parents[1]/'app/app.py'
        module=ast.parse(source.read_text(encoding='utf-8'))
        function=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='api_assign_computer')
        function.decorator_list=[]
        def connection():
            raise ReachedDatabase('Guard accepted the Enabled user')
        env=dict(request=SimpleNamespace(get_json=lambda:{'username':username,'computer_id':1}),
                 jsonify=lambda data:data,current_domain_cfg=lambda:{'id':1},
                 get_ad_users_and_groups=lambda cfg:(users,[],error),get_db_connection=connection)
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),env)
        return env['api_assign_computer']()

    def test_disabled_and_unknown_users_rejected_before_database(self):
        for users in ([{'SamAccountName':'alice','Enabled':False}], [], [{'SamAccountName':'alice'}]):
            response,status=self.check_request(users)
            self.assertEqual(status,400)
            self.assertEqual(response['status'],'error')

    def test_enabled_case_insensitive_user_can_proceed(self):
        with self.assertRaises(ReachedDatabase):
            self.check_request([{'SamAccountName':'Alice','Enabled':True}], ' ALICE ')

    def test_ad_failure_does_not_assign_from_stale_result(self):
        _,status=self.check_request([{'SamAccountName':'alice','Enabled':True}],error='AD unavailable')
        self.assertEqual(status,503)

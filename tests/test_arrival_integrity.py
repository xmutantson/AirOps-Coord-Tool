"""Synthetic route tests for durable arrival identities and response-loss retries."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Barrier
import unittest
from unittest.mock import Mock
from modules.services.arrivals import ensure_arrival_schema
import test_manifest_mutations as mutations


class ArrivalTests(mutations.MutationTests):
    def connect(self, database=None, **kwargs):
        c=sqlite3.connect(database or self.db,factory=mutations.base.ii.ClosingConnection,**kwargs)
        c.row_factory=sqlite3.Row
        return c

    def post_arrival(self, route, **changes):
        with self.app.test_request_context(method='POST',data=self.ramp_form(**changes),
                headers={'X-Requested-With':'XMLHttpRequest'}):
            return route()

    def outbound(self, tail='N456'):
        with self.connect() as c:
            return c.execute("INSERT INTO flights(direction,tail_number,complete,is_ramp_entry) VALUES ('outbound',?,0,1)", (tail,)).lastrowid

    def state(self):
        return {table:self.dict_rows(f'SELECT * FROM {table} ORDER BY rowid') for table in
            ('flights','flight_history','inventory_entries','flight_cargo','manifest_allocations','arrival_requests')}

    def test_arrival_legacy_outbound_retry_preserves_all_committed_effects(self):
        route=self.prepare_ramp(); fid=self.outbound()
        first=self.post_arrival(route).get_json()
        before=self.state()
        effects=Mock(side_effect=AssertionError('Retry must not repeat post-commit effects'))
        self.env.update(wargame_task_start=effects,wargame_finish_ramp_inbound=effects,try_satisfy_ramp_request=effects)
        second=self.post_arrival(route).get_json()
        self.assertEqual((first['id'],second['id']),(fid,fid))
        self.assertEqual(second['action'],'update_ignored')
        self.assertEqual(self.state(),before)
        effects.assert_not_called()

    def test_arrival_lost_response_retries_existing_outbound_and_new_inbound(self):
        route=self.prepare_ramp()
        for existing in (False,True):
            with self.subTest(existing_outbound=existing):
                tail='NOUT' if existing else 'NNEW'
                if existing: self.outbound(tail)
                form=dict(tail_number=tail,arrival_request_id=tail)
                original=self.env['dict_rows']
                def response_lost(sql,*args):
                    if sql == 'SELECT * FROM flights WHERE id=?':
                        raise ConnectionError('Synthetic response lost after commit')
                    return original(sql,*args)
                self.env['dict_rows']=response_lost
                with self.assertRaises(ConnectionError): self.post_arrival(route,**form)
                self.env['dict_rows']=original
                before=self.state()
                result=self.post_arrival(route,**form).get_json()
                self.assertEqual(result['action'],'update_ignored')
                self.assertEqual(self.state(),before)
                self.assertEqual(self.dict_rows("SELECT SUM(quantity) AS n FROM inventory_entries WHERE session_id=?",(f"arrival:{result['id']}",)),[{'n':2}])

    def test_arrival_distinct_requests_preserve_identical_legitimate_arrivals(self):
        route=self.prepare_ramp()
        ids=[self.post_arrival(route,arrival_request_id=key).get_json()['id'] for key in ('delivery-a','delivery-b')]
        self.assertNotEqual(*ids)
        self.assertEqual(self.dict_rows("SELECT SUM(quantity) AS n FROM inventory_entries WHERE session_id LIKE 'arrival:%'"),[{'n':4}])
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM arrival_requests'),[{'n':2}])

    def test_arrival_retry_resolves_before_new_open_leg_selection(self):
        route=self.prepare_ramp(); first=self.outbound()
        self.post_arrival(route,arrival_request_id='first')
        later=self.outbound()
        self.assertEqual(self.post_arrival(route,arrival_request_id='first').get_json()['id'],first)
        self.assertEqual(self.dict_rows('SELECT complete FROM flights WHERE id=?',(later,)),[{'complete':0}])
        self.assertEqual(self.post_arrival(route,arrival_request_id='later').get_json()['id'],later)

    def test_arrival_explicit_manifest_retry_precedes_closed_session_guard(self):
        route=self.prepare_ramp(); self.outbound()
        self.apply(mid='arrival-manifest')
        form=dict(manifest_id='arrival-manifest',arrival_request_id='manifest-request')
        first=self.post_arrival(route,**form).get_json()
        before=self.state()
        self.assertEqual(self.post_arrival(route,**form).get_json()['id'],first['id'])
        self.assertEqual(self.state(),before)
        conflict=self.post_arrival(route,**dict(form,arrival_request_id='different'))
        self.assertEqual(conflict[1],409)
        self.assertEqual(self.state(),before)

    def test_arrival_changed_payload_cannot_reuse_request_identity(self):
        route=self.prepare_ramp()
        self.post_arrival(route,arrival_request_id='event')
        before=self.state()
        conflict=self.post_arrival(route,arrival_request_id='event',cargo_weight='20')
        self.assertEqual(conflict[1],409)
        self.assertEqual(conflict[0].get_json()['status'],'arrival_conflict')
        self.assertEqual(self.state(),before)

    def test_arrival_identity_write_failure_rolls_back_both_flight_paths(self):
        route=self.prepare_ramp()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            mutations.inv.ensure_mutation_schema(c)
            ensure_arrival_schema(c)
        for existing in (False,True):
            with self.subTest(existing_outbound=existing):
                tail='NOUT' if existing else 'NNEW'
                if existing: self.outbound(tail)
                before=self.state()
                with self.connect() as c:
                    c.execute("CREATE TRIGGER fail_arrival BEFORE INSERT ON arrival_requests BEGIN SELECT RAISE(ABORT,'synthetic identity failure'); END")
                with self.assertRaises(sqlite3.IntegrityError):
                    self.post_arrival(route,tail_number=tail,arrival_request_id=tail)
                self.assertEqual(self.state(),before)
                with self.connect() as c: c.execute('DROP TRIGGER fail_arrival')
                self.assertEqual(self.post_arrival(route,tail_number=tail,arrival_request_id=tail).status_code,200)

    def test_arrival_concurrent_duplicate_requests_import_once(self):
        route=self.prepare_ramp(); fid=self.outbound(); barrier=Barrier(2)
        def submit(_):
            barrier.wait(timeout=3)
            return self.post_arrival(route,arrival_request_id='concurrent').get_json()['id']
        with ThreadPoolExecutor(max_workers=2) as pool: ids=list(pool.map(submit,range(2)))
        self.assertEqual(ids,[fid,fid])
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flight_history'),[{'n':1}])
        self.assertEqual(self.dict_rows("SELECT SUM(quantity) AS n FROM inventory_entries WHERE session_id=?",(f'arrival:{fid}',)),[{'n':2}])

    def test_arrival_removed_flight_retry_cannot_recreate_receipts(self):
        route=self.prepare_ramp()
        result=self.post_arrival(route,arrival_request_id='removed').get_json()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            mutations.inv.delete_finalized_flight(c,result['id'])
        before=self.state()
        conflict=self.post_arrival(route,arrival_request_id='removed')
        self.assertEqual(conflict[1],409)
        self.assertEqual(conflict[0].get_json()['status'],'arrival_closed')
        self.assertEqual(self.state(),before)


def load_tests(loader, tests, pattern):
    loader=unittest.TestLoader(); loader.testMethodPrefix='test_arrival_'
    return loader.loadTestsFromTestCase(ArrivalTests)

"""Durable mutation identities and transactional invariants, synthetic SQLite only."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from threading import Barrier
import types
import unittest
from unittest.mock import patch

import test_review_regressions as base
from modules.services import inventory as inv


class MutationTests(base.ReviewRegressionTests):
    def item(self, **changes):
        item = dict(category_id=1,sanitized_name='Rice',size_lb=5,qty=2,origin='Warehouse A')
        item.update(changes)
        return item

    def apply(self, items=None, mid='import-1', key='import-a'):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            return inv.apply_inbound_items(c,mid,items or [self.item()],import_id=key)

    def reverse(self, table='inventory_entries', rid=1, mid='session-1', pending=False):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            return inv.reverse_manifest_entry(c,source_table=table,source_id=rid,session_id=mid,pending=pending)

    def manual(self, action, **values):
        common=types.ModuleType('modules.utils.common')
        common.clean_mid=lambda value:value
        common.touch_pending_session=lambda *_:None
        self.env.update(validate_session_commit=inv.validate_session_commit,InventoryConflict=inv.InventoryConflict,publish_inventory_event=lambda:None)
        with patch.dict('sys.modules',{'modules.utils.common':common}):
            with self.app.test_request_context(method='POST',data=dict(action=action,manifest_id='session-1',**values)):
                return self.extract('inventory_advance_line','modules/routes_inventory/overview.py')()

    def test_mutation_advanced_retry_commits_one_return(self):
        with self.connect() as c:
            c.execute('CREATE TABLE wargame_metrics(event_type,delta_seconds,recorded_at)')
        self.assertTrue(self.manual('delete',entry_id='1').get_json()['success'])
        pending=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        self.manual('delete',entry_id='1')
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),pending)
        self.manual('commit')
        self.assertEqual(self.balance(),{'Warehouse A':10})
        self.manual('delete',entry_id='1')
        self.manual('commit')
        self.assertEqual(self.balance(),{'Warehouse A':10})

    def test_mutation_concurrent_reversal_has_one_compensation(self):
        barrier=Barrier(2)
        def remove(_):
            with sqlite3.connect(self.db,factory=base.ii.ClosingConnection) as c:
                barrier.wait(timeout=3)
                c.execute('BEGIN IMMEDIATE')
                return inv.reverse_manifest_entry(c,source_table='inventory_entries',source_id=1,session_id='session-1',pending=True)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(remove,range(2)))
        self.assertEqual(sorted(r['applied'] for r in results),[0,2])
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.commit_manifest_session(c,'session-1')
        self.assertEqual(self.balance(),{'Warehouse A':10})

    def test_mutation_partial_key_removal_caps_later_row_reversal(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.remove_manifest_item(c,session_id='session-1',queued_id=1,name='Rice',weight=5,qty=1,origin='Warehouse A')
        self.assertEqual(self.reverse()['applied'],1)
        self.assertEqual(self.reverse()['applied'],0)
        self.assertEqual(self.balance(),{'Warehouse A':10})

    def test_mutation_pending_reversal_cancel_then_retry_is_intentional(self):
        comp=self.reverse(pending=True)['comp_id']
        self.assertEqual(self.balance(),{'Warehouse A':8})
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.purge_pending_entry(c,'session-1',comp)
        self.assertEqual(self.reverse(pending=True)['applied'],2)
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.commit_manifest_session(c,'session-1')
        self.assertEqual(self.balance(),{'Warehouse A':10})

    def test_mutation_inbound_reversal_rolls_back_all_snapshot_and_pending_changes(self):
        with self.connect() as c:
            c.execute('DELETE FROM inventory_entries')
            c.execute("UPDATE queued_flights SET direction='inbound'")
            c.execute("UPDATE flight_cargo SET direction='in'")
            self.add_cargo(c,direction='in')
            self.add_cargo(c,direction='in',pending=1,quantity=1)
            c.execute("INSERT INTO inventory_entries(session_id,category_id,sanitized_name,weight_per_unit,quantity,total_weight,direction,origin,pending) VALUES ('other',1,'Rice',5,2,10,'out','Warehouse A',1)")
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        snapshots=self.dict_rows('SELECT * FROM flight_cargo')
        with self.assertRaises(inv.InventoryConflict):
            self.reverse('flight_cargo')
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)
        self.assertEqual(self.dict_rows('SELECT * FROM flight_cargo'),snapshots)
        self.assertEqual(self.balance(),{'Warehouse A':0})

    def test_mutation_advanced_inbound_reversal_checks_stock_before_reserving(self):
        with self.connect() as c:
            c.execute('DELETE FROM inventory_entries')
            c.execute("UPDATE queued_flights SET direction='inbound'")
            c.execute("UPDATE flight_cargo SET direction='in'")
            self.add_cargo(c,direction='in')
            c.execute("INSERT INTO inventory_entries(session_id,category_id,sanitized_name,weight_per_unit,quantity,total_weight,direction,origin,pending) VALUES ('other',1,'Rice',5,2,10,'out','Warehouse A',1)")
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        self.assertEqual(self.manual('delete',entry_id='1')[1],409)
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)

    def test_mutation_identity_distinguishes_tables_and_legacy_collision(self):
        with self.connect() as c:
            self.add_cargo(c,quantity=1,timestamp='2026-10-02T10:02:00')
        self.reverse(rid=3)
        with self.connect() as c:
            self.add_cargo(c,snapshot=True,origin='B',quantity=1)
            self.add_cargo(c,snapshot=True,origin='C',quantity=1)
            self.add_cargo(c,origin='B',quantity=1)
            self.add_cargo(c,origin='C',quantity=1)
        with self.app.test_request_context(method='POST',data={'manifest_id':'session-1'}):
            result=self.extract('delete_flight_cargo')(3)
        self.assertEqual(result.get_json()['status'],'ok')
        self.assertEqual(self.dict_rows('SELECT id FROM flight_cargo WHERE id=3'),[])
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM manifest_reversals WHERE source_id=3'),[{'n':2}])
        # An explicit ledger retry stays a no-op despite a snapshot tombstone.
        self.assertEqual(self.reverse(rid=3)['applied'],0)

    def test_mutation_identity_includes_manifest_when_numeric_ids_are_reused(self):
        self.reverse(rid=1)
        with self.connect() as c:
            c.execute('DELETE FROM flight_cargo')
            c.execute("DELETE FROM inventory_entries WHERE session_id='session-1'")
            c.execute("INSERT INTO inventory_entries(id,session_id,category_id,sanitized_name,weight_per_unit,quantity,total_weight,direction,origin,pending) VALUES (1,'new-session',1,'Rice',5,1,5,'out','Warehouse A',0)")
        self.assertEqual(self.reverse(rid=1,mid='new-session')['applied'],1)

    def test_mutation_reversal_storage_failure_rolls_back_ledger(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.ensure_mutation_schema(c)
            c.execute("CREATE TRIGGER fail_reversal BEFORE INSERT ON manifest_reversals BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        with self.assertRaises(sqlite3.IntegrityError):
            self.reverse()
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)
        with self.connect() as c:
            c.execute('DROP TRIGGER fail_reversal')
        self.assertEqual(self.reverse()['applied'],2)

    def test_mutation_import_retry_and_partial_success_do_not_replay_accepted_items(self):
        items=[self.item(item_id='a'),self.item(item_id='b',category_id=0,qty=3)]
        self.assertEqual(self.apply(items)['inserted'],1)
        result=self.apply([self.item(item_id='a'),self.item(item_id='b',qty=3)])
        self.assertEqual((result['inserted'],result['replayed']),(1,1))
        self.assertEqual(self.apply([self.item(item_id='b',qty=3),self.item(item_id='a')])['replayed'],2)
        self.assertEqual(self.dict_rows("SELECT SUM(quantity) AS qty FROM inventory_entries WHERE session_id='import-1'"),[{'qty':5}])

    def test_mutation_import_rejects_changed_accepted_identity_atomically(self):
        self.apply([self.item(item_id='a')])
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        with self.assertRaises(inv.InventoryConflict):
            self.apply([self.item(item_id='b'),self.item(item_id='a',qty=3)])
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)

    def test_mutation_concurrent_import_retry_records_one_receipt(self):
        barrier=Barrier(2)
        def apply(_):
            with sqlite3.connect(self.db,factory=base.ii.ClosingConnection) as c:
                barrier.wait(timeout=3)
                c.execute('BEGIN IMMEDIATE')
                return inv.apply_inbound_items(c,'import-1',[self.item()],import_id='same-request')
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(apply,range(2)))
        self.assertEqual(sum(r['inserted'] for r in result),1)
        self.assertEqual(sum(r['replayed'] for r in result),1)

    def test_mutation_import_identity_failure_rolls_back_receipt(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.ensure_mutation_schema(c)
            c.execute("CREATE TRIGGER fail_import BEFORE INSERT ON manifest_import_items BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.apply()
        self.assertEqual(self.dict_rows("SELECT * FROM inventory_entries WHERE session_id='import-1'"),[])
        with self.connect() as c:
            c.execute('DROP TRIGGER fail_import')
        self.assertEqual(self.apply()['inserted'],1)

    def test_mutation_closed_session_blocks_import_and_sql_insert_update_delete(self):
        self.sign();self.send()
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        with self.assertRaises(inv.InventoryConflict):
            self.apply(mid='session-1')
        for sql in ("UPDATE inventory_entries SET quantity=3 WHERE session_id='session-1'",
                    "DELETE FROM inventory_entries WHERE session_id='session-1'",
                    "INSERT INTO inventory_entries(session_id,direction,quantity) VALUES ('session-1','in',2)"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                with self.connect() as c:
                    c.execute(sql)
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)

    def test_mutation_direct_attachment_is_atomic_and_closes_empty_sessions(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT INTO flights(id) VALUES (9)')
            inv.attach_manifest_to_flight(c,'empty-session',9,'in')
        with self.assertRaises(inv.InventoryConflict):
            self.apply(mid='empty-session')
        self.apply()
        with self.connect() as c:
            c.execute("CREATE TRIGGER fail_cargo BEFORE INSERT ON flight_cargo BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                inv.attach_manifest_to_flight(c,'import-1',9,'in')
        self.assertEqual(self.dict_rows("SELECT * FROM manifest_allocations WHERE session_id='import-1'"),[])
        with self.connect() as c:
            c.execute('DROP TRIGGER fail_cargo')
            c.execute('BEGIN IMMEDIATE')
            inv.attach_manifest_to_flight(c,'import-1',9,'in')
        with self.assertRaises(inv.InventoryConflict):
            self.apply()

    def test_mutation_finalized_inbound_cancellation_cannot_unfund_reservations(self):
        with self.connect() as c:
            c.execute('DELETE FROM inventory_entries')
            c.execute("UPDATE queued_flights SET direction='inbound'")
            c.execute("UPDATE flight_cargo SET direction='in'")
            self.add_cargo(c,direction='in')
        self.sign();self.send()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.insert_entry(c,category_id=1,name='Rice',weight=5,qty=2,direction='out',origin='Warehouse A',session_id='other',pending=True)
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                inv.delete_finalized_flight(c,1)
        self.assertEqual(self.balance(),{'Warehouse A':0})
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'),[{'n':1}])


    def prepare_ramp(self):
        with self.connect() as c:
            c.execute('CREATE TABLE preferences(name,value)')
            c.execute('CREATE TABLE airports(ident,icao_code,iata_code,gps_code,local_code)')
            c.execute('CREATE TABLE flight_history(flight_id,timestamp,data)')
            c.execute('CREATE TABLE wargame_tasks(role,kind,key)')
            c.execute('ALTER TABLE flights ADD COLUMN complete INTEGER DEFAULT 0')
            c.execute('ALTER TABLE flights ADD COLUMN sent INTEGER DEFAULT 0')
        import re
        self.env.update(json=json,hhmm_norm=lambda value:value,FLIGHT_CODE_RE=re.compile('[A-Z0-9]+'),
            wargame_task_start=lambda **kw:None,wargame_finish_ramp_inbound=lambda *_:None,
            _cargo_reconciler_tick=lambda:None,sanitize_name=lambda value:value,guess_category_id_for_name=lambda *_:1,
            parse_adv_manifest=lambda *_:[dict(name='Rice',size_lb=5,qty=2,origin='Warehouse A')])
        self.extract('queue_flight')
        return self.extract('ramp_boss')

    def ramp_form(self, **changes):
        form=dict(direction='inbound',weight_unit='lbs',pilot_name='Pilot',pax_count='2',tail_number='N456',
            origin='KAAA',destination='KBBB',cargo_type='Food',cargo_weight='10',remarks='Rice 5 lbx2;',dep_time='1200')
        form.update(changes)
        return form

    def test_mutation_direct_arrival_auto_import_is_atomic_and_retry_safe(self):
        route=self.prepare_ramp()
        for _ in range(2):
            with self.app.test_request_context(method='POST',data=self.ramp_form(),headers={'X-Requested-With':'XMLHttpRequest'}):
                response=route()
                self.assertEqual(response.get_json()['id'],1)
        self.assertEqual(self.dict_rows("SELECT SUM(quantity) AS qty FROM inventory_entries WHERE session_id='arrival:1'"),[{'qty':2}])
        self.assertEqual(self.dict_rows("SELECT state FROM manifest_allocations WHERE session_id='arrival:1'"),[{'state':'sent'}])
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'),[{'n':1}])

    def test_mutation_direct_arrival_failure_rolls_back_flight_and_receipt(self):
        route=self.prepare_ramp()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.ensure_mutation_schema(c)
            c.execute("CREATE TRIGGER fail_attach BEFORE INSERT ON flight_cargo BEGIN SELECT RAISE(ABORT,'synthetic attach failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.app.test_request_context(method='POST',data=self.ramp_form()):
                route()
        self.assertEqual(self.dict_rows('SELECT * FROM flights'),[])
        self.assertEqual(self.dict_rows("SELECT * FROM inventory_entries WHERE session_id='arrival:1'"),[])
        self.assertEqual(self.dict_rows('SELECT * FROM flight_history'),[])

    def test_mutation_legacy_outbound_form_enters_acknowledged_queue_workflow(self):
        route=self.prepare_ramp()
        with self.app.test_request_context(method='POST',data=self.ramp_form(direction='outbound',manifest_id='session-1'),headers={'X-Requested-With':'XMLHttpRequest'}):
            result=route()
        self.assertEqual(result.get_json()['status'],'queued')
        self.assertEqual(self.dict_rows('SELECT * FROM flights'),[])

    def test_mutation_pending_expiration_clears_only_uncommitted_reversal_identity(self):
        comp=self.reverse(pending=True)['comp_id']
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.expire_pending_entries(c,'9999')
        self.assertEqual(self.dict_rows('SELECT id FROM inventory_entries WHERE id=?',(comp,)),[])
        self.assertEqual(self.reverse(pending=True)['applied'],2)
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.commit_manifest_session(c,'session-1')
            inv.expire_pending_entries(c,'9999')
        self.assertEqual(self.reverse()['applied'],0)
        self.assertEqual(self.balance(),{'Warehouse A':10})

    def test_mutation_migration_preserves_legacy_ledger_deletion_identity(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.ensure_allocation_schema(c)
            c.execute("INSERT INTO cargo_deletions VALUES ('inventory_entries',1)")
            self.add_cargo(c,direction='in')
            inv.ensure_mutation_schema(c)
            inv.ensure_mutation_schema(c)
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        self.assertEqual(self.reverse()['applied'],0)
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)

    def test_mutation_unattributed_snapshot_never_mints_a_return(self):
        with self.connect() as c:
            c.execute("DELETE FROM inventory_entries WHERE session_id='session-1'")
        before=self.dict_rows('SELECT * FROM inventory_entries')
        with self.assertRaises(inv.InventoryConflict):
            self.reverse('flight_cargo')
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries'),before)
        self.assertEqual(self.delete()[1],409)
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries'),before)

    def test_mutation_bulk_correction_preserves_case_variant_reservation_funding(self):
        with self.connect() as c:
            c.execute("UPDATE inventory_entries SET sanitized_name='RICE' WHERE COALESCE(session_id,'')=''")
        before=self.dict_rows('SELECT * FROM inventory_entries ORDER BY id')
        with self.connect() as c:
            receipt=c.execute("SELECT id FROM inventory_entries WHERE COALESCE(session_id,'')='' AND direction='in'").fetchone()[0]
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                inv.propagate_inventory_entries(c,[receipt],weight=25)
        self.assertEqual(self.dict_rows('SELECT * FROM inventory_entries ORDER BY id'),before)
        self.assertEqual(self.balance(),{'Warehouse A':8})

    def test_mutation_bulk_correction_moves_whole_unscoped_key_atomically(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute("DELETE FROM inventory_entries WHERE session_id='session-1'")
            inv.insert_entry(c,category_id=1,name='Rice',weight=5,qty=2,direction='out',origin='Warehouse A')
            ids=[r[0] for r in c.execute('SELECT id FROM inventory_entries ORDER BY direction DESC')]
            self.assertEqual(inv.propagate_inventory_entries(c,ids,weight=25),2)
            self.assertEqual(inv.available_by_origin(c,1,'Rice',25),{'Warehouse A':8})
            self.assertEqual(inv.available_by_origin(c,1,'Rice',5),{})


def load_tests(loader, tests, pattern):
    loader=unittest.TestLoader()
    loader.testMethodPrefix='test_mutation_'
    return loader.loadTestsFromTestCase(MutationTests)

"""Offline coverage for review findings; external independent tests remain untouched."""
import base64
from datetime import datetime, timezone, timedelta
from io import BytesIO
import logging
import os
from pathlib import Path
import re
import sqlite3
import types
import unittest
import uuid
from unittest.mock import patch

from flask import render_template
from jinja2 import FileSystemLoader
from markupsafe import escape
from PIL import Image

import test_manifest_ack as ma
import test_inventory_integrity as ii
from modules.services import inventory as inv
from modules.services import manifest_images as images

ROOT = Path(__file__).resolve().parents[1]


class ReviewRegressionTests(ma.ManifestAcknowledgementTests):
    def setUp(self):
        super().setUp()
        self.fund_stock()
        with self.connect() as c:
            for col in ('raw_name', 'pending_ts', 'source'):
                c.execute(f'ALTER TABLE inventory_entries ADD COLUMN {col} TEXT')
        self.env.update(logger=logging.getLogger('regression'), escape=escape,
                        timedelta=timedelta, get_preference=lambda *_: 'no')

    def extract(self, name, path='modules/routes/ramp.py'):
        return ii.extracted(path, name, self.env)

    def form(self, **changes):
        data = dict(direction='outbound', pilot_name='Pilot', pax_count='2', tail_number='N123',
                    origin='KAAA', destination='KBBB', travel_time='0030', cargo_weight='10', manifest_id='session-1')
        data.update(changes)
        return data

    def edit(self, **changes):
        with self.app.test_request_context(method='POST', data=self.form(**changes),
                                          headers={'X-Requested-With':'XMLHttpRequest'}):
            return self.env['edit_queued_flight'](1)

    def queue(self):
        with self.app.test_request_context(method='POST', data=self.form(),
                                          headers={'X-Requested-With':'XMLHttpRequest'}):
            return self.extract('queue_flight')()

    def delete(self):
        with self.app.test_request_context(method='POST'):
            return self.extract('delete_queued_flight')(1)

    def balance(self):
        with self.connect() as c:
            return inv.available_by_origin(c, 1, 'Rice', 5)

    def test_regression_queue_retries_share_owner_and_cannot_redispatch(self):
        with self.connect() as c:
            c.execute('DELETE FROM queued_flights')
            c.execute('DELETE FROM flight_cargo')
        first = self.queue().get_json()['qid']
        self.assertEqual(self.queue().get_json()['qid'], first)
        self.assertTrue(self.sign().get_json()['ok'])
        self.assertEqual(self.send().get_json()['status'], 'sent')
        self.send()
        self.assertEqual(self.queue()[1], 409)
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':1}])
        self.assertEqual(self.dict_rows('SELECT SUM(quantity) AS qty FROM flight_cargo WHERE flight_id IS NOT NULL'), [{'qty':2}])
        self.assertEqual(self.balance(), {'Warehouse A':8})

    def test_regression_legacy_duplicate_draft_cannot_consume_or_reverse_owner(self):
        with self.connect() as c:
            c.execute("INSERT INTO queued_flights (id,direction,manifest_id) VALUES (2,'outbound','session-1')")
        with self.app.test_request_context(method='POST'):
            self.extract('delete_queued_flight')(2)
        self.assertEqual(self.balance(), {'Warehouse A':8})
        self.sign()
        self.assertEqual(self.send().get_json()['status'], 'sent')
        self.delete()
        self.assertEqual(self.balance(), {'Warehouse A':8})

    def test_regression_delete_owns_write_lock_before_any_compensation(self):
        self.sign()
        fixture = self
        observed = []
        class LockedConnection(sqlite3.Connection):
            def execute(c, sql, parameters=()):
                if 'INSERT INTO inventory_entries' in sql:
                    fixture.assertTrue(c.in_transaction)
                    with fixture.connect(timeout=0) as competing:
                        with fixture.assertRaises(sqlite3.OperationalError):
                            competing.execute('BEGIN IMMEDIATE')
                    observed.append(True)
                return super().execute(sql, parameters)
        def connect(*_, **kwargs):
            c = sqlite3.connect(self.db, factory=LockedConnection, **kwargs)
            c.row_factory = sqlite3.Row
            self.addCleanup(c.close)
            return c
        self.env['sqlite3'] = types.SimpleNamespace(connect=connect, Row=sqlite3.Row)
        self.delete()
        self.assertTrue(observed)
        self.send()
        self.delete()
        self.assertEqual(self.balance(), {'Warehouse A':10})
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':0}])

    def test_regression_dispatch_wins_then_delete_never_returns_shipped_stock(self):
        self.sign()
        self.send()
        self.delete()
        self.delete()
        self.assertEqual(self.balance(), {'Warehouse A':8})
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':1}])

    def test_regression_receipt_delete_is_rejected_and_legacy_corruption_blocks_dispatch(self):
        self.sign()
        rid = self.dict_rows('SELECT id FROM inventory_entries WHERE session_id IS NULL')[0]['id']
        with self.app.test_request_context(method='POST'):
            response = self.extract('inventory_delete', 'modules/routes_inventory/detail.py')(rid)
        self.assertEqual(response[1], 409)
        self.assertEqual(self.balance(), {'Warehouse A':8})
        with self.connect() as c:
            c.execute('DELETE FROM inventory_entries WHERE id=?', (rid,))
        self.assertEqual(self.send()[1], 409)
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':0}])

    def test_regression_receipt_edit_preserves_reservations_and_item_identity(self):
        rid = self.dict_rows('SELECT id FROM inventory_entries WHERE session_id IS NULL')[0]['id']
        for qty, name, origin in ((1,'Rice','Warehouse A'), (10,'Beans','Warehouse A'), (10,'Rice','warehouse a')):
            with self.subTest(qty=qty,name=name,origin=origin):
                with self.assertRaises(inv.InventoryConflict):
                    with self.connect() as c:
                        c.execute('BEGIN IMMEDIATE')
                        inv.mutate_inventory_entry(c,rid,(1,name,name,5,qty,'in',origin))
                self.assertEqual(self.balance(), {'Warehouse A':8})
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            inv.mutate_inventory_entry(c,rid,(1,'Rice','Rice',5,9,'in','Warehouse A'))
        self.assertEqual(self.balance(), {'Warehouse A':7})

    def test_regression_missing_and_stale_displayed_revision_cannot_sign(self):
        with self.connect() as c:
            displayed = ma.ack.manifest_fingerprint(c,self.draft(c))
        self.edit(destination='KCCC')
        for payload in ({'typed_name':'Pilot'}, {'typed_name':'Pilot','expected_revision':displayed}):
            with self.app.test_request_context(json=payload):
                response = self.env['ramp_pilot_ack'](1)
            self.assertEqual(response[1],409)
            self.assertEqual(response[0].get_json()['error'],'revision_conflict')
        self.assertFalse(self.dict_rows('SELECT pilot_ack_signed_at FROM queued_flights')[0]['pilot_ack_signed_at'])
        self.assertTrue(self.sign().get_json()['ok'])

    def test_regression_full_removal_preserves_cutline_and_next_addition(self):
        with self.connect() as c:
            self.add_cargo(c,direction='in',quantity=2,timestamp='2026-10-02T10:03:00')
        self.edit(cargo_weight='0')
        self.assertEqual(self.dict_rows('SELECT quantity FROM flight_cargo'), [])
        self.assertTrue(self.sign().get_json()['ok'])
        with self.connect() as c:
            # Equal timestamp is intentional: membership, not clock order.
            self.add_cargo(c,quantity=1,timestamp='2026-10-02T10:03:00')
        self.edit(cargo_weight='5')
        self.assertEqual(self.dict_rows('SELECT quantity FROM flight_cargo'), [{'quantity':1}])
        self.assertTrue(self.sign().get_json()['ok'])
        self.send()
        self.assertEqual(self.dict_rows('SELECT cargo_weight_real FROM flights'), [{'cargo_weight_real':5.0}])

    def test_regression_removing_one_source_advances_cutline_for_whole_snapshot(self):
        with self.connect() as c:
            self.add_cargo(c,snapshot=True,origin='Warehouse B',quantity=1)
            self.add_cargo(c,origin='Warehouse B',quantity=1)
            self.add_cargo(c,direction='in',quantity=2,timestamp='2026-10-02T10:02:00')
        self.edit()
        self.assertEqual(self.dict_rows('SELECT origin,quantity FROM flight_cargo'), [{'origin':'Warehouse B','quantity':1}])
        self.assertTrue(self.sign().get_json()['ok'])

    def test_regression_pending_row_committed_later_is_not_hidden_by_cutline(self):
        with self.connect() as c:
            self.add_cargo(c,quantity=1,pending=1,timestamp='2026-10-02T10:00:00')
        self.edit()
        with self.connect() as c:
            c.execute('UPDATE inventory_entries SET pending=0 WHERE pending=1')
        self.edit()
        self.assertEqual(self.dict_rows('SELECT quantity FROM flight_cargo'), [{'quantity':3}])

    def test_regression_legacy_snapshot_delete_preserves_empty_revision(self):
        self.edit()
        fcid = self.dict_rows('SELECT id FROM flight_cargo')[0]['id']
        with self.app.test_request_context(method='POST',data={'manifest_id':'session-1'}):
            self.extract('delete_flight_cargo')(fcid)
        self.assertEqual(self.dict_rows('SELECT quantity FROM flight_cargo'), [])
        self.assertEqual(self.balance(), {'Warehouse A':10})
        self.assertTrue(self.sign().get_json()['ok'])
        with self.connect() as c:
            self.add_cargo(c,quantity=1)
        self.edit(cargo_weight='5')
        self.assertEqual(self.dict_rows('SELECT quantity FROM flight_cargo'), [{'quantity':1}])
        self.assertEqual(self.balance(), {'Warehouse A':9})

    def test_regression_closed_empty_allocation_rejects_new_scans(self):
        self.delete()
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                inv.adjust_pending(c,session_id='session-1',category_id=1,name='Rice',weight=5,
                                   direction='out',delta=1,origin='Warehouse A')
        self.assertEqual(self.balance(), {'Warehouse A':10})

    def test_regression_receipt_edit_route_rolls_back_underfunded_correction(self):
        rid = self.dict_rows('SELECT id FROM inventory_entries WHERE session_id IS NULL')[0]['id']
        self.env.update(sanitize_name=lambda value:value, session={})
        with self.app.test_request_context(method='POST',data=dict(name='Rice',weight='5',qty='1',
                direction='in',category='1',origin='Warehouse A')):
            response = self.extract('inventory_edit','modules/routes_inventory/detail.py')(rid)
        self.assertEqual(response[1],409)
        self.assertEqual(self.balance(),{'Warehouse A':8})

    def test_regression_manifest_identity_cannot_change_during_adoption_or_removal(self):
        with self.app.test_request_context(method='POST',json={'draft_id':1}):
            response = self.extract('api_manifest_adopt_snapshot')('different-session')
        self.assertEqual(response[1],409)
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                inv.remove_manifest_item(c,session_id='different-session',queued_id=1,name='Rice',weight=5)
        self.assertEqual(self.balance(),{'Warehouse A':8})

    def test_regression_queue_table_embeds_revision_for_displayed_row(self):
        self.env.update(render_template=lambda name,**context: context)
        with self.app.test_request_context():
            context = self.extract('queued_flights_table_partial')()
        row = context['queued'][0]
        with self.connect() as c:
            self.assertEqual(row['expected_revision'],ma.ack.manifest_fingerprint(c,self.draft(c)))
        self.assertEqual(row['airfield_landing'],'KBBB')

    def test_regression_case_distinct_sources_reverse_exactly(self):
        with self.connect() as c:
            self.add_cargo(c,snapshot=True,origin='warehouse a',quantity=3)
            self.add_cargo(c,origin='warehouse a',quantity=3)
            c.execute("""INSERT INTO inventory_entries (category_id,sanitized_name,weight_per_unit,quantity,
                total_weight,direction,timestamp,origin,pending) VALUES (1,'Rice',5,10,50,'in','old','warehouse a',0)""")
        self.delete()
        self.assertEqual(self.balance(), {'Warehouse A':10,'warehouse a':10})

    def test_regression_missing_signed_file_blocks_dispatch(self):
        self.sign()
        path = self.dict_rows('SELECT manifest_pdf_path FROM queued_flights')[0]['manifest_pdf_path']
        Path(path).unlink()
        self.assertEqual(self.send()[1],409)
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':0}])
        self.assertEqual(self.balance(), {'Warehouse A':8})

    def test_regression_dispatch_failure_rolls_back_allocation_then_retry(self):
        self.sign()
        with self.connect() as c:
            c.execute("CREATE TRIGGER fail_transfer BEFORE UPDATE OF flight_id ON flight_cargo BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.send()
        self.assertEqual(self.dict_rows('SELECT state FROM manifest_allocations'), [{'state':'queued'}])
        self.assertEqual(self.dict_rows('SELECT consumed FROM queued_flights'), [{'consumed':0}])
        self.assertEqual(self.dict_rows('SELECT COUNT(*) AS n FROM flights'), [{'n':0}])
        with self.connect() as c:
            c.execute('DROP TRIGGER fail_transfer')
        self.assertEqual(self.send().get_json()['status'],'sent')

    def test_regression_typed_pdf_total_matches_dispatch_and_ignores_remarks_numbers(self):
        with self.connect() as c:
            c.execute('DELETE FROM flight_cargo')
            c.execute("DELETE FROM inventory_entries WHERE session_id='session-1'")
            c.execute("UPDATE queued_flights SET cargo_weight='125.25',remarks='Manifest: old rice 5 lbx2;'")
        self.app.jinja_loader=FileSystemLoader(str(ROOT/'templates'))
        self.app.jinja_env.globals['get_preference']=lambda *_: ''
        rendered=[]
        class Renderer:
            def __init__(self,string,**kwargs):
                rendered.append(string)
                self.fetcher = kwargs['url_fetcher']
            def write_pdf(self,**kwargs):
                return b'OFFLINE PDF PLACEHOLDER'
        env=dict(os=os,re=re,datetime=datetime,timezone=timezone,Path=Path,uuid=uuid,HTML=Renderer,CSS=None,
                 get_db_file=lambda:self.db,render_template=render_template,STORE_ROOT=Path(self.tmp.name)/'pdf')
        for name in ('_sanitize_tail','_ensure_dir','build_manifest_pdf'):
            ii.extracted('modules/utils/manifest.py',name,env)
        fake=types.ModuleType('modules.utils.manifest')
        fake.build_manifest_pdf=env['build_manifest_pdf']
        real_connect=sqlite3.connect
        with patch.dict('sys.modules',{'modules.utils.manifest':fake}), patch.object(sqlite3,'connect',side_effect=lambda *a,**kw:real_connect(*a,factory=ii.ClosingConnection,**kw)):
            self.assertTrue(self.sign(build=True).get_json()['ok'])
        self.send()
        self.assertEqual(self.dict_rows('SELECT cargo_weight_real,cargo_weight FROM flights'), [{'cargo_weight_real':125.25,'cargo_weight':'125.25 lbs'}])
        total=re.search(r'Grand Total.*?<th class="right">\s*([^<]+)',rendered[0],re.S).group(1).strip()
        self.assertEqual(float(total),125.25)


class LegacyDeleteTests(ii.InventoryRouteTests):
    def test_regression_legacy_delete_retry_compensates_once(self):
        self.seed(10)
        self.seed(2,direction='out',session='m')
        fn=ii.extracted('modules/routes/ramp.py','delete_flight_cargo',dict(sqlite3=self.sqlite_api,DB_FILE=self.db,
            datetime=datetime,clean_mid=lambda mid:mid,jsonify=ii.jsonify,request=types.SimpleNamespace(form={'manifest_id':'m'})))
        fn(2)
        first=self.entries()
        fn(2)
        self.assertEqual(self.entries(),first)
        self.assertEqual(self.balances(),{'A':10})


class SignatureTests(unittest.TestCase):
    def png(self):
        buf=BytesIO()
        with Image.new('RGBA',(8,4),'white') as img:
            img.save(buf,format='PNG')
        return images.PNG_PREFIX+base64.b64encode(buf.getvalue()).decode('ascii')

    def test_regression_png_roundtrip_and_legacy_base64(self):
        png=self.png()
        clean=images.validate_signature(png)
        self.assertEqual(images.validate_signature(png[len(images.PNG_PREFIX):]),clean)
        self.assertEqual(images.signature_fetcher(clean)(clean)['mime_type'],'image/png')
        self.assertEqual(images.validate_signature(''),'')

    def test_regression_benign_invalid_and_small_boundary_inputs(self):
        with self.assertRaises(ValueError):
            images.validate_signature('not a signature')
        with patch.object(images,'MAX_SIGNATURE_BYTES',8), self.assertRaises(ValueError):
            images.validate_signature(self.png())
        with patch.object(images,'MAX_SIGNATURE_PIXELS',8), self.assertRaises(ValueError):
            images.validate_signature(self.png())
        with self.assertRaises(ValueError):
            images.signature_fetcher('')('unused-resource')


def load_tests(loader, tests, pattern):
    # Baseline parent methods are already executed by test_manifest_ack/inventory.
    loader=unittest.TestLoader()
    loader.testMethodPrefix='test_regression_'
    return unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in
                              (ReviewRegressionTests,LegacyDeleteTests,SignatureTests))

from pathlib import Path
import unittest
from unittest.mock import patch
from tools.adapter_audit import audit
ROOT=Path(__file__).resolve().parents[1]
class AdapterAuditTests(unittest.TestCase):
 def test_mismatched_input_manifest_stops_before_snapshot_reads(self):
  bundle={'build':{'input_manifests':[{'path':'vendors.json','sha256':'0'*64}]}}
  with patch('tools.adapter_audit.load_bundle',return_value=bundle), \
       patch('tools.adapter_audit.load_snapshot') as load_snapshot:
   with self.assertRaisesRegex(ValueError,'does not match'):
    audit(ROOT/'data/etl/vendors.json',ROOT/'data/etl/repro/vendors.json',ROOT/'unused-bundle')
   load_snapshot.assert_not_called()

 def test_all_documents_have_explicit_coverage_or_unavailability(self):
  result=audit(ROOT/'data/etl/vendors.json',ROOT/'data/etl/repro/vendors.json')
  self.assertEqual(56,result['summary']['documents']);self.assertEqual(53,result['summary']['with_snapshot'])
  self.assertEqual(0,result['summary']['unexplained'])
  self.assertTrue(all(row['sections'] for row in result['documents']))
  statuses=result['summary']['section_statuses']
  self.assertEqual(3,statuses['not_available'])
  self.assertGreater(statuses['candidates_only'],0)
  by_key = {(row['siem_id'], row['source_id']): row for row in result['documents']}
  self.assertEqual(
      result['summary']['documents_with_sections_requiring_review'],
      sum(bool(row['sections_requiring_review']) for row in by_key.values()),
  )
  self.assertEqual('html_shell_without_visible_content',
                   by_key['p06', 'deployment']['sections_requiring_review'][0]['reason'])
  self.assertFalse(by_key['p03', 'source_catalog']['sections_requiring_review'])
  maxpatrol={row['source_id']:row['sections'][0] for row in result['documents']
             if row['siem_id']=='p06'}
  for source_id in ('sources','supported_sources','deployment'):
   with self.subTest(source_id=source_id):
    self.assertEqual('not_extracted',maxpatrol[source_id]['status'])
    self.assertEqual('html_shell_without_visible_content',maxpatrol[source_id]['reason'])
  for source_id in ('supported_sources_api','partial_sources'):
   self.assertEqual('extracted',maxpatrol[source_id]['status'])
   self.assertGreater(maxpatrol[source_id]['record_count'],0)
  rvision = next(row for row in result['documents']
                 if row['siem_id'] == 'p03' and row['source_id'] == 'source_catalog')
  connections = rvision['connection_rows_needing_review']
  self.assertEqual(2, len(connections))
  self.assertTrue(all(row['excerpt'] for row in connections))
  ksc = next(row for row in connections if row['source'] == 'Kaspersky Security Center')
  self.assertEqual('partially_reviewed', ksc['relationship'])
  self.assertEqual({'DB MS SQL': 'database_collection',
                    'DB MySQL (MariaDB)': 'database_collection',
                    'DB PostgreSQL': 'database_collection',
                    'Syslog CEF': 'catalog_listed_scope_unknown'}, ksc['roles'])
  self.assertEqual(4, len(ksc['external_evidence']))
  self.assertEqual(['partially_reviewed', 'unknown'], sorted(row['relationship'] for row in connections))
  entries = [row['entries'] for row in connections]
  self.assertIn(['Syslog', 'Database'], entries)
  self.assertIn(['DB MS SQL', 'DB MySQL (MariaDB)', 'DB PostgreSQL', 'Syslog CEF'], entries)
  self.assertNotIn(['WMI', 'GPO'], entries)
  rows = {row['source']: row for row in rvision['connection_rows_with_reviewed_roles']}
  self.assertEqual({'Database': 'collection', 'SQL Audit': 'source_event_mechanism'},
                   rows['Microsoft SQL Server']['roles'])
  self.assertEqual({'Database': 'audit_stream', 'R-Vision Endpoint': 'service_event_stream'},
                   rows['Virtual Apps and Desktops']['roles'])
  reviewed = rows['Windows Management Instrumentation (WMI)']
  self.assertEqual({'WMI': 'collection', 'GPO': 'source_configuration'}, reviewed['roles'])
  self.assertEqual(2, len(reviewed['external_evidence']))
  self.assertEqual('Syslog', rows['Apache HTTP Server']['shared_transport'])
  self.assertEqual('MS SQL Database', rows['Secret Net Studio']['shared_transport'])
  self.assertEqual({'R-Vision Endpoint': 'collection_alternative', 'Syslog': 'collection_alternative'},
                   rows['Linux Auditd']['roles'])
  self.assertEqual({'Syslog': 'collection_alternative', 'Database': 'collection_alternative'},
                   rows['Oracle Database']['roles'])
if __name__=='__main__':unittest.main()

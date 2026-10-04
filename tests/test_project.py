import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from soc_case_manager.models import Incident, NetworkEvent, EndpointEvent, InvestigationAction, Task, RemediationPlan
from soc_case_manager.repository import load_incidents
from soc_case_manager.processing import IncidentProcessor
from soc_case_manager.iterators import IncidentCollection, create_lazy_pipeline
from soc_case_manager.context_managers import IncidentInvestigationContext
from soc_case_manager.reports import RemediationManager


class ProjectChecks(unittest.TestCase):
    def test_demo(self):
        result = subprocess.run([sys.executable, '-B', 'main.py'], cwd=ROOT,
                                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
                                capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('=== סיום ההדגמה ===', result.stdout)
        self.assertIn('דוח אחרי השלמת משימה', result.stdout)
        self.assertIn('(Done)', result.stdout)
        self.assertIn('FIFO', result.stdout)
        self.assertIn('מעבר חוזר על הגנרטור שמוצה: []', result.stdout)

    def test_invalid_records_and_duplicate_ids(self):
        valid = {'id': 'X', 'title': 'first', 'severity': 'High'}
        rows = [None, [], 42, {}, {**valid, 'id': ''}, {**valid, 'id': None},
                {**valid, 'severity': []}, {**valid, 'status': {}},
                valid, {**valid, 'title': 'duplicate'},
                {**valid, 'id': 'Y'}]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'records.jsonl'
            path.write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                result = load_incidents(path)
        self.assertEqual([i.incident_id for i in result], ['X', 'Y'])
        self.assertEqual(result[0].title, 'first')

    def test_task_validation_and_repeat_loading(self):
        processor = IncidentProcessor()
        processor.build_index([Incident('X', 'case', 'High')])
        manager = RemediationManager(processor)
        valid = {'task_id': 'T1', 'incident_id': 'X', 'description': 'test', 'assigned_team': 'IT'}
        rows = [None, [], {}, {**valid, 'task_id': ''}, {**valid, 'incident_id': []},
                {**valid, 'incident_id': 'missing'}, valid, valid]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'tasks.jsonl'
            path.write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                manager.load_tasks(path)
                manager.load_tasks(path)
        self.assertEqual(manager.generate_open_tasks_report(), {'IT': 1})

    def test_alternative_constructors(self):
        net = NetworkEvent.from_dict({'event_id':'n','timestamp':'2026-10-04','source':'FW','suspicious_ip':'192.0.2.1','port':22})
        endpoint = EndpointEvent.from_dict({'event_id':'e','timestamp':'2026-10-04','source':'EDR','malware_signature':'test'})
        action = InvestigationAction.from_dict({'action_id':'a','description':'scan','analyst_name':'demo'})
        plan = RemediationPlan.from_dict({'plan_id':'P','incident_id':'X','tasks':[{'task_id':'T','description':'scan','assigned_team':'IT'}]})
        incident = Incident('X', 'case', 'High')
        incident.add_event(net)
        incident.add_event(endpoint)
        incident.add_action(action)
        self.assertEqual(incident.calculate_total_risk(), 17)
        self.assertEqual(incident.get_actions_by_analyst('demo'), [action])
        self.assertEqual(len(plan.get_open_tasks()), 1)
        self.assertIn('incident=X', repr(plan))

    def test_yield_continuation_and_exhaustion(self):
        from soc_case_manager.iterators import generate_open_incidents
        incidents = [Incident('1', 'one', 'High'), Incident('2', 'two', 'Low')]
        generator = generate_open_incidents(incidents)
        self.assertIs(next(generator), incidents[0])
        self.assertEqual(list(generator), incidents[1:])
        self.assertEqual(list(generator), [])
        self.assertEqual(list(generate_open_incidents(incidents)), incidents)

    def test_collection_processing(self):
        processor = IncidentProcessor()
        incidents = [Incident('B', 'second', 'High'), Incident('A', 'first', 'High'), Incident('C', 'third', 'Low')]
        incidents[0].status = 'Closed'
        self.assertEqual([i.incident_id for i in processor.sort_by_severity_and_id(incidents)], ['A', 'B', 'C'])
        self.assertEqual([i.status for i in processor.sort_by_status_lambda(incidents)], ['Closed', 'Open', 'Open'])
        self.assertEqual(processor.get_unique_severities(incidents), {'High', 'Low'})
        self.assertEqual(processor.extract_first_and_rest(incidents), (incidents[0], incidents[1:]))
        self.assertEqual(processor.extract_first_and_rest([]), (None, []))
        self.assertEqual(processor.demonstrate_set_operations(), {'INC-001', 'INC-002', 'INC-003', 'INC-004'})

    def test_sample_loading(self):
        incidents = load_incidents(ROOT / 'data/sample_data.jsonl')
        self.assertEqual(len(incidents), 15)
        self.assertEqual(len({i.incident_id for i in incidents}), 15)

    def test_invalid_input_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.jsonl'
            path.write_text('\nnot json\n{}\n' + json.dumps({'id': 'bad', 'title': 'bad', 'severity': 'Unknown'}) + '\n' + json.dumps({'id': 'ok', 'title': 'valid', 'severity': 'High'}), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                result = load_incidents(path)
            self.assertEqual([i.incident_id for i in result], ['ok'])

    def test_models_and_validation(self):
        incident = Incident('1', 'Case', 'High')
        incident.add_event(NetworkEvent('n', '2026-10-02', 'Firewall', '192.0.2.1', 22))
        incident.add_event(EndpointEvent('e', '2026-10-02', 'EDR', 'test'))
        self.assertEqual(incident.calculate_total_risk(), 17)
        with self.assertRaises(ValueError):
            incident.severity = 'Unknown'
        with self.assertRaises(ValueError):
            incident.status = 'Unknown'

    def test_fifo_and_priority(self):
        processor = IncidentProcessor()
        incidents = [Incident('3', 'Low', 'Low'), Incident('2', 'Critical', 'Critical'), Incident('1', 'Critical', 'Critical')]
        for incident in incidents:
            processor.add_to_fifo(incident)
            processor.add_to_priority(incident)
        self.assertEqual([processor.process_next_fifo().incident_id for _ in incidents], ['3', '2', '1'])
        self.assertEqual([processor.process_next_priority().incident_id for _ in incidents], ['1', '2', '3'])
        self.assertIsNone(processor.process_next_fifo())
        self.assertIsNone(processor.process_next_priority())

    def test_independent_iterators_and_lazy_pipeline(self):
        collection = IncidentCollection()
        incidents = [Incident('1', 'Critical', 'Critical'), Incident('2', 'High', 'High')]
        incidents[0].status = 'In Progress'
        for incident in incidents:
            collection.add_incident(incident)
        first, second = iter(collection), iter(collection)
        self.assertEqual(next(first).incident_id, '1')
        self.assertEqual(next(first).incident_id, '2')
        self.assertEqual(next(second).incident_id, '1')
        self.assertEqual(list(create_lazy_pipeline(incidents)), ['1'])

    def test_context_success_and_rollback(self):
        incident = Incident('1', 'Case', 'High')
        with contextlib.redirect_stdout(io.StringIO()):
            with IncidentInvestigationContext(incident):
                incident.status = 'Closed'
            self.assertEqual(incident.status, 'Closed')
            with self.assertRaises(RuntimeError):
                with IncidentInvestigationContext(incident):
                    raise RuntimeError('test failure')
        self.assertEqual(incident.status, 'Closed')

    def test_remediation_reports(self):
        processor = IncidentProcessor()
        processor.build_index(load_incidents(ROOT / 'data/sample_data.jsonl'))
        manager = RemediationManager(processor)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            manager.load_tasks(ROOT / 'data/remediation_tasks.jsonl')
            manager.display_report()
        self.assertIn('T-106 skipped', output.getvalue())
        self.assertEqual(manager.generate_open_tasks_report(), {'IT Ops': 1, 'Security': 2, 'Network': 1, 'Identity': 1})
        manager.plans['RP-INC-002'].tasks[0].mark_completed()
        self.assertNotIn('IT Ops', manager.generate_open_tasks_report())


if __name__ == '__main__':
    unittest.main(verbosity=2)


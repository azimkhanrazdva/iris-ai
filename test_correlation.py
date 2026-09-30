import copy
import importlib.util
import json
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch
import attack_correlation as c
import iris_alert_ai as m

REAL = json.loads(Path(__file__).with_name('inspection-alerts.json').read_text())


def alert(aid, stage='brute_force', host='server01', user='alice', ip='soc-storage.example.test', minute=0, **extra):
    a = copy.deepcopy(REAL[1])
    a.update(alert_id=aid, cases=[], alert_source_ref=f'scenario-{aid}', alert_title=stage,
             alert_description='Synthetic regression scenario', alert_source_event_time=f'2026-09-25T12:{minute:02}:00Z')
    result = dict(dest_host=host, user=user, src_ip=ip, event_type=stage, **extra)
    a['alert_source_content'] = {'sid': f'scenario-{aid}', 'result': result}
    return a


def ai(case=None, refs=None):
    return dict(case_title='Test incident', severity='high', summary='Review login activity.',
                extracted_entities={}, likely_scenario='Requires verification', recommended_actions=['Review authentication logs.'],
                confidence='high', correlation={'relation': 'same_attack' if case else 'unrelated',
                'case_id': case, 'confidence': .9, 'evidence_alert_ids': refs or [], 'reason': 'Event sequence'})


class Regression(unittest.TestCase):
    def setUp(self):
        self.db = m.init_db(':memory:')

    def seed(self, a, cid=1):
        analysis = ai()
        analysis['_alert'] = a
        m.mark_alert(self.db, a['alert_id'], a['alert_source_ref'], 'case_created', case_id=cid,
                     analysis=analysis, fingerprint=c.fingerprint(a))

    def decision(self, a, cid=1, refs=None):
        return c.decide(c.candidates(self.db, a), ai(cid, refs or [1]), a)

    def test_one_chain_six_events(self):
        stages = ['brute_force', 'successful_login', 'powershell', 'privilege_escalation', 'c2', 'data_access']
        for index, stage in enumerate(stages, 1):
            a = alert(index, stage, minute=index)
            if index > 1:
                self.assertEqual(self.decision(a, refs=list(range(1,index)))['relation'], 'same_attack')
            self.seed(a)
        self.assertEqual(len(c.candidates(self.db, alert(9, 'exfiltration', minute=10))), 1)

    def test_two_parallel_attacks(self):
        self.seed(alert(1))
        self.seed(alert(2, 'phishing', 'server02', 'bob', '203.0.113.1', 1), 2)
        self.assertEqual(self.decision(alert(3, 'successful_login', minute=2))['case_id'], 1)
        self.assertEqual(self.decision(alert(4, 'powershell', 'server02', 'bob', '203.0.113.1', 3), 2, [2])['case_id'], 2)

    def test_same_ip_different_targets_are_related_not_merged(self):
        self.seed(alert(1))
        d = self.decision(alert(2, host='server02', minute=1))
        self.assertEqual(d['relation'], 'related')
        self.assertIsNone(d['case_id'])

    def test_same_ioc_different_chain(self):
        self.seed(alert(1, 'powershell', sha256='abc'))
        self.assertNotEqual(self.decision(alert(2, 'c2', 'other', 'bob', '203.0.113.1', 1, sha256='abc'))['relation'], 'same_attack')

    def test_lateral_movement_needs_causal_bridge(self):
        self.seed(alert(1, 'powershell'))
        a = alert(2, 'lateral_movement', 'server02', minute=1, src_host='server01')
        self.assertEqual(self.decision(a)['relation'], 'same_attack')

    def test_delayed_arrival_uses_event_time(self):
        self.seed(alert(1))
        a = alert(2, 'successful_login', minute=1)
        a['alert_creation_time'] = '2026-09-27T12:01:00Z'
        self.assertEqual(self.decision(a)['relation'], 'same_attack')

    def test_out_of_order(self):
        self.seed(alert(1, 'powershell', minute=2))
        a = alert(2, 'successful_login', minute=1)
        self.assertEqual(self.decision(a)['relation'], 'same_attack')
        self.seed(a)
        self.assertEqual([e['id'] for e in c.candidates(self.db, alert(3, 'c2', minute=3))[0]['timeline']], [2, 1])

    def test_distant_event_does_not_merge(self):
        self.seed(alert(1))
        a = alert(2, 'successful_login')
        a['alert_source_event_time'] = '2026-09-26T12:00:00Z'
        self.assertNotEqual(self.decision(a)['relation'], 'same_attack')

    def test_session_conflict_vetoes_similarity(self):
        self.seed(alert(1, 'successful_login', session_id='a'))
        self.assertNotEqual(self.decision(alert(2, 'powershell', minute=1, session_id='b'))['relation'], 'same_attack')

    def test_shared_host_user_without_chain_is_not_enough(self):
        self.seed(alert(1, 'brute_force'))
        self.assertNotEqual(self.decision(alert(2, 'powershell', minute=1))['relation'], 'same_attack')

    def test_ambiguous_two_cases(self):
        self.seed(alert(1), 1)
        self.seed(alert(2), 2)
        self.assertEqual(self.decision(alert(3, 'successful_login', minute=1))['relation'], 'uncertain')

    def test_insufficient_evidence(self):
        a = alert(1, 'unknown', '', '', '')
        a['alert_source_event_time'] = None
        self.assertEqual(c.decide([], ai(), a)['relation'], 'uncertain')

    def test_duplicate_real_payload(self):
        self.assertEqual(c.fingerprint(REAL[-1]), c.fingerprint(REAL[-2]))
        a = copy.deepcopy(REAL[-1])
        a['alert_source_content']['result']['dest_host'] = 'different'
        self.assertNotEqual(c.fingerprint(a), c.fingerprint(REAL[-1]))

    def test_no_ref_distinct_events(self):
        a, b = alert(1), alert(2, minute=1)
        for e in (a,b):
            e['alert_source_ref'] = None
            e['alert_source_content'].pop('sid')
        self.assertNotEqual(c.fingerprint(a), c.fingerprint(b))

    def test_customer_boundary(self):
        self.seed(alert(1))
        a = alert(2, 'successful_login', minute=1)
        a['alert_customer_id'] = 9
        self.assertEqual(c.candidates(self.db, a), [])

    def test_ai_cannot_select_foreign_id(self):
        self.seed(alert(1))
        self.assertEqual(self.decision(alert(2, 'successful_login', minute=1), cid=99)['relation'], 'uncertain')

    def test_ai_cannot_invent_evidence(self):
        self.seed(alert(1))
        self.assertEqual(self.decision(alert(2, 'successful_login', minute=1), refs=[999])['relation'], 'uncertain')

    def test_ai_unavailable_is_uncertain(self):
        self.seed(alert(1))
        a = alert(2, 'successful_login', minute=1)
        self.assertEqual(c.decide(c.candidates(self.db, a), {'_fallback': True}, a)['relation'], 'uncertain')

    def test_invalid_json_rejected(self):
        with patch.object(m, 'request_json', return_value={'message': {'content': '{broken'}}):
            with self.assertRaises(ValueError):
                m.analyze_with_ollama({'OLLAMA_BASE_URL':'http://localhost'}, alert(1))

    def test_render_distinct_facts_and_no_raw_dump(self):
        a = alert(1, failed_count=21)
        b = alert(2, 'powershell', minute=1, process='powershell.exe')
        text = c.overview([dict(ai(), _alert=b), dict(ai(), _alert=a)])
        self.assertIn('Failed logins: 21', text)
        self.assertIn('powershell.exe', text)
        self.assertLess(text.index('[#1]'), text.index('[#2]'))
        self.assertNotIn('```json', text)
        self.assertNotRegex(text, r'[А-Яа-яЁё]')

    def test_pagination_past_done_duplicates(self):
        self.seed(alert(1))
        responses = [{'status':'success','data':{'alerts':[{'alert_id':1}]}}, {'status':'success','data':{'alerts':[{'alert_id':2}]}}]
        cfg={'IRIS_BASE_URL':'https://iris', 'IRIS_API_KEY':'test', 'PER_PAGE':'1', 'MAX_ALERTS_PER_CYCLE':'1'}
        with patch.object(m, 'request_json', side_effect=responses):
            self.assertEqual(m.fetch_candidate_alerts(cfg, self.db), [{'alert_id':2}])

    def test_process_ai_failure_preserves_alert_and_case(self):
        a = alert(30)
        cfg={'MAX_ALERTS_PER_CYCLE':'1'}
        with patch.object(m, 'fetch_candidate_alerts', return_value=[a]), patch.object(m, 'fetch_alert', return_value=a), \
             patch.object(m, 'analyze_with_ollama', side_effect=TimeoutError()), patch.object(m, 'escalate_alert', return_value=42), \
             patch.object(m, 'flush_summaries'):
            m.process_once(cfg, self.db)
        row=self.db.execute('select status,case_id,analysis_json from processed_alerts where alert_id=30').fetchone()
        self.assertEqual(row[:2], ('uncertain',42))
        self.assertEqual(json.loads(row[2])['_alert']['alert_source_content'], a['alert_source_content'])

    def test_recover_after_remote_mutation_does_not_create_again(self):
        a=alert(1)
        m.mark_alert(self.db, 1, a['alert_source_ref'], 'prepared', analysis=dict(ai(), _alert=a))
        a['cases']=[7]
        with patch.object(m, 'fetch_candidate_alerts', return_value=[]), patch.object(m, 'fetch_alert', return_value=a), \
             patch.object(m, 'escalate_alert') as create, patch.object(m, 'flush_summaries'):
            m.process_once({'MAX_ALERTS_PER_CYCLE':'1'}, self.db)
        create.assert_not_called()
        self.assertEqual(self.db.execute('select case_id from processed_alerts').fetchone()[0],7)


if __name__ == '__main__':
    unittest.main(verbosity=2)

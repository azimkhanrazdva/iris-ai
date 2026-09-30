"""Evidence checks and presentation for the existing IRIS alert poller."""
from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone


FIELDS = {
    'src_ip': ('src_ip', 'source_ip', 'client_ip', 'remote_ip'),
    'dst_ip': ('dest_ip', 'dst_ip', 'destination_ip'),
    'src_host': ('src_host', 'source_host'),
    'dst_host': ('dest_host', 'dst_host', 'destination_host', 'host', 'hostname', 'computer'),
    'user': ('user', 'username', 'account', 'dest_user'),
    'session': ('session_id', 'logon_id', 'logon_guid', 'session_guid'),
    'process_id': ('process_guid', 'process_entity_id'),
    'parent_id': ('parent_process_guid', 'parent_process_entity_id'),
    'process': ('process', 'process_name', 'image'),
    'parent': ('parent_process', 'parent_process_name', 'parent_image'),
    'command': ('command_line', 'commandline', 'cmdline'),
    'domain': ('domain', 'dns', 'fqdn', 'query'),
    'url': ('url', 'uri'),
    'hash': ('hash', 'file_hash', 'sha256', 'sha1', 'md5'),
    'technique': ('technique', 'technique_id', 'mitre_technique', 'mitre_technique_id'),
    'tactic': ('tactic', 'mitre_tactic'),
    'rule': ('rule', 'rule_id', 'rule_name', 'search_name'),
    'kind': ('event_type', 'alert_type', 'attack_stage'),
}
STAGE_NAMES = {
    'brute_force': 'Password brute force', 'login': 'Successful login',
    'phishing': 'Phishing', 'execution': 'Process execution',
    'privilege': 'Privilege escalation', 'c2': 'Command and control',
    'lateral': 'Lateral movement', 'data_access': 'Data access',
    'exfiltration': 'Data exfiltration', 'unknown': 'Unclassified event',
}
TRANSITIONS = {
    ('brute_force', 'login'), ('phishing', 'execution'), ('login', 'execution'),
    ('execution', 'privilege'), ('execution', 'c2'), ('privilege', 'c2'),
    ('execution', 'data_access'), ('c2', 'data_access'), ('data_access', 'exfiltration'),
    ('c2', 'exfiltration'), ('execution', 'lateral'), ('privilege', 'lateral'),
    ('lateral', 'login'), ('lateral', 'execution'),
}


def values(data, keys):
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in keys:
                items = value if isinstance(value, list) else [value]
                found.extend(str(v).strip() for v in items if isinstance(v, (str, int, float)) and str(v).strip())
            if isinstance(value, (dict, list)):
                found.extend(values(value, keys))
    elif isinstance(data, list):
        for item in data:
            found.extend(values(item, keys))
    return list(dict.fromkeys(found))


def timestamp(value):
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r'\d{10}(\.\d+)?', str(value)):
            return float(value)
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def facts(alert):
    content = alert.get('alert_source_content') or {}
    if not isinstance(content, dict):
        content = {}
    f = {key: sorted({v.lower() for v in values(content, aliases)}) for key, aliases in FIELDS.items()}
    # Source event time outranks ingestion time, including nested Splunk _time.
    times = values(content.get('result', content), ('_time', 'event_time', 'timestamp'))
    event_time = times[0] if times else alert.get('alert_source_event_time')
    f.update(id=alert.get('alert_id'), customer=alert.get('alert_customer_id'),
             time=event_time, ts=timestamp(event_time), severity=alert.get('alert_severity_id'),
             title=alert.get('alert_title', ''), stage='unknown')
    kind = ' '.join(f['kind']).lower()
    text = kind or str(alert.get('alert_title', '')).lower()
    stage_terms = [
        ('brute_force', ('brute', 'failed login', 'failed_login', 'подбор')),
        ('login', ('successful_login', 'successful login', 'login_success', 'успешный вход')),
        ('phishing', ('phish', 'фишинг', 't1566')),
        ('privilege', ('privilege', 'elevation', 'повышение')),
        ('lateral', ('lateral', 'remote execution', 'psexec')),
        ('exfiltration', ('exfil', 'эксфильтрация')),
        ('data_access', ('data_access', 'data access', 'collection')),
        ('c2', ('c2', 'command_and_control', 'command and control', 'beacon')),
        ('execution', ('powershell', 'process', 'execution', 'malware', 'file', 't1059')),
    ]
    for stage, terms in stage_terms:
        if any(term in text for term in terms):
            f['stage'] = stage
            break
    if f['stage'] == 'unknown' and f['process']:
        f['stage'] = 'execution'
    return f


def fingerprint(alert):
    content = alert.get('alert_source_content') or {}
    ref = alert.get('alert_source_ref') or (content.get('sid') if isinstance(content, dict) else None)
    stable = {'customer': alert.get('alert_customer_id'), 'source': alert.get('alert_source'),
              'ref': ref, 'content': content}
    if not ref:
        stable['time'] = alert.get('alert_source_event_time')
        stable['title'] = alert.get('alert_title')
        stable['description'] = alert.get('alert_description')
        if not stable['time']:
            stable['id'] = alert.get('alert_id')
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def overlap(a, b, key):
    return bool(set(a.get(key, [])) & set(b.get(key, [])))


def pair_evidence(new, old):
    evidence, against = [], []
    if new['customer'] is None or new['customer'] != old['customer']:
        return {'eligible': False, 'related': False, 'score': 0, 'evidence': [], 'against': ['Different or unknown customer scope']}
    matches = [key for key in FIELDS if overlap(new, old, key)]
    same_target = overlap(new, old, 'dst_host') or overlap(new, old, 'dst_ip')
    conflicts = [key for key in ('dst_host', 'dst_ip', 'user', 'session')
                 if new[key] and old[key] and not overlap(new, old, key)]
    if 'dst_host' in conflicts and overlap(new, old, 'dst_ip'):
        conflicts.remove('dst_host')
    time_ok = new['ts'] is not None and old['ts'] is not None and abs(new['ts'] - old['ts']) <= 7200
    if not time_ok:
        against.append('No confirmed temporal proximity between events; correlation window is 2 hours')
    older, later = (old, new) if (old['ts'] or 0) <= (new['ts'] or 0) else (new, old)
    sequence = (older['stage'], later['stage']) in TRANSITIONS
    session = same_target and overlap(new, old, 'session')
    process = same_target and (overlap(new, old, 'process_id') or
        bool(set(new['parent_id']) & set(old['process_id'])) or bool(set(old['parent_id']) & set(new['process_id'])))
    pivot = (bool(set(older['dst_host']) & set(later['src_host'])) or
             bool(set(older['dst_ip']) & set(later['src_ip']))) and later['stage'] in {'lateral', 'login', 'execution'}
    lateral = pivot and overlap(new, old, 'user') and sequence
    # Explicit session/process linkage can explain progression, but not contradictory principals.
    blocking = [key for key in conflicts if key in ('user', 'session') or not lateral]
    src_conflict = new['src_ip'] and old['src_ip'] and not overlap(new, old, 'src_ip')
    if src_conflict and not (session or process or lateral) and {new['stage'], old['stage']} <= {'brute_force', 'login'}:
        blocking.append('src_ip')
    against.extend('Conflicting field: ' + key for key in blocking)
    identity = overlap(new, old, 'user') or overlap(new, old, 'src_ip')
    progression = same_target and identity and sequence
    repeated = (same_target and overlap(new, old, 'user') and overlap(new, old, 'src_ip')
                and new['stage'] == old['stage'] == 'brute_force'
                and new['ts'] is not None and old['ts'] is not None and abs(new['ts'] - old['ts']) <= 900)
    eligible = bool(time_ok and not blocking and (progression or lateral or
        ((session or process) and (sequence or new['stage'] == old['stage'] != 'unknown')) or repeated))
    for key in matches:
        evidence.append('Shared ' + key + ': ' + ', '.join(sorted(set(new[key]) & set(old[key])))[:230])
    if sequence:
        evidence.append('Attack sequence: ' + STAGE_NAMES[older['stage']] + ' -> ' + STAGE_NAMES[later['stage']])
    if process:
        evidence.append('Linked process or parent process identifier')
    if lateral:
        evidence.append('Confirmed pivot from the previous host to the next host')
    if repeated:
        evidence.append('Continuation of the same login attempt burst within 15 minutes')
    related = bool(time_ok and (overlap(new, old, 'hash') or overlap(new, old, 'domain') or
                               overlap(new, old, 'src_ip')))
    score = (10 if eligible else 0) + (3 if process or session or lateral else 0) + (2 if sequence else 0) + len(matches) - 3 * len(blocking)
    return {'eligible': eligible, 'related': related, 'score': score,
            'evidence': evidence, 'against': against, 'peer_alert_id': old['id']}


def candidates(conn, alert, limit=3):
    current = facts(alert)
    grouped = {}
    rows = conn.execute("SELECT case_id, analysis_json FROM processed_alerts WHERE case_id IS NOT NULL AND status IN ('case_created','case_merged','uncertain')").fetchall()
    for cid, raw in rows:
        previous = json.loads(raw or '{}').get('_alert')
        if not previous:
            continue
        f = facts(previous)
        if f['customer'] != current['customer']:
            continue
        grouped.setdefault(cid, []).append(f)
    result = []
    for cid, timeline in grouped.items():
        pairs = [pair_evidence(current, f) for f in timeline]
        useful = [p for p in pairs if p['evidence']]
        if not useful:
            continue
        best = max(useful, key=lambda p: p['score'])
        # A direct match to another concurrent session on this target is a hard ambiguity.
        rivals = [p for p in pairs if p['against'] and p['score'] >= best['score'] - 2]
        timeline.sort(key=lambda f: (f['ts'] is None, f['ts'] or 0, f['id']))
        result.append(dict(best, case_id=cid, timeline=timeline, rivals=rivals))
    result.sort(key=lambda c: (-c['score'], c['case_id']))
    for c in result[:limit]:
        c['candidate_overflow'] = len([x for x in result if x['eligible']]) > limit
    return result[:limit]


def decide(candidate_cases, ai, alert):
    decision = {'relation': 'uncertain', 'case_id': None, 'confidence': 0.0,
                'evidence': [], 'against': [], 'related_case_ids': []}
    if not ai or ai.get('_fallback'):
        decision['against'] = ['AI is unavailable or the response failed validation; analyst review is required']
        return decision
    strong = [c for c in candidate_cases if c['eligible']]
    if len(strong) > 1 or any(c.get('candidate_overflow') for c in candidate_cases):
        decision['against'] = ['Multiple eligible cases exist; automatic case selection is ambiguous']
        decision['related_case_ids'] = [c['case_id'] for c in strong]
        return decision
    response = ai.get('correlation') or {}
    chosen = next((c for c in candidate_cases if c['case_id'] == response.get('case_id')), None)
    refs = response.get('evidence_alert_ids', [])
    allowed_refs = ({e['id'] for e in chosen['timeline']} | {facts(alert)['id']}) if chosen else set()
    valid_refs = chosen and bool(refs) and all(i in allowed_refs for i in refs)
    if (chosen and chosen['eligible'] and response.get('relation') == 'same_attack'
            and response.get('confidence', 0) >= 0.8 and valid_refs
            and chosen['peer_alert_id'] in refs):
        decision.update(relation='same_attack', case_id=chosen['case_id'],
                        confidence=response['confidence'], evidence=chosen['evidence'], against=chosen['against'])
    elif strong:
        deterministic = strong[0]
        if response.get('relation') != 'same_attack' and deterministic['score'] >= 12 and not deterministic['against']:
            decision.update(relation='same_attack', case_id=deterministic['case_id'],
                            confidence=0.85, evidence=deterministic['evidence'],
                            against=['Merged by deterministic correlation because exactly one eligible attack chain matched and no contradictions were found'])
        else:
            decision.update(evidence=strong[0]['evidence'], against=['AI did not confirm a single attack chain with a verifiable event reference'])
    elif candidate_cases:
        related = [c for c in candidate_cases if c['related']]
        decision.update(relation='related' if related else 'uncertain',
                        related_case_ids=[c['case_id'] for c in related],
                        evidence=candidate_cases[0]['evidence'], against=candidate_cases[0]['against'])
    else:
        f = facts(alert)
        known = bool((f['dst_host'] or f['dst_ip']) and f['ts'] and f['stage'] != 'unknown')
        decision.update(relation='unrelated' if known else 'uncertain',
                        evidence=['No confirmed relationship found in processed history'],
                        against=[] if known else ['Insufficient event time, target, or event type data'])
    decision['ai_reason'] = str(response.get('reason', ''))[:700]
    return decision


def model_context(alert, cases):
    new = facts(alert)
    packed = []
    for c in cases:
        # Include nearest events and the anchor, preserving all competing case IDs.
        near = sorted(c['timeline'], key=lambda e: abs((e['ts'] or 0) - (new['ts'] or 0)))[:4]
        packed.append({'case_id': c['case_id'], 'eligible': c['eligible'],
                       'evidence': c['evidence'], 'against': c['against'],
                       'timeline': [compact_facts(e) for e in sorted(near, key=lambda e: e['ts'] or 0)],
                       'omitted_events': max(0, len(c['timeline']) - len(near))})
    result = (alert.get('alert_source_content') or {}).get('result', {})
    details = {k: v for k, v in result.items() if isinstance(v, (int, float, bool))}
    return {'new_alert': compact_facts(new), 'observations': details,
            'description': str(alert.get('alert_description') or '')[:450], 'candidates': packed}


def compact_facts(f):
    return {k: (v[:3] if isinstance(v, list) else v) for k, v in f.items() if v not in ([], None, '') and k != 'ts'}


def md(value, limit=600):
    text = html.escape(str(value or ''), quote=False).replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'([\\`*_{}\[\]()#+!|])', r'\\\1', text[:limit])


def english_or_legacy(value):
    text = str(value or '').strip()
    if re.search(r'[А-Яа-яЁё]', text):
        return 'Legacy AI hypothesis was produced before English-only formatting and is not shown in this summary.'
    return text or 'AI assessment is unavailable.'


def additions(alert, candidate):
    f = facts(alert)
    if not candidate:
        return ['Initial event for a separate investigation.']
    previous = candidate['timeline']
    out = []
    if f['stage'] not in {p['stage'] for p in previous}:
        out.append('New attack stage: ' + STAGE_NAMES[f['stage']] + '.')
    for key, label in [('dst_host', 'Target'), ('user', 'User account'), ('session', 'Session'),
                       ('process', 'Process'), ('domain', 'Domain'), ('hash', 'Hash')]:
        known = {v for p in previous for v in p.get(key, [])}
        novel = set(f[key]) - known
        if novel:
            out.append(label + ': ' + ', '.join(sorted(novel)) + '.')
    if f['ts'] is not None and any(p['ts'] is not None and f['ts'] < p['ts'] for p in previous):
        out.append('The event arrived late and was inserted according to its original event time.')
    return out or ['Another event from an already known stage; the specific details are listed below.']


def next_steps(stage):
    return {
        'brute_force': ['Validate the failed-login count, source, and account against authentication logs.',
                        'Check whether a successful login followed from the same source.'],
        'login': ['Identify the session ID and confirm whether the login was authorized by the account owner.',
                  'Review processes launched inside this session after login.'],
        'phishing': ['Review the message, sender, attachment, and clicked links.',
                     'Correlate attachment or link activity with endpoint process events.'],
        'execution': ['Collect the command line, parent process, and process identifier.',
                      'Correlate the process start with the login session and later network connections.'],
        'c2': ['Validate DNS, destination, and the process that initiated the connection.',
               'Measure connection periodicity and transferred data volume.'],
        'privilege': ['Validate the privilege change and tie it back to the originating session and process.'],
        'data_access': ['Identify which data was accessed, by which account, and through which process.'],
        'exfiltration': ['Validate data volume, destination, and content using available telemetry.'],
        'lateral': ['Confirm host-to-host activity using logs from both systems and the session identifier.'],
    }.get(stage, ['Clarify event time, source, target, and event type using primary logs.'])


def note(alert, analysis):
    f = facts(alert)
    d = analysis.get('_decision', {})
    names = {'same_attack': 'Added to the existing attack chain', 'related': 'Separate incident; possible shared campaign',
             'unrelated': 'New separate incident', 'uncertain': 'Relationship requires analyst review'}
    result = (alert.get('alert_source_content') or {}).get('result', {})
    lines = [f"### Alert #{f['id']}: {STAGE_NAMES[f['stage']]}", '',
             '| Field | Value |', '| --- | --- |',
             f"| Event time | {md(f['time']) or 'Not provided'} |",
             f"| Target | {md(', '.join(f['dst_host'] + f['dst_ip'])) or 'Not provided'} |",
             f"| Source | {md(', '.join(f['src_host'] + f['src_ip'])) or 'Not provided'} |",
             f"| User account | {md(', '.join(f['user'])) or 'Not provided'} |", '',
             '**Observed facts**', '']
    labels = {'failed_count': 'Failed logins', 'success_after_failures': 'Success after failures',
              'process': 'Process', 'parent_process': 'Parent process', 'command_line': 'Command line',
              'domain': 'Domain', 'session_id': 'Session', 'sha256': 'SHA-256', 'bytes_out': 'Bytes sent'}
    observed = [f'- {labels.get(k, md(k))}: {md(v)}' for k, v in result.items()
                if isinstance(v, (str, int, float, bool)) and k not in {'batch', 'user', 'src_ip', 'dest_host', 'event_type', '_time'}]
    lines += observed[:12] or [f"- Source event title: {md(f['title'])}."]
    lines += ['', '**New information**', '', *('- ' + md(e) for e in analysis.get('_new_information', ['Historical event; relationship was determined by an earlier worker version.']))]
    lines += ['', '**Case relationship**', '', '- ' + names.get(d.get('relation'), names['uncertain']) + '.',
              *('- ' + md(e) for e in d.get('evidence', [])[:5]),
              *('- Needs review: ' + md(e) for e in d.get('against', [])[:4])]
    if d.get('related_case_ids'):
        lines += ['- Related cases, not merged automatically: ' + ', '.join(f'[#{cid}](/case?cid={cid})' for cid in d['related_case_ids'])]
    lines += ['', '**AI assessment, hypothesis**', '', md(english_or_legacy(analysis.get('summary'))),
              '', '**Recommended next actions**', '']
    lines += ['- ' + md(a) for a in next_steps(f['stage'])]
    lines += ['', f"[Source alert #{f['id']} and full JSON](/alerts?alert_ids={f['id']})", '']
    return '\n'.join(lines)


def overview(rows):
    ordered = sorted(rows, key=lambda r: (facts(r['_alert'])['ts'] is None, facts(r['_alert'])['ts'] or 0))
    lines = ['## Investigation timeline', '', f'Events in this chain: **{len(ordered)}**. Times below are shown in UTC.', '',
             '| Event time | Alert | Stage | Target / user |', '| --- | --- | --- | --- |']
    for r in ordered:
        f = facts(r['_alert'])
        when = datetime.fromtimestamp(f['ts'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if f['ts'] else 'Not provided'
        target = ', '.join(f['dst_host'] or f['dst_ip']) + ' / ' + ', '.join(f['user'])
        lines.append(f"| {when} | [#{f['id']}](/alerts?alert_ids={f['id']}) | {STAGE_NAMES[f['stage']]} | {md(target)} |")
    lines += ['', '## Event facts and correlation decisions', '']
    for r in ordered:
        lines += [note(r['_alert'], r), '---', '']
    return '\n'.join(lines)

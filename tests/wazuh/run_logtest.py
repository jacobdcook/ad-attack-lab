import json, sys
sys.path.insert(0, '/var/ossec/framework/scripts')
from wazuh_logtest import WazuhLogtest
for path in sys.argv[1:]:
    w, tok = WazuhLogtest(), None
    print('== session', path)
    for line in open(path):
        e = json.loads(line); s, d = e['win']['system'], e['win']['eventdata']
        out = w.process_log(line.strip(), tok)['output']; tok = w.last_token
        r = out.get('rule', {})
        who = d.get('targetUserName') if s['eventID'] != '10' else d.get('sourceImage', '').split('\\')[-1]
        extra = d.get('serviceName') or d.get('grantedAccess') or d.get('subjectUserName') or ''
        print('\t'.join([s['eventID'], s['eventRecordID'], who or '', extra, out.get('decoder', {}).get('name', ''), r.get('id', '-'), str(r.get('level', '')), r.get('description', '')]))
    w.remove_session(tok)

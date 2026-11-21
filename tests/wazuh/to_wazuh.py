import json, re, sys
import xml.etree.ElementTree as ET
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
SEV = {'0': 'AUDIT_SUCCESS', '4': 'INFORMATION'}
def lc(n): return n[0].lower() + n[1:]
def conv(x):
    r = ET.fromstring(x)
    s, sysd = r.find(NS + 'System'), {}
    p = s.find(NS + 'Provider')
    sysd['providerName'] = p.get('Name')
    if p.get('Guid'): sysd['providerGuid'] = p.get('Guid')
    for tag in ['EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords', 'Channel', 'Computer']:
        e = s.find(NS + tag)
        if e is not None and e.text: sysd[lc(tag) if tag != 'EventID' else 'eventID'] = e.text
    sysd['systemTime'] = s.find(NS + 'TimeCreated').get('SystemTime')
    sysd['eventRecordID'] = s.find(NS + 'EventRecordID').text
    ex = s.find(NS + 'Execution')
    sysd['processID'], sysd['threadID'] = ex.get('ProcessID'), ex.get('ThreadID')
    sysd['severityValue'] = SEV.get(sysd.get('level', ''), 'INFORMATION')
    ed = {lc(d.get('Name')): (d.text or '').strip() for d in r.find(NS + 'EventData') if d.get('Name')}
    return {'win': {'system': sysd, 'eventdata': ed}}
src = open(sys.argv[1], encoding='utf-8-sig').read()
for x in re.findall(r'<Event .*?</Event>', src, re.S):
    print(json.dumps(conv(x), separators=(',', ':')))

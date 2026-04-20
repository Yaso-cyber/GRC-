from grc_tool.database import Database
from grc_tool.control_manager import ControlManager

db = Database(); db.initialize()
cm = ControlManager(db)

frameworks = ['NIST CSF', 'NIST AI RMF', 'ISO 27001', 'SOC 2', 'CSA CCM']
for fw in frameworks:
    rows = db.fetchall("SELECT control_id FROM controls WHERE framework=? ORDER BY id LIMIT 3", (fw,))
    ids = [r['control_id'] for r in rows]
    if len(ids) >= 1:
        cm.update_control_status(ids[0], 'Implemented', owner='Yasmin', actor='Yasmin')
        print(f'{fw}: {ids[0]} -> Implemented')
    if len(ids) >= 2:
        cm.update_control_status(ids[1], 'Implemented', owner='Yasmin', actor='Yasmin')
        print(f'{fw}: {ids[1]} -> Implemented')
    if len(ids) >= 3:
        cm.update_control_status(ids[2], 'Partially Implemented', owner='Yasmin', actor='Yasmin')
        print(f'{fw}: {ids[2]} -> Partially Implemented')
from grc_tool.database import Database
from grc_tool.control_manager import ControlManager

db = Database(); db.initialize()
cm = ControlManager(db)

# Check what control IDs actually exist
rows = db.fetchall("SELECT control_id, framework FROM controls ORDER BY framework, control_id LIMIT 10")
print("Sample control IDs in DB:")
for r in rows:
    print(f"  {r['framework']}: {r['control_id']}")

updates = [
    ('CSF-GV-1', 'Implemented'),
    ('CSF-ID-1', 'Implemented'),
    ('CSF-PR-1', 'Partial'),
    ('ISO-5.1',  'Implemented'),
    ('ISO-5.10', 'Partial'),
    ('SOC2-CC1.1','Implemented'),
    ('AIRMF-GV-1','Partial'),
    ('CCM-IAM-01','Implemented'),
]
for cid, st in updates:
    ok = cm.update_control_status(cid, st, owner='Yasmin', actor='Yasmin')
    status = 'ok' if ok else 'NOT FOUND'
    print(f'{cid} -> {st}: {status}')

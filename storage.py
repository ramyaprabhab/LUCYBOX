
import sqlite3, json, io, csv
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
DEFAULT_DB = "events.db"
SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,
  source TEXT,
  severity TEXT,
  event_type TEXT,
  raw_json TEXT,
  signature TEXT,
  src_ip TEXT,
  dest_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  status TEXT DEFAULT 'open',
  tags TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TEXT,
  updated_at TEXT
);
'''
def get_conn(path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
def init_db(path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur = conn.cursor(); cur.executescript(SCHEMA); conn.commit(); conn.close()
def insert_event(event:Dict[str,Any], path:Optional[str]=None) -> int:
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur = conn.cursor()
    cur.execute('''INSERT INTO events (ts,source,severity,event_type,raw_json,signature,src_ip,dest_ip) VALUES (?,?,?,?,?,?,?,?)''',
                (event.get('timestamp'), event.get('source'), event.get('severity'), event.get('event_type'),
                 json.dumps(event.get('raw_json')), event.get('signature'), event.get('src_ip'), event.get('dest_ip')))
    rowid = cur.lastrowid; conn.commit(); conn.close(); create_alert_for_event(rowid, path); return rowid
def query_events(limit:int=100, search:Optional[str]=None, path:Optional[str]=None) -> List[Dict[str,Any]]:
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur = conn.cursor()
    if search:
        q = f"%{search}%"; cur.execute("SELECT * FROM events WHERE raw_json LIKE ? OR signature LIKE ? ORDER BY id DESC LIMIT ?", (q,q,limit))
    else:
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows
def get_event(eid:int,path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur=conn.cursor(); cur.execute("SELECT * FROM events WHERE id = ?", (eid,)); r=cur.fetchone(); conn.close(); return dict(r) if r else None
def purge_old_events(days:int=30,path:Optional[str]=None) -> int:
    if not path: path = DEFAULT_DB
    cutoff = datetime.utcnow() - timedelta(days=days); cutoff_iso = cutoff.isoformat() + "Z"
    conn = get_conn(path); cur = conn.cursor(); cur.execute("DELETE FROM events WHERE ts < ?", (cutoff_iso,)); removed = cur.rowcount; conn.commit(); conn.close(); return removed
def create_alert_for_event(event_id:int,path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    now = datetime.utcnow().isoformat() + "Z"; conn = get_conn(path); cur=conn.cursor(); cur.execute("INSERT INTO alerts (event_id,status,tags,notes,created_at,updated_at) VALUES (?,?,?,?,?,?)", (event_id,"open","","",now,now)); conn.commit(); conn.close()
def list_alerts(limit:int=200,status:Optional[str]=None,tag:Optional[str]=None,path:Optional[str]=None):
    if not path: path = DEFAULT_DB; conn = get_conn(path); cur=conn.cursor(); qparts=[]; params=[]
    if status: qparts.append("status = ?"); params.append(status)
    if tag: qparts.append("tags LIKE ?"); params.append(f"%{tag}%")
    where = ("WHERE " + " AND ".join(qparts)) if qparts else ""
    sql = f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?"; params.append(limit)
    cur.execute(sql, params); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return rows
def top_talkers(limit:int=10,path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur = conn.cursor(); cur.execute("SELECT src_ip, COUNT(*) as cnt FROM events WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY cnt DESC LIMIT ?", (limit,)); rows=[dict(r) for r in cur.fetchall()]; conn.close(); return rows
def events_time_buckets(bucket_minutes:int=60,hours:int=24,path:Optional[str]=None):
    if not path: path = DEFAULT_DB
    conn = get_conn(path); cur = conn.cursor(); cur.execute("SELECT ts FROM events WHERE ts IS NOT NULL"); rows=cur.fetchall(); conn.close()
    from datetime import datetime,timedelta
    now = datetime.utcnow(); buckets={}; total_minutes = hours*60; n_buckets = total_minutes//bucket_minutes
    for i in range(n_buckets):
        bucket_start = now - timedelta(minutes=bucket_minutes * (n_buckets - i))
        label = bucket_start.strftime("%Y-%m-%d %H:%M"); buckets[label]=0
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["ts"].replace("Z",""))
        except Exception:
            continue
        diff = now - ts
        if diff.total_seconds() > hours*3600: continue
        minutes_back = int(diff.total_seconds()//60)
        bucket_index = (hours*60 - minutes_back - 1)//bucket_minutes
        if bucket_index < 0: continue
        bucket_start = now - timedelta(minutes=bucket_minutes * (n_buckets - bucket_index))
        label = bucket_start.strftime("%Y-%m-%d %H:%M")
        if label in buckets: buckets[label]+=1
    return [{"bucket":k,"count":v} for k,v in buckets.items()]

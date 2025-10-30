
import threading, time, json, logging
from parser import parse_eve_line
import storage
LOG = logging.getLogger("collectors")
_thread=None; _stop_event=threading.Event(); _current_mode=None
SAMPLE=[{'timestamp':'2025-10-08T21:00:00Z','event_type':'alert','alert':{'signature':'Test Alert','severity':2},'src_ip':'10.0.0.5'},{'timestamp':'2025-10-08T21:00:03Z','event_type':'http','src_ip':'10.0.0.6','http':{'hostname':'example.com'}}]
def _sim(sample, interval):
    i=0
    while not _stop_event.is_set():
        ev = parse_eve_line(sample[i%len(sample)]); storage.insert_event(ev); i+=1; time.sleep(interval)
def start_simulator(interval=2.0):
    global _thread,_stop_event,_current_mode; stop(); _stop_event.clear(); _current_mode='sim'; _thread=threading.Thread(target=_sim,args=(SAMPLE,interval),daemon=True); _thread.start(); return _thread
def stop():
    global _thread,_stop_event,_current_mode
    if _thread and _thread.is_alive(): _stop_event.set(); _thread.join(timeout=1.0)
    _thread=None; _stop_event.clear(); _current_mode=None
def status(): return {'running': _thread is not None and _thread.is_alive(), 'mode': _current_mode}

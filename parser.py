
import json
from datetime import datetime
def parse_eve_line(raw):
    if isinstance(raw, str):
        try:
            j = json.loads(raw)
        except Exception:
            return {"timestamp": datetime.utcnow().isoformat() + "Z","source":"unknown","severity":"INFO","event_type":"raw","raw_json":raw,"signature":"","src_ip":None,"dest_ip":None,"metadata":{}}
    elif isinstance(raw, dict):
        j = raw
    else:
        j = {}
    ts = j.get("timestamp") or j.get("ts") or datetime.utcnow().isoformat() + "Z"
    event_type = j.get("event_type") or j.get("type") or "unknown"
    source = j.get("host") or j.get("sensor") or j.get("source") or j.get("src_ip") or "unknown"
    severity = "INFO"
    if event_type == "alert":
        alert = j.get("alert", {})
        sev = alert.get("severity") or alert.get("level")
        severity = str(sev) if sev is not None else "WARN"
    sig = ""
    if isinstance(j.get("alert"), dict):
        sig = j["alert"].get("signature","") or j["alert"].get("signature_id","") or ""
    src = j.get("src_ip") or j.get("source_ip") or j.get("src")
    dst = j.get("dest_ip") or j.get("destination_ip") or j.get("dst")
    return {"timestamp":ts,"source":source,"severity":severity,"event_type":event_type,"raw_json":j,"signature":sig,"src_ip":src,"dest_ip":dst,"metadata":{}}

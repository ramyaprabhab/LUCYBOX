
import os, logging, json
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, Response, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import storage, collectors, parser, pcap_util, config as cfg
cfg.load_config()
LOG = logging.getLogger("python_evebox"); logging.basicConfig(level=logging.DEBUG if cfg.CONFIG["server"].get("debug") else logging.INFO)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads"); os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {"json","pcap","pcapng","pdml","xml"}
def allowed_filename(fn): return "." in fn and fn.rsplit(".",1)[1].lower() in ALLOWED_EXT
app = Flask(__name__, static_folder="static", template_folder="templates"); app.secret_key="change-me"
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = cfg.CONFIG.get("admin", {}).get("token"); provided = request.headers.get("X-Admin-Token") or request.args.get("token")
        if token and provided == token: return f(*args, **kwargs)
        flash("Admin token required"); return redirect(url_for("index"))
    return wrapper
@app.before_first_request
def startup():
    storage.init_db(cfg.CONFIG["storage"].get("db_path")); collectors.start_simulator()
@app.route("/")
def index():
    q = request.args.get("q"); events = storage.query_events(limit=200, search=q)
    buckets = storage.events_time_buckets(bucket_minutes=60, hours=24); top = storage.top_talkers(limit=10)
    return render_template("index.html", events=events, q=q, buckets=buckets, top=top)
@app.route("/admin")
@require_admin
def admin(): stat = collectors.status(); return render_template("admin.html", collectors=stat, storage=cfg.CONFIG.get("storage",{}))
@app.route("/admin/import", methods=["GET","POST"])
@require_admin
def admin_import():
    if request.method == "GET": return render_template("import.html")
    file = request.files.get("file"); 
    if not file: flash("No file uploaded"); return redirect(url_for("admin"))
    filename = secure_filename(file.filename); save_path = os.path.join(UPLOAD_FOLDER, filename); file.save(save_path)
    ext = filename.rsplit(".",1)[-1].lower(); inserted=0
    try:
        if ext in ("pcap","pcapng"):
            for i, pkt in enumerate(pcap_util.stream_pcap(save_path)):
                summ = pcap_util.packet_summary(pkt)
                ev = {"timestamp": None, "source": summ.get("src") or "pcap", "event_type":"packet", "raw_json": summ, "signature": summ.get("proto"), "src_ip": summ.get("src"), "dest_ip": summ.get("dst")}
                storage.insert_event(ev); inserted += 1
        elif ext == "json":
            with open(save_path, "r") as fh: data = json.load(fh)
            if isinstance(data, list):
                for pkt in data:
                    layers = pkt.get("_source", {}).get("layers", {}); ip4 = layers.get("ip"); src=None; dst=None; proto=None
                    if ip4: src = ip4.get("ip.src"); dst = ip4.get("ip.dst")
                    if "tcp" in layers: proto="TCP"
                    elif "udp" in layers: proto="UDP"
                    ts = pkt.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.time_epoch") or None
                    ev = {"timestamp": ts, "source": src or "tshark", "event_type":"packet", "raw_json": pkt, "signature": proto or "unknown", "src_ip": src, "dest_ip": dst}
                    storage.insert_event(ev); inserted += 1
            elif isinstance(data, dict):
                ev = parser.parse_eve_line(data); storage.insert_event(ev); inserted = 1
        elif ext in ("pdml","xml"):
            import xml.etree.ElementTree as ET
            tree = ET.parse(save_path); root = tree.getroot()
            for pkt in root.findall(".//packet"):
                ts=None; src=None; dst=None; proto=None
                for field in pkt.findall(".//field"):
                    name = field.get("name","")
                    if name == "ip.src": src = field.get("show")
                    elif name == "ip.dst": dst = field.get("show")
                    elif name == "frame.time_epoch": ts = field.get("show")
                    elif name == "ip.proto" and not proto: proto = field.get("show")
                ev = {"timestamp": ts, "source": src or "pdml", "event_type":"packet", "raw_json": None, "signature": proto or "unknown", "src_ip": src, "dest_ip": dst}
                storage.insert_event(ev); inserted += 1
        else:
            with open(save_path, "r") as fh:
                for line in fh:
                    line=line.strip()
                    if not line: continue
                    try:
                        obj = json.loads(line); ev = parser.parse_eve_line(obj); storage.insert_event(ev); inserted += 1
                    except Exception:
                        continue
        flash(f"Imported {inserted} records from {filename}")
    except Exception as e:
        flash("Import error: "+str(e))
    return redirect(url_for("admin"))
@app.route("/analysis")
def analysis_ui():
    top = storage.top_talkers(limit=20); buckets = storage.events_time_buckets(bucket_minutes=60, hours=24)
    conn = storage.get_conn(cfg.CONFIG["storage"].get("db_path")); cur = conn.cursor(); cur.execute("SELECT signature, COUNT(*) as cnt FROM events GROUP BY signature ORDER BY cnt DESC LIMIT 50"); proto_rows=[dict(r) for r in cur.fetchall()]; conn.close()
    return render_template("analysis.html", top=top, buckets=buckets, proto_rows=proto_rows)
@app.route("/api/pcap/analyze", methods=["POST"])
def api_pcap_analyze():
    file = request.files.get("pcap"); 
    if not file: return jsonify({"error":"no file"}), 400
    filename = secure_filename(file.filename); save_path = os.path.join(UPLOAD_FOLDER, filename); file.save(save_path)
    try:
        cnt = pcap_util.count_packets(save_path); summary=[] 
        for i,pkt in enumerate(pcap_util.stream_pcap(save_path)):
            if i>=50: break
            summary.append(pcap_util.packet_summary(pkt))
        return jsonify({"count":cnt,"summary":summary})
    except Exception as e:
        return jsonify({"error":str(e)}), 500
@app.route("/api/events", methods=["GET"])
def api_events():
    limit = int(request.args.get("limit","200")); q = request.args.get("q"); return jsonify(storage.query_events(limit=limit, search=q))
@app.route("/api/events", methods=["POST"])
def api_ingest():
    ev = request.get_json(); 
    if not ev: return jsonify({"error":"invalid json"}), 400
    norm = parser.parse_eve_line(ev); storage.insert_event(norm); return jsonify({"status":"ok"}), 201
if __name__ == "__main__":
    app.run(host=cfg.CONFIG["server"].get("host","127.0.0.1"), port=cfg.CONFIG["server"].get("port",5000), debug=cfg.CONFIG["server"].get("debug", True))

import mysql.connector
import getpass
import queue
import threading
import time
import json
from typing import Any, Dict, Optional
from flask import Flask, jsonify, Response
from flask_cors import CORS
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# Database connection
password = getpass.getpass("Enter MySQL password: ")
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password=password,
    database='packetdb'  
)
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS packets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(15),
    dst_ip VARCHAR(15),
    protocol VARCHAR(10),
    src_port INT,
    dst_port INT
)
''')
conn.commit()

_packet_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
_sniffer_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()

app = Flask(__name__)
CORS(app)

def _format_packet(packet: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "timestamp": time.time(),
        "protocol": "unknown",
        "src": None,
        "dst": None,
        "src_port": None,
        "dst_port": None,
    }

    if packet.haslayer(IP):
        result["src"] = packet[IP].src
        result["dst"] = packet[IP].dst

        if packet.haslayer(TCP):
            result["protocol"] = "TCP"
            result["src_port"] = packet[TCP].sport
            result["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            result["protocol"] = "UDP"
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport
        else:
            result["protocol"] = "Other"

    return result

def process_packet(packet):
    pkt = _format_packet(packet)
    _packet_queue.put(pkt)
    
    # Also insert into database
    try:
        cursor.execute('''
        INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port)
        VALUES (%s, %s, %s, %s, %s)
        ''', (pkt['src'], pkt['dst'], pkt['protocol'], pkt['src_port'], pkt['dst_port']))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        conn.rollback()

def _packet_callback(packet: Any) -> None:
    process_packet(packet)

def start_capture(interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> None:
    global _sniffer_thread

    if _sniffer_thread and _sniffer_thread.is_alive():
        return

    _stop_event.clear()

    def _sniff():
        while not _stop_event.is_set():
            sniff(
                prn=_packet_callback,
                store=False,
                timeout=1,
                iface=interface,
                filter=bpf_filter,
            )

    _sniffer_thread = threading.Thread(target=_sniff, daemon=True, name="packet-sniffer")
    _sniffer_thread.start()

def stop_capture() -> None:
    _stop_event.set()
    if _sniffer_thread:
        _sniffer_thread.join(timeout=1)

def get_packet(timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    try:
        return _packet_queue.get(timeout=timeout)
    except queue.Empty:
        return None

def is_running() -> bool:
    return bool(_sniffer_thread and _sniffer_thread.is_alive())

@app.route("/start", methods=["POST"])
def start():
    start_capture()
    return jsonify({"status": "started", "running": True})

@app.route("/stop", methods=["POST"])
def stop():
    stop_capture()
    return jsonify({"status": "stopped", "running": False})

@app.route("/status")
def status():
    return jsonify({"running": is_running()})

@app.route("/packets")
def get_packets():
    try:
        cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 100")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        result = [dict(zip(columns, row)) for row in rows]
        return jsonify(result)
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

def event_stream():
    while True:
        pkt = get_packet(timeout=1.0)
        if pkt is not None:
            yield f"data: {json.dumps(pkt)}\n\n"
        else:
            yield ": keep-alive\n\n"

@app.route("/stream")
def stream():
    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True)
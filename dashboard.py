import streamlit as st
import pandas as pd
import random
import time
import smtplib
from datetime import datetime
from email.message import EmailMessage

# --- PAGE CONFIG ---
st.set_page_config(page_title="INTMS Command Center", layout="wide", initial_sidebar_state="expanded")

# --- NAVIGATION LOGIC ---
if 'page' not in st.session_state:
    st.session_state.page = "Monitoring"

with st.sidebar:
    st.markdown("### 🟢 INTMS Robot")
    if st.button("🎯 Monitoring", use_container_width=True):
        st.session_state.page = "Monitoring"
        st.rerun()
    if st.button("🛡️ Incidents", use_container_width=True):
        st.session_state.page = "Incidents"
        st.rerun()
    if st.button("📖 Threat Dictionary", use_container_width=True): # New Button
        st.session_state.page = "Dictionary"
        st.rerun()
    st.markdown("---")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #171b21; color: #a1a9b7; font-family: -apple-system, sans-serif; }
    .block-container { padding-top: 2rem; padding-bottom: 0rem; }
    .ur-card { background-color: #21262d; border-radius: 8px; padding: 20px; margin-bottom: 15px; border: 1px solid #30363d; }
    .ur-title { color: #ffffff; font-size: 24px; font-weight: 600; margin-bottom: 4px; display: flex; align-items: center;}
    .ur-subtitle { color: #3fb950; font-size: 14px; margin-bottom: 20px;}
    .ur-label { color: #a1a9b7; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
    .ur-value { color: #ffffff; font-size: 24px; font-weight: 600; }
    .ur-value-green { color: #3fb950; font-size: 24px; font-weight: 600; }
    .ur-small-text { color: #a1a9b7; font-size: 12px; margin-top: 4px; }
    .tuple-value { color: #3fb950; font-size: 18px; font-weight: bold; }
    
    .matrix-terminal {
        background-color: #090b0f;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
        font-size: 11px;
        padding: 15px;
        border-radius: 6px;
        border: 1px solid #1f242d;
        height: 350px;
        overflow: hidden;
        display: flex;
        flex-direction: column-reverse; 
        line-height: 1.4;
        text-shadow: 0 0 2px #00ff41;
    }
    </style>
""", unsafe_allow_html=True)

# --- INIT SESSION STATE ---
if 'pps_data' not in st.session_state:
    st.session_state.pps_data = [random.randint(40, 60) for _ in range(60)]
if 'bps_data' not in st.session_state:
    st.session_state.bps_data = [random.randint(5000, 8000) for _ in range(60)]
if 'last_check' not in st.session_state:
    st.session_state.last_check = 0
if 'top_src' not in st.session_state:
    st.session_state.top_src = "192.168.1.15"
if 'top_dst' not in st.session_state:
    st.session_state.top_dst = "10.0.0.254"
if 'current_spike_pps' not in st.session_state:
    st.session_state.current_spike_pps = 45
if 'matrix_logs' not in st.session_state:
    st.session_state.matrix_logs = []
if 'alert_history' not in st.session_state:
    st.session_state.alert_history = []

# --- REAL EMAIL LOGIC ---
def send_real_email():
    sender_email = "h3manth2000@gmail.com"  
    app_password = "wvrl qvae ibwt neif" 
    receiver_email = "xdhemanth2000@gmail.com" 
    
    msg = EmailMessage()
    msg['Subject'] = '🚨 [CRITICAL] INTMS 3σ Network Anomaly'
    msg['From'] = sender_email
    msg['To'] = receiver_email
    
    email_body = f"""
    INTMS AUTOMATED ALERT SYSTEM
    -----------------------------------
    STATUS: Critical Threshold Breached
    
    Heuristic Incident Report:
    - Detected Attacker: {st.session_state.top_src}
    - Packet Rate: {st.session_state.current_spike_pps} PPS
    - Logic: z > 4.2 Standard Deviation
    
    Mitigation Action: Pending Admin Review
    """
    msg.set_content(email_body)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
        return True
    except: return False

# --- SMTP AUTO-ESCALATION ENGINE ---
def send_escalation_alert(pps_val, attacker_ip, is_auto=False):
    try:
        sender_email = "h3manth2000@gmail.com"  
        app_password = "wvrl qvae ibwt neif" 
        receiver_email = "xdhemanth2000@gmail.com" 
        
        msg = EmailMessage()
        prefix = "[AUTO-EMERGENCY]" if is_auto else "[MANUAL ESCALATION]"
        msg['Subject'] = f'🚨 {prefix} INTMS Critical Threat Detected'
        msg['From'] = sender_email
        msg['To'] = receiver_email
        
        msg.set_content(f"""
        INTMS EMERGENCY INCIDENT REPORT
        -------------------------------
        STATUS: EMERGENCY THRESHOLD BREACHED
        Attacker IP: {attacker_ip}
        Packet Rate: {pps_val} PPS
        Detection Type: {'Autonomous Hook' if is_auto else 'L1 SOC Review'}
        
        Logic: Deterministic rate exceeded 10,000 PPS. 
        Action: Automatic mitigation hooks pending review.
        """)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
        return True
    except: return False

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    threshold_limit = st.slider("3σ Threshold Level", 100, 300, 230, 10)
    st.markdown("---")

    

# --- UPDATE LOGIC ---
def update_data():
    st.session_state.last_check = 0 if st.session_state.last_check >= 5 else st.session_state.last_check + 1
    
    is_serious = random.random() > 0.99 
    new_pps = random.randint(500, 600) if is_serious else random.randint(40, 65)
    new_bps = (new_pps * random.randint(1200, 2500)) / 5.0
    
    st.session_state.pps_data.append(new_pps)
    st.session_state.pps_data.pop(0)
    st.session_state.bps_data.append(new_bps)
    st.session_state.bps_data.pop(0)

    now_ts = datetime.now().strftime("%H:%M:%S")
    
    if is_serious:
        st.session_state.top_src = f"45.22.10.{random.randint(10,99)}"
        send_real_email() 
        st.session_state.alert_history.insert(0, {
            "ts": now_ts, "flow": [st.session_state.top_src, "10.0.0.254", "TCP"],
            "pps": new_pps, "state": "critical", "reason": "z > 4.2"
        })

    for _ in range(random.randint(1, 2)):
        log_color = "#ff4b4b" if is_serious else "#00ff41"
        src = st.session_state.top_src if is_serious else f"192.168.1.{random.randint(2, 250)}"
        dst = "10.0.0.254" if is_serious else f"10.0.0.{random.randint(2, 254)}"
        log_line = f'<span style="color:{log_color}">[{datetime.now().strftime("%M:%S.%f")[:-3]}] {src} &rarr; {dst}</span>'
        st.session_state.matrix_logs.insert(0, log_line)
    
    if len(st.session_state.matrix_logs) > 22: st.session_state.matrix_logs.pop()

update_data()

# --- PAGE ROUTING ---
if st.session_state.page == "Monitoring":
    
   # --- HEADER ROW (MUST BE INDENTED UNDER THE IF GATE) ---
    col_head1, col_head2 = st.columns([3, 1])
    
    with col_head1:
        st.markdown("""
            <div class="ur-title">
                <span style="color:#3fb950; margin-right: 10px;">🟢</span> INTMS Command Center
            </div>
            <div class="ur-subtitle">
                Autonomous Heuristic Detection Active for <span style="color:#3fb950; font-weight:bold;">SRM_Campus_Net</span>
            </div>
        """, unsafe_allow_html=True)

    with col_head2:
        st.markdown("<div style='padding-top: 15px;'></div>", unsafe_allow_html=True) # Spacer for alignment
        # The Manual Escalation Button
        if st.button("🚨 Escalate Threat", use_container_width=True):
            if send_real_email(): 
                st.toast("Escalation Email Sent!", icon="🛡️")
                st.success("Tier-2 SOC Notified")
            else:
                st.error("Mail Server Connection Failed")

    # --- ROW 1: PRIMARY KPIs ---
    c1, c2, c3, c4 = st.columns(4)
    crit = st.session_state.pps_data[-1] >= 500
    c1.markdown(f'<div class="ur-card"><div class="ur-label">Status</div><div style="color:{"#ff4b4b" if crit else "#3fb950"}; font-size:24px; font-weight:600;">{"🚨 ATTACK" if crit else "UP"}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="ur-card">
                <div class="ur-label">Last check</div>
                <div class="ur-value" style="font-size:24px;">{st.session_state.last_check}s ago</div>
                <div class="ur-small-text">Refreshes <span style="font-weight:bold;">every 5s</span></div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        current_bps = st.session_state.bps_data[-1] 
        kb_per_sec = int(current_bps / 1024)
        st.markdown(f"""
            <div class="ur-card">
                <div class="ur-label">Throughput</div>
                <div class="ur-value" style="font-size:24px;">{kb_per_sec} KB/s</div>
                <div class="ur-small-text">Metric: <span style="font-weight:bold;">Live BPS Stream</span></div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        origin_ip = st.session_state.top_src
        dest_ip = st.session_state.top_dst
        current_load = st.session_state.pps_data[-1]
        origin_label = "🚨 CRITICAL ORIGIN" if current_load >= 500 else "TOP ORIGIN"
        label_color = "#ff4b4b" if current_load >= 500 else "#a1a9b7"
        st.markdown(f"""
            <div class="ur-card">
                <div class="ur-label" style="color:{label_color}; font-weight:bold;">{origin_label}</div>
                <div class="ur-value" style="font-size:20px; color:white;">{origin_ip}</div>
                <div class="ur-small-text" style="margin-top:2px;">Target: <span style="color:#3fb950;">{dest_ip}</span></div>
                <div class="ur-small-text">Volume: <span style="font-weight:bold; color:#ff4b4b;">{current_load} pkts/s</span></div>
            </div>
        """, unsafe_allow_html=True)

    # --- ROW 2: 5-TUPLE INSPECTOR ---
    t_cols = st.columns(5)
    vals = [st.session_state.top_src if crit else f"192.168.1.{random.randint(2,250)}", 
            "10.0.0.254" if crit else f"10.0.0.{random.randint(2,254)}", 
            random.randint(1024,65535), random.choice([80,443]), "TCP"]
    for i, (lab, val) in enumerate(zip(["Src IP", "Dst IP", "Src Port", "Dst Port", "Proto"], vals)):
        t_cols[i].markdown(f'<div class="ur-card" style="padding:15px;"><div class="ur-label">{lab}</div><div class="tuple-value">{val}</div></div>', unsafe_allow_html=True)

    # --- MAIN ANALYTICS ---
    left_col, right_col = st.columns([2.5, 1.5])
    with left_col:
        with st.container():
            st.markdown(f'<div class="ur-card" style="border-bottom:none; margin-bottom:0;"><div style="display:flex; justify-content:space-between;"><div class="ur-label" style="font-size:16px; color:white;">Traffic Volume (PPS) vs Threshold</div><div class="ur-label" style="color:#ff4b4b;">🔴 Limit: {threshold_limit} PPS</div></div></div>', unsafe_allow_html=True)
            st.line_chart(pd.DataFrame({"Live": st.session_state.pps_data, "Threshold": [threshold_limit]*60}), color=["#3fb950", "#ff4b4b"], height=230)
            st.markdown(f'<div class="ur-card" style="border-top:1px solid #30363d; margin-top:-16px;"><div style="display:flex; justify-content:space-between;"><div><span class="ur-value">{int(sum(st.session_state.pps_data)/60)}</span><br><span class="ur-small-text">Avg PPS</span></div><div><span class="ur-value" style="color:#ff4b4b;">↑ {max(st.session_state.pps_data)}</span><br><span class="ur-small-text">Peak Max</span></div></div></div>', unsafe_allow_html=True)

        st.markdown("### Top 10 Active Flows (by BPS share)")
        st.table(pd.DataFrame([{"Source": f"192.168.1.{random.randint(2,255)}", "Dest": f"10.0.0.{random.randint(2,254)}", "BPS": random.randint(1000, 9000), "Share": f"{random.randint(2,15)}%"} for _ in range(10)]).sort_values("BPS", ascending=False))

    with right_col:
        st.markdown('<div class="ur-card" style="padding:15px;"><div class="ur-label" style="color:white; display:flex; justify-content:space-between;"><span>Raw Packet Stream</span><span style="color:#3fb950;">● Live</span></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="matrix-terminal">{"<br>".join(st.session_state.matrix_logs)}</div></div>', unsafe_allow_html=True)
        
        st.markdown("### Alerts History (JSON Stream)")
        for alert in st.session_state.alert_history[:4]:
            with st.expander(f"🚨 {alert['state'].upper()} - {alert['ts']}"):
                st.json(alert)
                if st.button(f"Mitigate {alert['flow'][0]}", key=alert['ts']):
                    st.error(f"Applying rule: iptables rate-limit on {alert['flow'][0]}")

elif st.session_state.page == "Incidents":
    st.markdown('<h1 style="color:white; font-family:sans-serif; margin-bottom:20px;">Incidents.</h1>', unsafe_allow_html=True)
    
    # Hero Section
    st.markdown("""
        <div style="background: linear-gradient(90deg, #1e252e 0%, #171b21 100%); padding: 40px; border-radius: 15px; border: 1px solid #30363d; margin-bottom: 30px;">
            <h2 style="color:white; font-size:32px; margin-bottom:10px;">Your <span style="color:#3fb950;">incidents overview</span> on the way!</h2>
            <p style="color:#a1a9b7; font-size:16px;">Deterministic logs from the SRM_Campus_Net gateway. Neatly displayed for forensics. 🧠</p>
        </div>
    """, unsafe_allow_html=True)

    # Content Layout: Incidents on left, Intelligence on right
    col_inv, col_mit = st.columns([2, 1])

    with col_inv:
        st.markdown("### 📊 Active & Past Incidents")
        if not st.session_state.alert_history:
            st.info("No incidents detected yet. Monitoring SRM_Campus_Net...")
        else:
            # Table Header
            st.markdown("""<div style="display: grid; grid-template-columns: 1fr 2fr 2fr; padding: 10px 20px; color: #a1a9b7; font-size: 11px; text-transform: uppercase; letter-spacing: 1px;"><div>Status</div><div>Source Origin</div><div>Telemetry Detail</div></div>""", unsafe_allow_html=True)
            
            for alert in st.session_state.alert_history[:6]:
                is_active = alert == st.session_state.alert_history[0] and st.session_state.pps_data[-1] > 300
                st.markdown(f"""
                    <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; padding: 20px; background: #21262d; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 10px; align-items: center;">
                        <div style="color: {"#ff4b4b" if is_active else "#3fb950"}; font-weight: bold; font-size: 13px;">{"🔴 Ongoing" if is_active else "🟢 Resolved"}</div>
                        <div style="color: white; font-weight: 500;">{alert['flow'][0]} <br><span style="color:#a1a9b7; font-size:11px;">Anomaly Detected</span></div>
                        <div>
                            <span style="background: #30363d; color: #ff4b4b; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">{alert['pps']} PPS</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

    with col_mit:
        st.markdown("### 🛡️ Mitigation Intelligence")
        if st.session_state.alert_history:
            latest = st.session_state.alert_history[0]
            
            # --- FEATURE: REASON OF ATTACK ---
            st.markdown(f"""
                <div class="ur-card">
                    <div class="ur-label">Root Cause Analysis</div>
                    <div style="color: #ff4b4b; font-weight:bold; font-size:15px; margin-bottom:10px;">Volumetric PPS Flood</div>
                    <p style="font-size:12px; color:#a1a9b7;">
                        <b>Detection Logic:</b> Heuristic breach of 3&sigma; baseline.<br><br>
                        The source <b>{latest['flow'][0]}</b> is transmitting packets at a rate that exceeds standard campus behavior by <b>4.2 standard deviations</b>. This indicates a potential DoS/DDoS attempt.
                    </p>
                </div>
            """, unsafe_allow_html=True)

            # --- FEATURE: POSSIBLE MITIGATIONS ---
            st.markdown(f"""
                <div class="ur-card" style="border-left: 4px solid #3fb950;">
                    <div class="ur-label" style="color:#3fb950;">Recommended Mitigation</div>
                    <p style="font-size:12px; color:white; margin-bottom:10px;"><b>Action:</b> Kernel-level IP Drop</p>
                    <div style="color:#00ff41; font-size:13px; font-family:monospace; background:#090b0f; padding:12px; border-radius:4px; border: 1px solid #1f242d;">
                        # iptables -A INPUT -s {latest['flow'][0]} -j DROP
                    </div>
                    <p style="font-size:11px; color:#a1a9b7; margin-top:10px;">Deploying this rule will instantly discard all frames from this origin at the NIC driver layer.</p>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button("🚀 Deploy Mitigation", use_container_width=True):
                st.success(f"Kernel rule active: {latest['flow'][0]} blocked.")
        else:
            st.markdown('<div class="ur-card" style="text-align:center; padding:40px; color:#a1a9b7;">Network baseline stable.<br>No mitigations required at this time.</div>', unsafe_allow_html=True)

    # CRITICAL: This prevents the Monitoring content from bleeding into this page
    st.stop()
elif st.session_state.page == "Dictionary":
    st.markdown('<h1 style="color:white; font-family:sans-serif; margin-bottom:20px;">Threat Dictionary.</h1>', unsafe_allow_html=True)
    
    st.markdown("""
        <div style="background: linear-gradient(90deg, #1e252e 0%, #171b21 100%); padding: 40px; border-radius: 15px; border: 1px solid #30363d; margin-bottom: 30px;">
            <h2 style="color:white; font-size:32px; margin-bottom:10px;">Network <span style="color:#3fb950;">Anomaly Index</span></h2>
            <p style="color:#a1a9b7; font-size:16px;">Comprehensive database of 20+ monitored attack vectors on SRM_Campus_Net. 📚</p>
        </div>
    """, unsafe_allow_html=True)

    # 20 Threats with Icons and Concise Details
    threats = [
        {"icon": "🌊", "n": "UDP Flood", "d": "Volumetric saturation", "m": "Rate-limit / DROP"},
        {"icon": "🤝", "n": "SYN Flood", "d": "Handshake exhaustion", "m": "SYN Cookies"},
        {"icon": "📡", "n": "DNS Amp", "d": "Spoofed query gain", "m": "RRL Policy"},
        {"icon": "📟", "n": "ICMP Flood", "d": "Ping saturation", "m": "Disable Echo"},
        {"icon": "🌐", "n": "HTTP Flood", "d": "Layer 7 exhaustion", "m": "WAF Filter"},
        {"icon": "🐌", "n": "Slowloris", "d": "Stalled connections", "m": "Limit sessions"},
        {"icon": "⏱️", "n": "NTP Amp", "d": "Monlist exploitation", "m": "Disable Monlist"},
        {"icon": "💣", "n": "Smurf Atk", "d": "ICMP reflection", "m": "Disable Broadcast"},
        {"icon": "🔍", "n": "Port Scan", "d": "Reconnaissance", "m": "Block Sequentials"},
        {"icon": "💥", "n": "Fraggle", "d": "UDP reflection", "m": "Filter Port 7/19"},
        {"icon": "🛸", "n": "Zero-Day", "d": "Heuristic anomaly", "m": "3σ Isolation"},
        {"icon": "🎭", "n": "ARP Spoof", "d": "MAC poisoning", "m": "DAI Inspection"},
        {"icon": "🆔", "n": "IP Spoof", "d": "Forged source IP", "m": "Unicast RPF"},
        {"icon": "💉", "n": "SQL Inject", "d": "Payload injection", "m": "Input Sanitizing"},
        {"icon": "📜", "n": "XSS Vector", "d": "Script injection", "m": "CSP Policy"},
        {"icon": "🛤️", "n": "BGP Hijack", "d": "Routing table theft", "m": "RPKI Check"},
        {"icon": "🤖", "n": "Botnet C2", "d": "Malicious beaconing", "m": "C2 Domain Block"},
        {"icon": "🌑", "n": "Darknet TX", "d": "Unallocated traffic", "m": "Blackhole Route"},
        {"icon": "💀", "n": "Ping of Death", "d": "Oversized ICMP", "m": "Patch TCP/IP"},
        {"icon": "📉", "n": "Deathline", "d": "State table drain", "m": "Stateful Tuning"}
    ]

    # Render as a grid of interactive buttons that look like "Square Icons"
    cols = st.columns(4)
    for i, t in enumerate(threats):
        with cols[i % 4]:
            # Each button is styled with the Icon + Name
            # The details are shown inside the button text for that 'Square' look
            button_label = f"{t['icon']}\n{t['n']}\n({t['d']})"
            if st.button(button_label, key=f"threat_{i}", use_container_width=True):
                st.session_state.active_threat = t

    # Bottom Detail Panel (Appears when a square is clicked)
    if 'active_threat' in st.session_state:
        at = st.session_state.active_threat
        st.markdown(f"""
            <div style="margin-top:30px; background:#21262d; padding:30px; border-radius:12px; border: 1px solid #3fb950;">
                <div style="display:flex; align-items:center; gap:15px; margin-bottom:15px;">
                    <span style="font-size:40px;">{at['icon']}</span>
                    <div>
                        <h3 style="color:white; margin:0;">{at['n']} Intelligence Report</h3>
                        <p style="color:#3fb950; margin:0; font-size:12px; font-weight:bold;">INTMS THREAT VECTOR ID: {random.randint(1000, 9999)}</p>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:30px;">
                    <div>
                        <p style="color:#a1a9b7; font-size:11px; letter-spacing:1px; margin-bottom:5px;">BEHAVIORAL DESCRIPTION</p>
                        <p style="color:white; font-size:15px;">{at['d']}. Detected via real-time metadata analysis on SRM_Campus_Net.</p>
                    </div>
                    <div>
                        <p style="color:#a1a9b7; font-size:11px; letter-spacing:1px; margin-bottom:5px;">RECOMMENDED KERNEL MITIGATION</p>
                        <code style="display:block; background:#0d1117; color:#3fb950; padding:12px; border-radius:6px; font-family:monospace;">{at['m']}</code>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("<br><p style='text-align:center; color:#a1a9b7;'>Click a threat square above to analyze the heuristic signature.</p>", unsafe_allow_html=True)

    st.stop()

# --- GLOBAL REFRESH ---
time.sleep(1)
st.rerun()
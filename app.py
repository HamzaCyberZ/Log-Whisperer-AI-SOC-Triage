import os
import streamlit as st
from detector import detect_anomalies, summarize
from llm_triage import generate_incident_report, ollama_available
from db import init_db, register_user, verify_user, save_history, get_history
from pdf_gen import create_pdf

# 1. Initialize DB & Page Config
init_db()
st.set_page_config(
    page_title="Log Whisperer | AI SOC Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Liquid Glassmorphism ("Watery Mirror") CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Deep Liquid Cyber Backdrop */
    .stApp {
        background: 
            radial-gradient(circle at 14% 16%, rgba(14, 165, 233, 0.24), transparent 36%),
            radial-gradient(circle at 86% 80%, rgba(99, 102, 241, 0.22), transparent 38%),
            radial-gradient(circle at 50% 45%, rgba(16, 185, 129, 0.08), transparent 52%),
            linear-gradient(135deg, #03060c 0%, #08101d 50%, #040913 100%);
        color: #e2e8f0;
    }

    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Watery Mirror Sidebar */
    section[data-testid="stSidebar"] {
        background: rgba(11, 19, 34, 0.48) !important;
        backdrop-filter: blur(24px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.14) !important;
        box-shadow: 8px 0 32px rgba(0, 0, 0, 0.45);
    }

    /* Glass Hero Header */
    .glass-hero {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.10) 0%, rgba(255, 255, 255, 0.02) 100%);
        backdrop-filter: blur(22px) saturate(170%);
        -webkit-backdrop-filter: blur(22px) saturate(170%);
        border: 1px solid rgba(255, 255, 255, 0.16);
        border-top: 1px solid rgba(255, 255, 255, 0.38);
        border-radius: 20px;
        padding: 22px 28px;
        margin-bottom: 22px;
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.22);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .hero-title {
        font-size: 1.95rem;
        font-weight: 700;
        background: linear-gradient(90deg, #ffffff 0%, #7dd3fc 50%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.5px;
    }

    .hero-sub {
        color: #94a3b8;
        font-size: 0.92rem;
        margin-top: 4px;
    }

    /* Glass Containers */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background: rgba(15, 23, 42, 0.42) !important;
        backdrop-filter: blur(22px) saturate(165%) !important;
        -webkit-backdrop-filter: blur(22px) saturate(165%) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.28) !important;
        border-radius: 18px !important;
        padding: 18px !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35) !important;
    }

    /* Glass Metric Cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.02));
        backdrop-filter: blur(18px);
        -webkit-backdrop-filter: blur(18px);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-top: 1px solid rgba(255, 255, 255, 0.3);
        border-radius: 16px;
        padding: 16px 20px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        transition: transform 0.25s ease, border-color 0.25s ease;
    }
    div[data-testid="stMetric"]:hover {
        transform: translateY(-3px);
        border-color: rgba(56, 189, 248, 0.55);
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
    }
    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-weight: 700;
    }

    /* Inputs & Textareas */
    input[type="text"], input[type="password"] {
        background: rgba(6, 11, 22, 0.65) !important;
        color: #f1f5f9 !important;
        border: 1px solid rgba(255, 255, 255, 0.16) !important;
        border-radius: 12px !important;
    }
    textarea {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
        background: rgba(6, 11, 22, 0.68) !important;
        color: #e0f2fe !important;
        border: 1px solid rgba(255, 255, 255, 0.16) !important;
        border-radius: 14px !important;
    }
    textarea:focus, input:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 18px rgba(56, 189, 248, 0.25) !important;
    }

    /* Tabs Styling */
    button[data-baseweb="tab"] {
        background: rgba(255, 255, 255, 0.04) !important;
        border-radius: 10px 10px 0 0 !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
        padding: 10px 20px !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: rgba(56, 189, 248, 0.15) !important;
        color: #7dd3fc !important;
        border-bottom: 2px solid #38bdf8 !important;
    }

    /* Liquid Buttons */
    .stButton > button, .stDownloadButton > button {
        background: rgba(255, 255, 255, 0.06);
        backdrop-filter: blur(12px);
        color: #f1f5f9;
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 12px;
        font-weight: 600;
        transition: all 0.25s ease;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background: rgba(56, 189, 248, 0.18);
        border-color: #38bdf8;
        color: #ffffff;
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.25);
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0284c7 0%, #3b82f6 50%, #6366f1 100%);
        border: 1px solid rgba(255, 255, 255, 0.35);
        color: white;
        box-shadow: 0 8px 25px rgba(14, 165, 233, 0.4);
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 10px 30px rgba(56, 189, 248, 0.65);
        transform: translateY(-2px);
    }

    /* Anomaly Log Cards */
    .log-card {
        background: rgba(255, 255, 255, 0.04);
        border-left: 3px solid #f43f5e;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }
    .badge-sig {
        display: inline-block;
        background: rgba(244, 63, 94, 0.2);
        color: #fda4af;
        border: 1px solid rgba(244, 63, 94, 0.4);
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.74rem;
        font-weight: 600;
        margin-bottom: 6px;
        text-transform: uppercase;
    }
    .badge-outlier {
        display: inline-block;
        background: rgba(245, 158, 11, 0.2);
        color: #fcd34d;
        border: 1px solid rgba(245, 158, 11, 0.4);
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.74rem;
        font-weight: 600;
        margin-bottom: 6px;
        text-transform: uppercase;
    }
    .log-code {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #cbd5e1;
        word-break: break-all;
        display: block;
    }

    /* Status & User Pills */
    .pill-green {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.4);
        color: #6ee7b7;
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 0.82rem;
        font-weight: 600;
        display: inline-block;
    }
    .pill-red {
        background: rgba(244, 63, 94, 0.15);
        border: 1px solid rgba(244, 63, 94, 0.4);
        color: #fda4af;
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 0.82rem;
        font-weight: 600;
        display: inline-block;
    }
    .user-card {
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 14px;
        padding: 14px;
        margin-bottom: 14px;
    }
</style>
""", unsafe_allow_html=True)

# --- Session State for Login ---
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""

# ================= GLASS AUTHENTICATION PORTAL =================
if not st.session_state["logged_in"]:
    st.markdown("<br>", unsafe_allow_html=True)
    _, center_col, _ = st.columns([1, 1.35, 1])

    with center_col:
        st.markdown("""
        <div class="glass-hero" style="flex-direction: column; text-align: center; margin-bottom: 18px;">
            <div class="hero-title">🛡️ Log Whisperer</div>
            <div class="hero-sub">Autonomous AI SOC Triage &amp; Forensic Platform</div>
        </div>
        """, unsafe_allow_html=True)

        with st.container(border=True):
            tab1, tab2 = st.tabs(["🔑 Analyst Login", "📝 Create Account"])

            with tab1:
                login_user = st.text_input("Username", key="login_user", placeholder="Enter your SOC handle")
                login_pass = st.text_input("Password", type="password", key="login_pass", placeholder="••••••••")
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Access SOC Console →", type="primary", use_container_width=True):
                    if verify_user(login_user, login_pass):
                        st.session_state["logged_in"] = True
                        st.session_state["username"] = login_user
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")

            with tab2:
                reg_user = st.text_input("New Username", key="reg_user", placeholder="Choose a username")
                reg_pass = st.text_input("New Password", type="password", key="reg_pass", placeholder="Create a strong password")
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Register Analyst", type="primary", use_container_width=True):
                    if not reg_user.strip() or not reg_pass.strip():
                        st.warning("Username and password cannot be empty.")
                    elif register_user(reg_user, reg_pass):
                        st.success("Account created! Switch to the Login tab.")
                    else:
                        st.error("Username already exists.")
    st.stop()

# ================= MAIN APP (After Login) =================
is_ollama_up = ollama_available()

# --- Watery Mirror Sidebar ---
with st.sidebar:
    st.markdown(f"""
    <div class="user-card">
        <div style="font-size: 0.78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px;">Active Analyst</div>
        <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin-top: 2px;">👤 {st.session_state['username']}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ Detection Engine")
    contamination = st.slider(
        "Isolation Sensitivity",
        min_value=0.05,
        max_value=0.40,
        value=0.15,
        step=0.05,
        help="Controls how aggressively statistical outliers are flagged."
    )
    max_display = st.slider("Max Flagged Lines Shown", 5, 30, 10, 5)

    st.divider()
    st.markdown("**Local LLM Status**")
    if is_ollama_up:
        st.markdown('<span class="pill-green">● Ollama Connected</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="pill-red">● Ollama Offline</span>', unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state["logged_in"] = False
        st.session_state["username"] = ""
        st.rerun()

# --- Top Glass Hero Banner ---
status_pill = (
    '<span class="pill-green">● AI Engine Online</span>'
    if is_ollama_up else
    '<span class="pill-red">● AI Engine Offline</span>'
)

st.markdown(f"""
<div class="glass-hero">
    <div>
        <div class="hero-title">🛡️ Log Whisperer — AI SOC Triage</div>
        <div class="hero-sub">ML Anomaly Isolation &bull; Signature Heuristics &bull; Automated Forensic PDF Reports</div>
    </div>
    <div>{status_pill}</div>
</div>
""", unsafe_allow_html=True)

# --- Navigation Tabs ---
tab_scan, tab_history = st.tabs(["🔍 Threat Scanner", "📜 Audit & Scan History"])

# ==================== TAB 1: SCANNER ====================
with tab_scan:
    with st.container(border=True):
        st.markdown("#### 📥 Log Telemetry Ingestion")
        c1, c2, c3, c4 = st.columns([1, 1, 1, 1.4])

        if c1.button("🔐 SSH Brute-Force", use_container_width=True):
            if os.path.exists("samples/ssh_bruteforce.log"):
                with open("samples/ssh_bruteforce.log") as f:
                    st.session_state["raw_logs"] = f.read()

        if c2.button("🌐 Nginx Web Scan", use_container_width=True):
            if os.path.exists("samples/nginx_scan.log"):
                with open("samples/nginx_scan.log") as f:
                    st.session_state["raw_logs"] = f.read()

        if c3.button("✅ Clean K8s", use_container_width=True):
            if os.path.exists("samples/k8s_clean.log"):
                with open("samples/k8s_clean.log") as f:
                    st.session_state["raw_logs"] = f.read()

        uploaded_file = c4.file_uploader("Upload Log", type=["log", "txt"], label_visibility="collapsed")
        if uploaded_file is not None:
            st.session_state["raw_logs"] = uploaded_file.read().decode("utf-8", errors="ignore")

        raw_logs = st.text_area(
            "Paste logs here:",
            value=st.session_state.get("raw_logs", ""),
            height=200,
            placeholder="Paste raw syslog, auth.log, nginx access logs, or Kubernetes events here...",
            label_visibility="collapsed"
        )

        btn_col, info_col = st.columns([1.2, 3])
        analyze_clicked = btn_col.button("⚡ Analyze Logs", type="primary", use_container_width=True)
        if raw_logs.strip():
            info_col.caption(f"Telemetry buffer ready: **{len(raw_logs.strip().splitlines())}** lines loaded.")

    if analyze_clicked and raw_logs.strip():
        with st.spinner("🔬 Isolating anomalies & generating AI triage report..."):
            df = detect_anomalies(raw_logs, contamination=contamination)
            summary = summarize(df)
            anomalies = df[df['anomaly'] == 1]

            report = "No anomalies found."
            if len(anomalies) > 0:
                report = generate_incident_report(anomalies['line'].tolist(), summary)
                save_history(st.session_state["username"], summary['total'], summary['anomalies'], report)

        st.markdown("<br>", unsafe_allow_html=True)

        # KPI Row
        threat_pct = round((summary['anomalies'] / summary['total']) * 100, 1) if summary['total'] > 0 else 0
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Lines Scanned", f"{summary['total']:,}")
        m2.metric("Suspicious Lines", f"{summary['anomalies']:,}", delta=f"{threat_pct}% flagged", delta_color="inverse")
        m3.metric("Unique IPs", len(summary['involved_ips']))
        m4.metric("Severity Status", "CRITICAL" if summary['anomalies'] > 5 else ("WARNING" if summary['anomalies'] > 0 else "CLEAN"))

        st.markdown("<br>", unsafe_allow_html=True)

        # Split Results View
        left, right = st.columns([1.05, 1.15], gap="large")

        with left:
            with st.container(border=True):
                st.markdown("#### 🎯 Flagged Anomalies & Signatures")
                if len(anomalies) > 0:
                    if summary['involved_ips']:
                        ips_str = " • ".join([f"`{ip}`" for ip in list(summary['involved_ips'])[:6]])
                        st.markdown(f"**Involved IPs:** {ips_str}")

                    for _, row in anomalies.head(max_display).iterrows():
                        is_sig = bool(row['signatures'])
                        badge_cls = "badge-sig" if is_sig else "badge-outlier"
                        badge_txt = row['signatures'] if is_sig else "Outlier"
                        safe_line = str(row['line'])[:180].replace("<", "&lt;").replace(">", "&gt;")
                        st.markdown(f"""
                        <div class="log-card">
                            <span class="{badge_cls}">{badge_txt}</span>
                            <code class="log-code">{safe_line}</code>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("✅ No anomalies detected in this log batch.")

        with right:
            with st.container(border=True):
                st.markdown("#### 🤖 AI Incident Report")
                if len(anomalies) > 0:
                    st.markdown(report)
                    st.divider()
                    pdf_bytes = create_pdf(report, summary['total'], summary['anomalies'])
                    st.download_button(
                        label="⬇️ Download Official PDF Report",
                        data=pdf_bytes,
                        file_name=f"incident_report_{st.session_state['username']}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                else:
                    st.info("Traffic looks clean. No incident report needed.")

    elif not raw_logs.strip():
        st.info("👆 Load a sample dataset above, upload a `.log` file, or paste raw logs to start scanning.")

# ==================== TAB 2: HISTORY ====================
with tab_history:
    with st.container(border=True):
        st.markdown(f"#### 📜 Scan Archive for `{st.session_state['username']}`")
        history_data = get_history(st.session_state["username"])

        if not history_data:
            st.info("No past scans found in your account. Run an analysis in the Threat Scanner tab!")
        else:
            for idx, row in enumerate(history_data):
                timestamp, total, sus, rep = row
                with st.expander(f"📅 {timestamp}   |   📄 Total Lines: {total}   |   🚨 Suspicious: {sus}"):
                    st.markdown(rep)
                    hist_pdf = create_pdf(rep, total, sus)
                    st.download_button(
                        label="⬇️ Export This Report as PDF",
                        data=hist_pdf,
                        file_name=f"incident_report_{st.session_state['username']}_{idx+1}.pdf",
                        mime="application/pdf",
                        key=f"hist_pdf_{idx}"
                    )
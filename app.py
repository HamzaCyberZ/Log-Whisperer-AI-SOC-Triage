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

# 2. Sleek Cyber / Glassmorphism UI Theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background: #030712;
        color: #f3f4f6;
    }

    section[data-testid="stSidebar"] {
        background: #0b0f19 !important;
        border-right: 1px solid rgba(56, 189, 248, 0.1);
    }

    .cyber-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }

    .hero-banner {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .hero-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
        margin: 0;
    }

    .hero-sub {
        color: #94a3b8;
        font-size: 0.9rem;
        margin-top: 4px;
    }

    .stButton > button {
        background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        opacity: 0.9;
        transform: translateY(-1px);
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
    }

    .log-card {
        background: rgba(3, 7, 18, 0.6);
        border-left: 3px solid #f43f5e;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 8px;
    }
    .badge-sig {
        background: rgba(244, 63, 94, 0.2);
        color: #fda4af;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .log-code {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #e2e8f0;
        word-break: break-all;
    }
</style>
""", unsafe_allow_html=True)

# --- Session State ---
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""

# ================= AUTHENTICATION =================
if not st.session_state["logged_in"]:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #38bdf8; margin:0;">🛡️ Log Whisperer</h1>
            <p style="color: #94a3b8;">Autonomous AI SOC Triage & Forensic Platform</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.container(border=True):
            tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
            with tab1:
                u = st.text_input("Username", key="l_user")
                p = st.text_input("Password", type="password", key="l_pass")
                if st.button("Login", use_container_width=True):
                    if verify_user(u, p):
                        st.session_state["logged_in"] = True
                        st.session_state["username"] = u
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")
            with tab2:
                ru = st.text_input("New Username", key="r_user")
                rp = st.text_input("New Password", type="password", key="r_pass")
                if st.button("Create Account", use_container_width=True):
                    if register_user(ru, rp):
                        st.success("Registered successfully! Switch to Login.")
                    else:
                        st.error("Username taken.")
    st.stop()

# ================= DASHBOARD =================
with st.sidebar:
    st.markdown(f"### 👤 {st.session_state['username']}")
    st.divider()
    contamination = st.slider("Anomaly Sensitivity", 0.05, 0.40, 0.15, 0.05)
    max_display = st.slider("Max Display Lines", 5, 30, 10, 5)
    st.divider()
    st.markdown('<span style="color:#34d399; font-weight:600;">● Cloud Groq Engine Active</span>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state["logged_in"] = False
        st.rerun()

st.markdown("""
<div class="hero-banner">
    <div>
        <p class="hero-title">🛡️ Log Whisperer — AI SOC Triage</p>
        <p class="hero-sub">ML Anomaly Isolation • Cloud Groq Engine • Instant PDF Forensic Reports</p>
    </div>
    <div><span style="background: rgba(16,185,129,0.2); color: #34d399; padding: 6px 12px; border-radius: 20px; font-weight:600; border:1px solid rgba(16,185,129,0.4);">Online</span></div>
</div>
""", unsafe_allow_html=True)

tab_scan, tab_history = st.tabs(["🔍 Threat Scanner", "📜 Scan History"])

with tab_scan:
    with st.container(border=True):
        st.markdown("#### 📥 Log Telemetry Ingestion")
        c1, c2, c3, c4 = st.columns([1, 1, 1, 1.3])

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
        if uploaded_file:
            st.session_state["raw_logs"] = uploaded_file.read().decode("utf-8", errors="ignore")

        raw_logs = st.text_area(
            "Paste logs here:",
            value=st.session_state.get("raw_logs", ""),
            height=180,
            placeholder="Paste logs here..."
        )

        analyze_clicked = st.button("⚡ Analyze & Run AI Triage", type="primary", use_container_width=True)

    if analyze_clicked and raw_logs.strip():
        with st.spinner("🔬 Running ML anomaly isolation & querying Groq LLM..."):
            df = detect_anomalies(raw_logs, contamination=contamination)
            summary = summarize(df)
            anomalies = df[df['anomaly'] == 1]

            report = "No anomalies found."
            if len(anomalies) > 0:
                report = generate_incident_report(anomalies['line'].tolist(), summary)
                save_history(st.session_state["username"], summary['total'], summary['anomalies'], report)

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Lines", f"{summary['total']:,}")
        m2.metric("Suspicious", f"{summary['anomalies']:,}")
        m3.metric("Unique IPs", len(summary['involved_ips']))
        m4.metric("Status", "CRITICAL" if summary['anomalies'] > 0 else "CLEAN")

        st.markdown("<br>", unsafe_allow_html=True)
        left, right = st.columns([1, 1.2], gap="large")

        with left:
            with st.container(border=True):
                st.markdown("#### 🎯 Flagged Signatures")
                if len(anomalies) > 0:
                    for _, row in anomalies.head(max_display).iterrows():
                        safe_line = str(row['line'])[:150].replace("<", "&lt;").replace(">", "&gt;")
                        st.markdown(f"""
                        <div class="log-card">
                            <span class="badge-sig">{row['signatures'] or 'Outlier'}</span>
                            <code class="log-code">{safe_line}</code>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("No anomalies detected.")

        with right:
            with st.container(border=True):
                st.markdown("#### 🤖 AI Incident Report")
                st.markdown(report)
                if len(anomalies) > 0:
                    pdf_bytes = create_pdf(report, summary['total'], summary['anomalies'])
                    st.download_button(
                        "⬇️ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"incident_report_{st.session_state['username']}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )

with tab_history:
    with st.container(border=True):
        st.markdown(f"#### 📜 Scan Archive for `{st.session_state['username']}`")
        history_data = get_history(st.session_state["username"])
        if not history_data:
            st.info("No past scans found.")
        else:
            for idx, row in enumerate(history_data):
                timestamp, total, sus, rep = row
                with st.expander(f"📅 {timestamp} | Total: {total} | Suspicious: {sus}"):
                    st.markdown(rep)
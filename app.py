
import os
import html
import streamlit as st

from detector import detect_anomalies, summarize
from llm_triage import generate_incident_report
from db import (
    init_db,
    register_user,
    verify_user,
    save_history,
    get_history
)
from pdf_gen import create_pdf


# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

st.set_page_config(
    page_title="Log Whisperer | AI SOC Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_db()


# ==========================================
# 2. CYBER THEME
# ==========================================

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
    border-right: 1px solid rgba(56,189,248,0.1);
}

.cyber-card {
    background: rgba(17,24,39,0.7);
    border: 1px solid rgba(56,189,248,0.2);
    border-radius: 12px;
    padding: 20px;
}

.hero-banner {
    background: linear-gradient(135deg,
        rgba(14,165,233,0.15),
        rgba(99,102,241,0.1));
    border: 1px solid rgba(56,189,248,0.3);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 24px;
}

.hero-title {
    font-size: 1.8rem;
    font-weight: 700;
    color: #38bdf8;
}

.hero-sub {
    color: #94a3b8;
    font-size: 0.9rem;
}

.stButton > button {
    background: linear-gradient(135deg,#0284c7,#2563eb);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

.stButton > button:hover {
    opacity: 0.9;
    box-shadow: 0 0 15px rgba(56,189,248,0.4);
}

.log-card {
    background: rgba(3,7,18,0.6);
    border-left: 3px solid #f43f5e;
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 8px;
}

.badge-sig {
    background: rgba(244,63,94,0.2);
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


# ==========================================
# 3. SESSION STATE
# ==========================================

DEFAULTS = {
    "logged_in": False,
    "username": "",
    "raw_logs": "",
    "analysis_result": None,
    "analysis_error": None
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ==========================================
# 4. AI ENGINE
# ==========================================

def run_ai_triage(lines, summary, provider):

    """
    Calls the AI provider supported by llm_triage.py.
    """

    try:
        return generate_incident_report(
            lines,
            summary,
            provider=provider
        )

    except TypeError as error:
        if "provider" in str(error):
            raise RuntimeError(
                "llm_triage.py must support the provider parameter. "
                "Please update that file."
            ) from error

        raise


# ==========================================
# 5. AUTHENTICATION
# ==========================================

if not st.session_state.logged_in:

    st.markdown("<br><br>", unsafe_allow_html=True)

    _, col, _ = st.columns([1, 1.2, 1])

    with col:

        st.markdown("""
        <div style="text-align:center;margin-bottom:20px;">
            <h1 style="color:#38bdf8;">🛡️ Log Whisperer</h1>
            <p style="color:#94a3b8;">
                Autonomous AI SOC Triage & Forensic Platform
            </p>
        </div>
        """, unsafe_allow_html=True)

        with st.container(border=True):

            tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])

            with tab1:

                username = st.text_input(
                    "Username",
                    key="login_username"
                )

                password = st.text_input(
                    "Password",
                    type="password",
                    key="login_password"
                )

                if st.button("Login", use_container_width=True):

                    if not username.strip() or not password:
                        st.warning("Enter username and password.")

                    elif verify_user(username.strip(), password):

                        st.session_state.logged_in = True
                        st.session_state.username = username.strip()

                        st.rerun()

                    else:
                        st.error("Invalid username or password.")

            with tab2:

                new_username = st.text_input(
                    "New Username",
                    key="register_username"
                )

                new_password = st.text_input(
                    "New Password",
                    type="password",
                    key="register_password"
                )

                if st.button("Create Account", use_container_width=True):

                    if not new_username.strip() or not new_password:
                        st.warning("Enter username and password.")

                    elif register_user(
                        new_username.strip(),
                        new_password
                    ):
                        st.success(
                            "Account created! Please login."
                        )

                    else:
                        st.error(
                            "Registration failed or username already exists."
                        )

    st.stop()


# ==========================================
# 6. SIDEBAR
# ==========================================

with st.sidebar:

    st.markdown(
        f"### 👤 {html.escape(st.session_state.username)}"
    )

    st.divider()

    st.markdown("### ⚙️ Detection Settings")

    contamination = st.slider(
        "Anomaly Sensitivity",
        min_value=0.05,
        max_value=0.40,
        value=0.15,
        step=0.05
    )

    max_display = st.slider(
        "Max Display Lines",
        min_value=5,
        max_value=30,
        value=10,
        step=5
    )

    st.divider()

    st.markdown("### 🤖 AI Engine")

    provider_options = [
        "Groq (Llama 3.3)",
        "Google Gemini (1.5 Flash)",
        "Cerebras (Ultra-Fast Llama)",
        "Anthropic Claude (3.5 Sonnet)"
    ]

    selected_llm = st.selectbox(
        "AI Engine Provider",
        provider_options,
        key="selected_llm"
    )

    st.caption(f"Selected: {selected_llm}")

    st.divider()

    st.markdown(
        '<span style="color:#34d399;font-weight:600;">'
        '● SOC Dashboard Active</span>',
        unsafe_allow_html=True
    )

    if st.button("🚪 Logout", use_container_width=True):

        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.raw_logs = ""
        st.session_state.analysis_result = None

        st.rerun()


# ==========================================
# 7. MAIN DASHBOARD
# ==========================================

st.markdown("""
<div class="hero-banner">
    <div class="hero-title">
        🛡️ Log Whisperer — AI SOC Triage
    </div>
    <div class="hero-sub">
        ML Anomaly Isolation • Multi-LLM Engine
        • Instant PDF Forensic Reports
    </div>
</div>
""", unsafe_allow_html=True)


tab_scan, tab_history = st.tabs([
    "🔍 Threat Scanner",
    "📜 Scan History"
])


# ==========================================
# 8. THREAT SCANNER
# ==========================================

with tab_scan:

    with st.container(border=True):

        st.markdown("#### 📥 Log Telemetry Ingestion")

        c1, c2, c3, c4 = st.columns([1, 1, 1, 1.3])

        samples = {
            "ssh": (
                c1,
                "🔐 SSH Brute-Force",
                "samples/ssh_bruteforce.log"
            ),
            "nginx": (
                c2,
                "🌐 Nginx Web Scan",
                "samples/nginx_scan.log"
            ),
            "k8s": (
                c3,
                "✅ Clean K8s",
                "samples/k8s_clean.log"
            )
        }

        for key, (column, label, path) in samples.items():

            if column.button(
                label,
                use_container_width=True,
                key=f"sample_{key}"
            ):

                full_path = os.path.join(BASE_DIR, path)

                if os.path.isfile(full_path):

                    with open(
                        full_path,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as file:

                        st.session_state.raw_logs = file.read()

                else:
                    st.error(f"Sample file not found: {full_path}")

        uploaded_file = c4.file_uploader(
            "Upload Log",
            type=["log", "txt"],
            key="log_upload"
        )

        if uploaded_file is not None:

            uploaded_content = uploaded_file.getvalue().decode(
                "utf-8",
                errors="ignore"
            )

            if st.session_state.get("uploaded_name") != uploaded_file.name:

                st.session_state.raw_logs = uploaded_content
                st.session_state.uploaded_name = uploaded_file.name

        raw_logs = st.text_area(
            "Paste logs here:",
            value=st.session_state.raw_logs,
            height=180,
            placeholder="Paste your server logs here...",
            key="log_input"
        )

        st.session_state.raw_logs = raw_logs

        analyze_clicked = st.button(
            "⚡ Analyze & Run AI Triage",
            type="primary",
            use_container_width=True
        )

    # ======================================
    # 9. ANALYSIS ENGINE
    # ======================================

    if analyze_clicked:

        st.session_state.analysis_result = None
        st.session_state.analysis_error = None

        if not raw_logs.strip():

            st.warning("Please upload or paste log data first.")

        else:

            try:

                with st.spinner("🔬 Running ML anomaly detection..."):

                    df = detect_anomalies(
                        raw_logs,
                        contamination=contamination
                    )

                    summary = summarize(df)

                    anomalies = df[df["anomaly"] == 1]

                report = "No anomalies found. The scanned logs appear clean."

                ai_status = "Not required"

                if not anomalies.empty:

                    try:

                        with st.spinner(
                            f"🤖 Generating report using {selected_llm}..."
                        ):

                            report = run_ai_triage(
                                anomalies["line"].tolist(),
                                summary,
                                selected_llm
                            )

                        ai_status = selected_llm

                    except Exception as ai_error:

                        report = (
                            "AI report generation failed.\n\n"
                            f"Error: {str(ai_error)}\n\n"
                            "ML anomaly detection completed successfully."
                        )

                        ai_status = "AI unavailable"

                # Store results so they survive Streamlit reruns.

                st.session_state.analysis_result = {
                    "df": df,
                    "summary": summary,
                    "anomalies": anomalies,
                    "report": report,
                    "ai_status": ai_status
                }

                # Save history independently.

                try:

                    save_history(
                        st.session_state.username,
                        summary["total"],
                        summary["anomalies"],
                        report
                    )

                except Exception as db_error:

                    st.warning(
                        f"Analysis completed, but history could not be saved: {db_error}"
                    )

            except Exception as error:

                st.session_state.analysis_error = str(error)

    # ======================================
    # 10. DISPLAY RESULTS
    # ======================================

    if st.session_state.analysis_error:

        st.error(
            f"Analysis Error: {st.session_state.analysis_error}"
        )

    result = st.session_state.analysis_result

    if result:

        summary = result["summary"]
        anomalies = result["anomalies"]
        report = result["report"]

        st.markdown("### 📊 Security Analysis Results")

        m1, m2, m3, m4 = st.columns(4)

        m1.metric(
            "Total Lines Scanned",
            f"{summary['total']:,}"
        )

        m2.metric(
            "Suspicious Lines",
            f"{summary['anomalies']:,}"
        )

        m3.metric(
            "Unique IPs",
            len(summary["involved_ips"])
        )

        m4.metric(
            "Severity Status",
            "CRITICAL" if summary["anomalies"] > 0 else "CLEAN"
        )

        left, right = st.columns([1, 1.2], gap="large")

        # Flagged anomalies

        with left:

            with st.container(border=True):

                st.markdown("#### 🎯 Flagged Anomalies & Signatures")

                if not anomalies.empty:

                    st.write(
                        "**Involved IPs:**",
                        ", ".join(
                            map(str, summary["involved_ips"])
                        )
                    )

                    for _, row in anomalies.head(max_display).iterrows():

                        safe_line = html.escape(
                            str(row["line"])[:150]
                        )

                        signature = html.escape(
                            str(row.get("signatures") or "Outlier")
                        )

                        st.markdown(
                            f"""
                            <div class="log-card">
                                <span class="badge-sig">
                                    {signature}
                                </span>
                                <br><br>
                                <code class="log-code">
                                    {safe_line}
                                </code>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                else:

                    st.success("No anomalies detected.")

        # AI report

        with right:

            with st.container(border=True):

                st.markdown("#### 🤖 AI Incident Report")

                st.caption(
                    f"AI Provider: {result['ai_status']}"
                )

                st.markdown(report)

                if summary["anomalies"] > 0:

                    try:

                        pdf_bytes = create_pdf(
                            report,
                            summary["total"],
                            summary["anomalies"]
                        )

                        st.download_button(
                            "⬇️ Download PDF Report",
                            data=pdf_bytes,
                            file_name="incident_report.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )

                    except Exception as pdf_error:

                        st.error(
                            f"PDF generation failed: {pdf_error}"
                        )


# ==========================================
# 11. SCAN HISTORY
# ==========================================

with tab_history:

    with st.container(border=True):

        st.markdown(
            f"#### 📜 Scan Archive for "
            f"`{st.session_state.username}`"
        )

        try:

            history_data = get_history(
                st.session_state.username
            )

            if not history_data:

                st.info("No past scans found.")

            else:

                for idx, row in enumerate(history_data):

                    timestamp, total, suspicious, report = row

                    with st.expander(
                        f"📅 {timestamp} | "
                        f"Total: {total} | "
                        f"Suspicious: {suspicious}"
                    ):

                        st.markdown(str(report))

        except Exception as error:

            st.error(f"History loading error: {error}")

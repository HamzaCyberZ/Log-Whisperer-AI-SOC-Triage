import streamlit as st
from groq import Groq

def generate_incident_report(suspicious_lines, summary):
    if not suspicious_lines:
        return "No suspicious lines to analyze."
    
    # Groq client initialize karein (Streamlit Secrets se key read karein)
    client = Groq(api_key=st.secrets["sk-Eg2SCnEjNfOUl82eznnVRGuE4IEbBO6VYAmn3rJckO64W4DO"])
    
    log_block = "\n".join(suspicious_lines[:20])
    sig_str = "\n".join(f"- {name}: {count}" for name, count in summary.get('top_signatures', [])) or "- (none)"
    ip_str = ", ".join(summary.get('involved_ips', [])) or "(none)"
    
    prompt = f"""You are a senior SOC analyst. Analyze the log evidence below and write a concise incident report.

=== STATS ===
Total lines: {summary.get('total', 0)}
Suspicious: {summary.get('anomalies', 0)}
Signatures:
{sig_str}
IPs: {ip_str}

=== SUSPICIOUS LOGS ===
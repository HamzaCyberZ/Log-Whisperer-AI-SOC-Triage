
import os
import streamlit as st

from groq import Groq
from google import genai
from cerebras.cloud.sdk import Cerebras
import anthropic


# ==========================================
# API KEY HELPER
# ==========================================

def get_api_key(key_name):

    try:
        api_key = st.secrets.get(key_name)
    except Exception:
        api_key = None

    if not api_key:
        api_key = os.getenv(key_name)

    return api_key.strip() if api_key else None


# ==========================================
# MAIN AI INCIDENT REPORT FUNCTION
# ==========================================

def generate_incident_report(
    suspicious_lines,
    summary,
    provider="Groq (Llama 3.3)"
):

    if not suspicious_lines:
        return "No suspicious lines to analyze."

    # Limit evidence to avoid excessive token usage.
    log_block = "\n".join(
        str(line)[:1000]
        for line in suspicious_lines[:20]
    )

    signatures = summary.get("top_signatures", [])

    sig_str = "\n".join(
        f"- {name}: {count}"
        for name, count in signatures
    ) or "- None"

    ip_str = ", ".join(
        map(str, summary.get("involved_ips", []))
    ) or "(none)"

    prompt = f"""
You are a senior Security Operations Center (SOC) analyst.

Analyze the following security log evidence.

IMPORTANT:
- Only make claims supported by the provided logs.
- Do not invent indicators of compromise.
- Clearly distinguish observed evidence from possible threats.
- Do not claim an attack succeeded without evidence.

=== STATISTICS ===

Total lines: {summary.get('total', 0)}
Suspicious lines: {summary.get('anomalies', 0)}

=== SIGNATURES ===

{sig_str}

=== INVOLVED IP ADDRESSES ===

{ip_str}

=== SUSPICIOUS LOGS ===

{log_block}

=== REQUIRED INCIDENT REPORT ===

1. Executive Summary
2. Incident Severity (Critical/High/Medium/Low)
3. Attack Classification
4. Indicators of Compromise (IOCs)
5. Technical Analysis
6. Potential Impact
7. Recommended Remediation
8. Final SOC Analyst Assessment

Write a professional, structured SOC incident report.
"""

    system_message = (
        "You are an expert SOC analyst specializing in "
        "SIEM, threat detection, incident response, "
        "network security and digital forensics."
    )

    try:

        # ======================================
        # 1. GROQ
        # ======================================

        if "Groq" in provider:

            api_key = get_api_key("GROQ_API_KEY")

            if not api_key:
                return "Groq API key missing. Configure GROQ_API_KEY."

            client = Groq(api_key=api_key)

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": system_message
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )

            return response.choices[0].message.content or (
                "Groq returned an empty response."
            )

        # ======================================
        # 2. GOOGLE GEMINI
        # ======================================

       elif "Gemini" in provider:

    api_key = get_api_key("GEMINI_API_KEY")

    if not api_key:
        return "Gemini API key missing."

    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={
            "system_instruction": system_message,
            "temperature": 0.3,
            "max_output_tokens": 2000
        }
    )

    return response.text or "Gemini returned an empty response."
        # ======================================
        # 3. CEREBRAS
        # ======================================

                elif "Cerebras" in provider:
            api_key = get_api_key("CEREBRAS_API_KEY")

            if not api_key:
                return "Cerebras API key missing."

            client = Cerebras(api_key=api_key)

            response = client.chat.completions.create(
                model="gpt-oss-120b",
                messages=[
                    {
                        "role": "system",
                        "content": system_message
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )

            return (
                response.choices[0].message.content
                or "Cerebras returned an empty response."
            )

        # ======================================
        # 4. ANTHROPIC CLAUDE
        # ======================================

        elif "Claude" in provider:

            api_key = get_api_key("ANTHROPIC_API_KEY")

            if not api_key:
                return "Anthropic API key missing. Configure ANTHROPIC_API_KEY."

            client = anthropic.Anthropic(api_key=api_key)

            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                temperature=0.3,
                system=system_message,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            return "\n".join(
                block.text
                for block in response.content
                if block.type == "text"
            )

        else:

            return f"Unsupported AI provider: {provider}"

    except Exception as error:

        return (
            f"Incident report generation failed with {provider}:\n"
            f"{type(error).__name__}: {str(error)}"
        )


# ==========================================
# OLLAMA STATUS
# ==========================================

def ollama_available():

    return False

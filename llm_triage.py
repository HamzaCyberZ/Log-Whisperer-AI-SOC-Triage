import os
import streamlit as st

from groq import Groq
from google import genai
from cerebras.cloud.sdk import Cerebras
import anthropic


# ==========================================
# MODEL NAMES
# Override any of these in st.secrets or env vars without editing code.
# ==========================================

DEFAULT_MODELS = {
    "GROQ_MODEL": "llama-3.3-70b-versatile",
    "GEMINI_MODEL": "gemini-3.8-flash",
    "CEREBRAS_MODEL": "gpt-oss-120b",
    "CLAUDE_MODEL": "claude-sonnet-5-5",
}


# ==========================================
# API KEY / SETTINGS HELPER
# ==========================================

def get_api_key(key_name):
    try:
        api_key = st.secrets.get(key_name)
    except Exception:
        api_key = None

    if not api_key:
        api_key = os.getenv(key_name)

    return api_key.strip() if api_key else None


def get_model(setting_name):
    return get_api_key(setting_name) or DEFAULT_MODELS[setting_name]


def _is_model_not_found(error):
    text = str(error).lower()
    return (
        "404" in text
        or "not_found" in text
        or "model_not_found" in text
        or "does not exist" in text
        or "no longer available" in text
    )


def _pick_from_list(available, preferred_hints, banned=()):
    """Pick the first available model matching a hint, in hint order."""
    available = [
        m for m in available
        if not any(b in m.lower() for b in banned)
    ]
    for hint in preferred_hints:
        for name in available:
            if hint in name.lower():
                return name
    return available[0] if available else None


# ==========================================
# PROVIDER CALLS
# ==========================================

def _call_groq(api_key, system_message, prompt):
    client = Groq(api_key=api_key)

    def run(model):
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        return response.choices[0].message.content

    model = get_model("GROQ_MODEL")
    try:
        text = run(model)
    except Exception as error:
        if not _is_model_not_found(error):
            raise
        available = [m.id for m in client.models.list().data]
        fallback = _pick_from_list(
            available,
            ["llama-3.3-70b", "llama-3.1-70b", "gpt-oss-120b", "llama", "qwen"],
            banned=("whisper", "guard", "tts", "orpheus", "prompt"),
        )
        if not fallback:
            raise
        text = run(fallback)

    return text or "Groq returned an empty response."


def _call_gemini(api_key, system_message, prompt):
    client = genai.Client(api_key=api_key)

    def run(model):
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config={
                "system_instruction": system_message,
                "temperature": 0.3,
                "max_output_tokens": 2000,
            },
        )
        return response.text

    model = get_model("GEMINI_MODEL")
    try:
        text = run(model)
    except Exception as error:
        if not _is_model_not_found(error):
            raise
        available = [
            m.name.replace("models/", "")
            for m in client.models.list()
        ]
        fallback = _pick_from_list(
            [m for m in available if "flash" in m.lower()],
            ["flash"],
            banned=("image", "tts", "live", "audio", "embedding", "lite"),
        )
        if not fallback:
            raise
        text = run(fallback)

    return text or "Gemini returned an empty response."


def _call_cerebras(api_key, system_message, prompt):
    client = Cerebras(api_key=api_key)

    def run(model):
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        return response.choices[0].message.content

    model = get_model("CEREBRAS_MODEL")
    try:
        text = run(model)
    except Exception as error:
        if not _is_model_not_found(error):
            raise
        available = [m.id for m in client.models.list().data]
        fallback = _pick_from_list(
            available,
            ["gpt-oss", "llama", "qwen", "glm"],
        )
        if not fallback:
            raise
        text = run(fallback)

    return text or "Cerebras returned an empty response."


def _call_claude(api_key, system_message, prompt):
    client = anthropic.Anthropic(api_key=api_key)

    # Note: newer Claude models reject the `temperature` parameter,
    # so it is intentionally not sent.
    response = client.messages.create(
        model=get_model("CLAUDE_MODEL"),
        max_tokens=2000,
        system=system_message,
        messages=[{"role": "user", "content": prompt}],
    )

    text = "\n".join(
        block.text for block in response.content if block.type == "text"
    )
    return text or "Claude returned an empty response."


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
        if "Groq" in provider:
            api_key = get_api_key("GROQ_API_KEY")
            if not api_key:
                return "Groq API key missing. Configure GROQ_API_KEY."
            return _call_groq(api_key, system_message, prompt)

        elif "Gemini" in provider:
            api_key = get_api_key("GEMINI_API_KEY")
            if not api_key:
                return "Gemini API key missing. Configure GEMINI_API_KEY."
            return _call_gemini(api_key, system_message, prompt)

        elif "Cerebras" in provider:
            api_key = get_api_key("CEREBRAS_API_KEY")
            if not api_key:
                return "Cerebras API key missing. Configure CEREBRAS_API_KEY."
            return _call_cerebras(api_key, system_message, prompt)

        elif "Claude" in provider:
            api_key = get_api_key("ANTHROPIC_API_KEY")
            if not api_key:
                return "Anthropic API key missing. Configure ANTHROPIC_API_KEY."
            return _call_claude(api_key, system_message, prompt)

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
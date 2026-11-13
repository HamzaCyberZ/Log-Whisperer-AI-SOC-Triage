# 🛡️ Log Whisperer — AI SOC Triage

Hackathon project for FAST-NUCES Peshawar × MLH (21 Nov 2026).

## What it does
1. Paste raw logs (SSH / nginx / k8s).
2. A hybrid detector (Isolation Forest + signature rules) flags suspicious lines.
3. A local LLM (Ollama) writes a human-readable incident report with severity, MITRE ATT&CK hint, timeline, and recommended actions.

## Why it matters
Small teams on cloud-native stacks drown in logs. Enterprise SOC tools are expensive and require a security team. Log Whisperer turns raw logs into a 30-second incident report, fully offline, with zero data leaving the machine.

## Run
```bash
pip install -r requirements.txt
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
docker exec -it ollama ollama pull qwen2.5:3b
streamlit run app.py
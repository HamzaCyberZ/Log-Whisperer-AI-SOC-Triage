# db.py (Supabase version)
import streamlit as st
from supabase import create_client
import hashlib

url = st.secrets["https://supabase.com/dashboard/project/qfjccefmdzoksytqunes"]
key = st.secrets["ESpWiTT0pTYcobqnA7iC3g_vaaXoGyS"]
supabase = create_client(url, key)

def hash_password(password):
    return hashlib.sha256(str(password).strip().encode()).hexdigest()

def register_user(username, password):
    try:
        supabase.table("users").insert({"username": username, "password": hash_password(password)}).execute()
        return True
    except Exception:
        return False

def verify_user(username, password):
    try:
        res = supabase.table("users").select("password").eq("username", username).execute()
        if res.data and res.data[0]["password"] == hash_password(password):
            return True
        return False
    except Exception:
        return False

def save_history(username, total, suspicious, report):
    supabase.table("history").insert({
        "username": username, "total_lines": total, 
        "suspicious_lines": suspicious, "report": report
    }).execute()

def get_history(username):
    res = supabase.table("history").select("*").eq("username", username).order("timestamp", desc=True).execute()
    return [(r["timestamp"], r["total_lines"], r["suspicious_lines"], r["report"]) for r in res.data]
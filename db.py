
import streamlit as st
import hashlib
from supabase import create_client


# ==========================================
# SUPABASE CONNECTION
# ==========================================

@st.cache_resource
def get_supabase_client():
    try:
        url = st.secrets["supabase_url"]
        key = st.secrets["supabase_key"]

        return create_client(url, key)

    except Exception as e:
        st.error(f"Supabase connection error: {e}")
        return None


supabase = get_supabase_client()


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def init_db():
    if supabase is None:
        st.error("Supabase database is not connected.")
        return False

    return True


# ==========================================
# PASSWORD HASHING
# ==========================================

def hash_password(password):
    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


# ==========================================
# USER REGISTRATION
# ==========================================

def register_user(username, password):
    try:
        if supabase is None:
            return False

        username = username.strip()

        if not username or not password:
            return False

        existing = (
            supabase.table("users")
            .select("username")
            .eq("username", username)
            .execute()
        )

        if existing.data:
            return False

        supabase.table("users").insert({
            "username": username,
            "password": hash_password(password)
        }).execute()

        return True

    except Exception as e:
        st.error(f"Registration error: {e}")
        return False


# ==========================================
# USER LOGIN
# ==========================================

def verify_user(username, password):
    try:
        if supabase is None:
            return False

        result = (
            supabase.table("users")
            .select("username")
            .eq("username", username.strip())
            .eq("password", hash_password(password))
            .execute()
        )

        return len(result.data) > 0

    except Exception as e:
        st.error(f"Login error: {e}")
        return False


# ==========================================
# SAVE INCIDENT HISTORY
# ==========================================

def save_history(username, total, suspicious, report):
    try:
        if supabase is None:
            return False

        data = {
            "username": username,
            "logs": str(total),
            "total_lines": int(total),
            "suspicious_lines": int(suspicious),
            "report": str(report)
        }

        supabase.table("history").insert(data).execute()

        return True

    except Exception as e:
        st.error(f"History save error: {e}")
        return False


# ==========================================
# GET USER INCIDENT HISTORY
# ==========================================

def get_history(username):
    try:
        if supabase is None:
            return []

        result = (
            supabase.table("history")
            .select(
                "created_at,total_lines,suspicious_lines,report"
            )
            .eq("username", username)
            .order("created_at", desc=True)
            .execute()
        )

        history_records = []

        for row in result.data:
            history_records.append((
                row.get("created_at", "Unknown"),
                row.get("total_lines", 0),
                row.get("suspicious_lines", 0),
                row.get("report", "")
            ))

        return history_records

    except Exception as e:
        st.error(f"History retrieval error: {e}")
        return []


import streamlit as st
from supabase import create_client
import hashlib


# ==========================================
# SUPABASE CONFIGURATION
# ==========================================

@st.cache_resource
def get_supabase_client():
    url = st.secrets["supabase_url"]
    key = st.secrets["supabase_key"]

    return create_client(url, key)


supabase = get_supabase_client()


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def init_db():
    try:
        return supabase is not None
    except Exception as e:
        st.error(f"Database initialization error: {e}")
        return False


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

def save_history(username, logs, report):
    try:
        supabase.table("history").insert({
            "username": username,
            "logs": logs,
            "report": report
        }).execute()

        return True

    except Exception as e:
        st.error(f"History save error: {e}")
        return False


# ==========================================
# GET USER INCIDENT HISTORY
# ==========================================

def get_history(username):
    try:
        result = (
            supabase.table("history")
            .select("*")
            .eq("username", username)
            .execute()
        )

        return result.data

    except Exception as e:
        st.error(f"History retrieval error: {e}")
        return []

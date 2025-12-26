# app.py
import streamlit as st
import tempfile
import requests
from bs4 import BeautifulSoup
import zipfile
import os

from apk_analysis import analyze_apk
from nlp_risk import compute_privacy_risk
from tracker_analysis import analyze_trackers

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(
    page_title="AppShield – Android Privacy Inspector",
    layout="wide"
)

# ---------------------------------------------------------
# THEME TOGGLE
# ---------------------------------------------------------
theme = st.sidebar.radio("🎨 Theme", ["Dark", "Light"])

if theme == "Dark":
    st.markdown("""
    <style>
    body { background-color: #0e1117; color: white; }
    [data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 10px;
    }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    [data-testid="metric-container"] {
        background-color: #f9f9f9;
        border: 1px solid #ddd;
        padding: 15px;
        border-radius: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------
st.title("🛡️ AppShield")
st.markdown("### AI-Driven Privacy & Security Inspector for Android Applications")

st.write(
    "AppShield is an AI-driven framework for analyzing Android applications "
    "to identify privacy risks by combining static analysis, third-party tracker detection, "
    "NLP-based privacy policy understanding, and runtime behavior monitoring."
)

st.markdown(
    """
    **Core Capabilities**
    - 🔍 Static Permission & APK Analysis  
    - 🌐 Third-Party Tracker Detection  
    - 📜 NLP-Based Privacy Policy Analysis  
    - 📡 Runtime Network Monitoring (Partial)  
    - 📊 Explainable Privacy Risk Scoring  
    """
)

st.divider()

uploaded_apk = st.file_uploader(
    "Upload Android package file (.apk, .apkm, .xapk, .zip)",
    type=None
)

# ---------------------------------------------------------
# HELPER FUNCTION
# ---------------------------------------------------------
def extract_apk_from_bundle(bundle_path):
    try:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            apks = [n for n in zf.namelist() if n.lower().endswith(".apk")]
            if not apks:
                return None

            chosen = next((a for a in apks if os.path.basename(a).lower() == "base.apk"), None)
            if not chosen:
                apks = sorted(apks, key=lambda x: zf.getinfo(x).file_size, reverse=True)
                chosen = apks[0]

            data = zf.read(chosen)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f:
                f.write(data)
                return f.name
    except:
        return None

# ---------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------
if uploaded_apk:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_apk.read())
        bundle_path = tmp.name

    st.success(f"✅ Uploaded: {uploaded_apk.name}")

    if uploaded_apk.name.lower().endswith(".apk"):
        apk_path = bundle_path
    else:
        apk_path = extract_apk_from_bundle(bundle_path)

    if not apk_path:
        st.error("No APK found inside uploaded file.")
        st.stop()

    info = analyze_apk(apk_path)
    tracker_info = analyze_trackers(apk_path)

    # ---------------------------------------------------------
    # DASHBOARD METRICS
    # ---------------------------------------------------------
    st.subheader("📊 Privacy Summary Dashboard")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Permissions", len(info["permissions"]))
    col2.metric("Domains", tracker_info["num_domains"])
    col3.metric("Trackers", tracker_info["num_trackers"])
    col4.metric("Tracker Risk", tracker_info["risk_level"])

    # ---------------------------------------------------------
    # TABS
    # ---------------------------------------------------------
    tab1, tab2, tab3, tab4 = st.tabs(
        ["🔍 Permissions", "🌐 Trackers", "📜 Privacy Policy", "🧠 AI Risk"]
    )

    with tab1:
        st.subheader("Requested Permissions")
        with st.expander("View permissions"):
            for p in info["permissions"]:
                st.write(p)

    with tab2:
        st.subheader("Third-Party Trackers")
        if tracker_info["tracker_domains"]:
            for dom, cat in tracker_info["tracker_domains"].items():
                st.write(f"- `{dom}` ({cat})")
        else:
            st.success("No known tracker domains detected.")

    with tab3:
        st.subheader("Privacy Policy")
        policy_text = ""
        try:
            play_url = f"https://play.google.com/store/apps/details?id={info['package_name']}"
            r = requests.get(play_url, headers={"User-Agent": "Mozilla/5.0"})
            soup = BeautifulSoup(r.text, "lxml")

            link = next((a["href"] for a in soup.find_all("a", href=True)
                         if "privacy" in (a.text or "").lower()), None)

            if link:
                if link.startswith("/"):
                    link = "https://play.google.com" + link

                pr = requests.get(link, headers={"User-Agent": "Mozilla/5.0"})
                ps = BeautifulSoup(pr.text, "lxml")
                for t in ps(["script", "style", "noscript"]):
                    t.extract()

                policy_text = " ".join(ps.get_text().split())
                st.write(policy_text[:2000] + "...")
            else:
                st.warning("Privacy policy not found.")
        except:
            st.warning("Unable to fetch privacy policy.")

    with tab4:
        st.subheader("AI-Based Privacy Risk")
        if policy_text:
            risk = compute_privacy_risk(info["permissions"], policy_text)
            st.metric("Privacy Risk Score", f"{risk['score']} / 100")
            st.write(f"Risk Level: **{risk['level']}**")
            for r in risk["reasons"]:
                st.write(f"- {r}")
        else:
            st.warning("Risk analysis unavailable (no policy text).")

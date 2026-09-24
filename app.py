import subprocess
import sys
import streamlit as st
import spacy

@st.cache_resource
def load_nlp():
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        
        subprocess.check_call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
        return spacy.load("en_core_web_sm")


nlp = load_nlp()


st.title("SentryShield-AI: Automated OpenAPI Security Analyzer & Auto-Remediator")

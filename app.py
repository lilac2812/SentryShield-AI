import streamlit as st
import json
import yaml
import pandas as pd
from datetime import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="SentryShield-AI Security Intelligence Hub", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Professional Custom CSS (Full Cyber Command Center Theme) ---
st.markdown("""
    <style>
        /* Deep Dark Purple Gradient with Embedded Cyber Circuit Background */
        .stApp {
            background: 
                linear-gradient(135deg, rgba(23, 15, 44, 0.94) 0%, rgba(9, 5, 20, 0.98) 100%),
                url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M10 10h80v80H10z' fill='none'/%3E%3Cpath d='M20 0v40h30l10 10h40' stroke='%23a855f7' stroke-width='0.6' stroke-opacity='0.18' fill='none'/%3E%3Cpath d='M0 30h30l20 20v30' stroke='%23c084fc' stroke-width='0.6' stroke-opacity='0.18' fill='none'/%3E%3Ccircle cx='50' cy='50' r='2' fill='%23e9d5ff' fill-opacity='0.3'/%3E%3Ccircle cx='80' cy='30' r='1.5' fill='%23c084fc' fill-opacity='0.3'/%3E%3C/svg%3E"),
                radial-gradient(circle at top left, #3b0764, #170f2c, #090514);
            background-attachment: fixed;
            color: #f3e8ff;
        }
        
        .hero-title { font-size: 2.8rem; font-weight: 700; color: #f3e8ff; letter-spacing: -0.5px; margin: 0; }
        .hero-subtitle { font-size: 1.2rem; color: #d8b4fe; font-weight: 400; margin-top: 5px; }
        
        .section-card { 
            background: rgba(46, 16, 101, 0.5) !important;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 20px; 
            border-radius: 16px; 
            border: 1px solid rgba(168, 85, 247, 0.3) !important; 
            border-top: 3px solid #a855f7 !important;
            margin-bottom: 20px; 
            box-shadow: 0 10px 30px 0 rgba(0, 0, 0, 0.5);
        }
        
        .custom-metric-card {
            background: rgba(46, 16, 101, 0.5) !important;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 16px;
            border-radius: 16px;
            border: 1px solid rgba(168, 85, 247, 0.3) !important;
            border-top: 3px solid #c084fc !important;
            height: 100%;
            box-shadow: 0 8px 25px 0 rgba(0, 0, 0, 0.4);
        }
        .custom-metric-label {
            font-size: 0.85rem;
            color: #d8b4fe;
            font-weight: 600;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .custom-metric-value {
            font-size: 1.4rem;
            color: #f3e8ff;
            font-weight: 700;
            word-break: break-word;
            white-space: normal;
        }
        .vuln-box {

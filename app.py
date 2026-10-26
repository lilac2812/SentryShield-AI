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

# --- Professional Custom CSS (Modern Glass - Dark Purple Theme) ---
st.markdown("""
    <style>
        /* Deep Dark Purple Gradient Background */
        .stApp {
            background: radial-gradient(circle at top left, #2e1065, #170f2c, #090514);
            color: #f3e8ff;
        }
        
        .hero-title { font-size: 2.8rem; font-weight: 700; color: #f3e8ff; letter-spacing: -0.5px; }
        .hero-subtitle { font-size: 1.2rem; color: #d8b4fe; font-weight: 400; }
        
        .section-card { 
            background: rgba(46, 16, 101, 0.45) !important;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 20px; 
            border-radius: 16px; 
            border: 1px solid rgba(168, 85, 247, 0.25) !important; 
            margin-bottom: 20px; 
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        }
        
        .custom-metric-card {
            background: rgba(46, 16, 101, 0.45) !important;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 16px;
            border-radius: 16px;
            border: 1px solid rgba(168, 85, 247, 0.25) !important;
            height: 100%;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
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
            background: rgba(46, 16, 101, 0.45) !important;
            backdrop-filter: blur(12px);
            border: 1px solid rgba(168, 85, 247, 0.25);
            border-left: 5px solid #f85149;
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 14px;
        }
        .vuln-box-med {
            background: rgba(46, 16, 101, 0.45) !important;
            backdrop-filter: blur(12px);
            border: 1px solid rgba(168, 85, 247, 0.25);
            border-left: 5px solid #d29922;
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 14px;
        }
        
        /* Soft Lavender Headings */
        h1, h2, h3 {
            color: #d8b4fe !important;
            font-weight: 700 !important;
        }

        /* Vibrant Violet Gradient Buttons */
        .stButton > button {
            background: linear-gradient(135deg, #7c3aed 0%, #9333ea 100%) !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 10px !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 12px rgba(126, 58, 237, 0.4);
        }
        .stButton > button:hover {
            background: linear-gradient(135deg, #6d28d9 0%, #7e22ce 100%) !important;
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.6) !important;
            transform: translateY(-2px);
        }
    </style>
""", unsafe_allow_html=True)

# --- Initialize Session State ---
if 'step' not in st.session_state:
    st.session_state.step = 'welcome'
if 'scanned_files' not in st.session_state:
    st.session_state.scanned_files = {}
if 'selected_file' not in st.session_state:
    st.session_state.selected_file = ""
if 'messages' not in st.session_state:
    st.session_state.messages = []

# --- Security Analysis & Remediation Engine ---
SENSITIVE_KEYWORDS = ["password", "ssn", "credit_card", "secret", "token", "api_key", "private_key", "auth"]

def analyze_and_remediate(spec_data):
    issues = []
    remediated_spec = json.loads(json.dumps(spec_data))

    paths = spec_data.get("paths", {})
    global_security = spec_data.get("security", [])

    if "components" not in remediated_spec:
        remediated_spec["components"] = {}
    if "securitySchemes" not in remediated_spec["components"]:
        remediated_spec["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }

    for path, path_item in paths.items():
        has_path_params = "{" in path and "}" in path

        for method, details in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue

            endpoint_security = details.get("security", global_security)

            # 1. BOLA / IDOR Detection
            if has_path_params and not endpoint_security:
                issues.append({
                    "severity": "HIGH",
                    "owasp": "API1:2023 - Broken Object Level Authorization",
                    "type": "Broken Object Level Authorization (BOLA / IDOR Risk)",
                    "path": f"{method.upper()} {path}",
                    "details": "This route includes URL parameters (such as IDs), but lacks required authentication checks or authorization guards, allowing unauthorized users to access other records.",
                    "recommendation": "Enforce mandatory JSON Web Token (JWT) Bearer authentication scope on all parameterized route endpoints."
                })
                remediated_spec["paths"][path][method]["security"] = [{"BearerAuth": []}]

            # 2. Sensitive Data Exposure
            responses = details.get("responses", {})
            for code, resp in responses.items():
                schema = resp.get("content", {}).get("application/json", {}).get("schema", {})
                props = schema.get("properties", {})

                for prop_name in props.keys():
                    if any(key in prop_name.lower() for key in SENSITIVE_KEYWORDS):
                        issues.append({
                            "severity": "HIGH",
                            "owasp": "API3:2023 - Broken Object Property Level Authorization",
                            "type": "Sensitive Data Exposure in API Response",
                            "path": f"{method.upper()} {path} (Response Code {code})",
                            "details": f"The response data schema exposes unmasked or unprotected sensitive data property: '{prop_name}'.",
                            "recommendation": "Apply strict property-level masking, omission, or administrative authorization checks before returning sensitive records."
                        })

            # 3. Missing Rate Limits
            if "429" not in responses:
                issues.append({
                    "severity":

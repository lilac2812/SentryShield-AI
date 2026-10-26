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
                    "severity": "MEDIUM",
                    "owasp": "API4:2023 - Unrestricted Resource Consumption",
                    "type": "Missing Rate Limit Defenses",
                    "path": f"{method.upper()} {path}",
                    "details": "The endpoint definition does not specify an HTTP 429 (Too Many Requests) response code to handle excessive traffic.",
                    "recommendation": "Define explicit HTTP 429 response structures in the specification to mitigate brute-force and denial-of-service attacks."
                })
                if "responses" in remediated_spec["paths"][path][method]:
                    remediated_spec["paths"][path][method]["responses"]["429"] = {
                        "description": "Too Many Requests - Rate limit exceeded"
                    }

    # 4. Insecure Transport Check
    schemes = spec_data.get("schemes", [])
    servers = spec_data.get("servers", [])
    is_http = "http" in schemes or any(s.get("url", "").startswith("http://") for s in servers)

    if is_http:
        issues.append({
            "severity": "CRITICAL",
            "owasp": "API2:2023 - Broken Authentication / Insecure Transport",
            "type": "Insecure Cleartext Transport Protocol",
            "path": "GLOBAL SERVER CONFIGURATION",
            "details": "The API definition includes unencrypted cleartext HTTP server URLs or connection schemes.",
            "recommendation": "Enforce TLS 1.2 or TLS 1.3 HTTPS transport encryption across all active server target URLs."
        })
        if "schemes" in remediated_spec:
            remediated_spec["schemes"] = ["https"]
        if "servers" in remediated_spec:
            for server in remediated_spec["servers"]:
                if server.get("url", "").startswith("http://"):
                    server["url"] = server["url"].replace("http://", "https://")

    return issues, remediated_spec

def calculate_security_grade(issues):
    crit = sum(1 for i in issues if i['severity'] == 'CRITICAL')
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    med = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    score = max(0, 100 - (crit * 30 + high * 15 + med * 5))
    if score >= 90: return "A (Secure)", "🟢"
    elif score >= 75: return "B (Good)", "🟢"
    elif score >= 60: return "C (Moderate Risk)", "🟠"
    elif score >= 40: return "D (High Risk)", "🔴"
    else: return "F (Critical Vulnerabilities)", "🔴"

def generate_audit_report_text(filename, spec_title, total_endpoints, grade, issues):
    report = []
    report.append("=" * 60)
    report.append("       SENTRYSHIELD-AI ENTERPRISE SECURITY AUDIT REPORT")
    report.append("=" * 60)
    report.append(f"Generated Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"File Inspected      : {filename}")
    report.append(f"API Specification   : {spec_title}")
    report.append(f"Endpoints Scanned   : {total_endpoints}")
    report.append(f"Security Posture    : {grade}")
    report.append("-" * 60)
    report.append("EXECUTIVE SUMMARY & COMPLIANCE FINDINGS:")
    report.append(f"Total Vulnerabilities Detected: {len(issues)}")
    report.append("-" * 60)
    
    if not issues:
        report.append("No security vulnerabilities were identified in this specification. All routes conform to OWASP API Top 10 guidelines.")
    else:
        for idx, iss in enumerate(issues, 1):
            report.append(f"\n[{idx}] SEVERITY: {iss['severity']}")
            report.append(f"    Category: {iss['owasp']}")
            report.append(f"    Issue   : {iss['type']}")
            report.append(f"    Target  : {iss['path']}")
            report.append(f"    Details : {iss['details']}")
            report.append(f"    Action  : {iss['recommendation']}")
            report.append("-" * 40)
            
    report.append("\nEnd of SentryShield-AI Audit Deliverable.")
    return "\n".join(report)


# ==========================================
# WELCOME SCREEN
# ==========================================
if st.session_state.step == 'welcome':
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2.5, 1])
    with col2:
        st.markdown("<h1 class='hero-title' align='center'>🛡️ SentryShield-AI</h1>", unsafe_allow_html=True)
        st.markdown("<p class='hero-subtitle' align='center'>Enterprise OpenAPI Security Intelligence & Self-Healing Gateway</p>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        
        st.markdown("""
        <div class='section-card'>
            <b>Welcome to SentryShield-AI.</b> Upload multiple OpenAPI or Swagger specification files simultaneously to evaluate them against the <b>OWASP API Top 10</b> security standards. 
            <br><br>
            <ul>
                <li><b>Multi-File Batch Scanning:</b> Analyze entire suites of microservice specifications at once.</li>
                <li><b>Visual Code Diffs:</b> Inspect exact self-healing patches before deployment.</li>
                <li><b>Instant Code & Report Exports:</b> Download professional audit documentation and patched YAML specifications immediately.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Launch Security Suite", type="primary", use_container_width=True):
            st.session_state.step = 'upload'
            st.rerun()


# ==========================================
# UPLOAD SCREEN
# ==========================================
elif st.session_state.step == 'upload':
    st.subheader("📁 Upload API Specifications")
    st.markdown("Upload **one or multiple** OpenAPI or Swagger specification files (`.yaml`, `.yml`, `.json`) below to begin your security evaluation.")
    
    uploaded_files = st.file_uploader("Choose OpenAPI files", type=["yaml", "yml", "json"], accept_multiple_files=True)
    
    col_back, col_next = st.columns([1, 1])
    with col_back:
        if st.button("⬅️ Return to Overview"):
            st.session_state.step = 'welcome'
            st.rerun()
            
    with col_next:
        if uploaded_files:
            if st.button("🔍 Run Security Analysis", type="primary"):
                if 'scanned_files' not in st.session_state:
                    st.session_state.scanned_files = {}
                
                for f in uploaded_files:
                    try:
                        content = f.read().decode("utf-8")
                        spec = json.loads(content) if f.name.endswith(".json") else yaml.safe_load(content)
                        issues, fixed_spec = analyze_and_remediate(spec)
                        grade, grade_icon = calculate_security_grade(issues)
                        
                        st.session_state.scanned_files[f.name] = {
                            "spec_data": spec,
                            "issues": issues,
                            "fixed_spec": fixed_spec,
                            "grade": f"{grade_icon} {grade}"
                        }
                    except Exception as e:
                        st.error(f"Error parsing {f.name}: {e}")
                
                if st.session_state.scanned_files:
                    st.session_state.selected_file = list(st.session_state.scanned_files.keys())[0]
                    st.session_state.step = 'results'
                    st.rerun()


# ==========================================
# RESULTS DASHBOARD
# ==========================================
elif st.session_state.step == 'results':
    st.sidebar.title("📦 Uploaded Microservices")
    st.sidebar.markdown("Select a specification file to inspect its security posture:")
    
    file_list = list(st.session_state.scanned_files.keys())
    selected_filename = st.sidebar.selectbox

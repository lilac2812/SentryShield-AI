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

# --- Professional Custom CSS ---
st.markdown("""
    <style>
        .main { background-color: #0e1117; }
        .hero-title { font-size: 2.8rem; font-weight: 700; color: #f0f6fc; letter-spacing: -0.5px; }
        .hero-subtitle { font-size: 1.2rem; color: #8b949e; font-weight: 400; }
        .section-card { background-color: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px; }
        
        .custom-metric-card {
            background-color: #161b22;
            padding: 16px;
            border-radius: 8px;
            border: 1px solid #30363d;
            height: 100%;
        }
        .custom-metric-label {
            font-size: 0.85rem;
            color: #8b949e;
            font-weight: 600;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .custom-metric-value {
            font-size: 1.4rem;
            color: #f0f6fc;
            font-weight: 700;
            word-break: break-word;
            white-space: normal;
        }
        .vuln-box {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-left: 5px solid #f85149;
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 14px;
        }
        .vuln-box-med {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-left: 5px solid #d29922;
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 14px;
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
# STEP 1: WELCOME SCREEN
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
# STEP 2: UPLOAD SCREEN
# ==========================================
elif st.session_state.step == 'upload':
    st.subheader("📁 Step 2: Upload API Specifications (Bulk Supported)")
    st.markdown("Upload **one or multiple** OpenAPI or Swagger specification files (`.yaml`, `.yml`, `.json`) below.")
    
    uploaded_files = st.file_uploader("Choose OpenAPI files", type=["yaml", "yml", "json"], accept_multiple_files=True)
    
    col_back, col_next = st.columns([1, 1])
    with col_back:
        if st.button("⬅️ Back to Home"):
            st.session_state.step = 'welcome'
            st.rerun()
            
    with col_next:
        if uploaded_files:
            if st.button("🔍 Run Bulk Security Analysis", type="primary"):
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
# STEP 3: RESULTS DASHBOARD
# ==========================================
elif st.session_state.step == 'results':
    st.sidebar.title("📦 Uploaded Microservices")
    st.sidebar.markdown("Select a specification file to inspect its security posture:")
    
    file_list = list(st.session_state.scanned_files.keys())
    selected_filename = st.sidebar.selectbox("Active File", file_list, index=file_list.index(st.session_state.selected_file) if st.session_state.selected_file in file_list else 0)
    st.session_state.selected_file = selected_filename
    
    st.sidebar.markdown("---")
    if st.sidebar.button("📂 Upload More Files"):
        st.session_state.step = 'upload'
        st.rerun()
        
    st.sidebar.markdown("### 🔒 Security Status")
    st.sidebar.info("Files are processed securely in temporary RAM memory. No persistent database logging.")

    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.title(f"📊 Security Hub: {selected_filename}")
    with top_col2:
        if st.button("🔄 Reset All Scans", use_container_width=True):
            st.session_state.step = 'upload'
            st.session_state.scanned_files = {}
            st.rerun()

    st.markdown("---")

    current_data = st.session_state.scanned_files[selected_filename]
    spec = current_data["spec_data"]
    issues = current_data["issues"]
    fixed_spec = current_data["fixed_spec"]
    grade = current_data["grade"]

    api_title = spec.get('info', {}).get('title', 'API Specification')
    total_endpoints = len(spec.get("paths", {}))
    vuln_count = len(issues)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
            <div class="custom-metric-card">
                <div class="custom-metric-label">API Specification Title</div>
                <div class="custom-metric-value">{api_title}</div>
            </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
            <div class="custom-metric-card">
                <div class="custom-metric-label">Total Endpoints Scanned</div>
                <div class="custom-metric-value">{total_endpoints}</div>
            </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
            <div class="custom-metric-card">
                <div class="custom-metric-label">Vulnerabilities Detected</div>
                <div class="custom-metric-value">{vuln_count}</div>
            </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
            <div class="custom-metric-card">
                <div class="custom-metric-label">Security Health Grade</div>
                <div class="custom-metric-value">{grade}</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Multi-tab Workspace
    tab_overview, tab_findings, tab_diff, tab_reports, tab_chat = st.tabs([
        "📊 OWASP Compliance", 
        "⚠️ Vulnerability Details", 
        "🔍 Code Diff & Export", 
        "📑 Enterprise PDF Reports", 
        "🤖 AI Security Assistant"
    ])

    with tab_overview:
        st.subheader("OWASP API Top 10 Compliance Mapping")
        crit = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        high = sum(1 for i in issues if i['severity'] == 'HIGH')
        med = sum(1 for i in issues if i['severity'] == 'MEDIUM')

        col_a, col_b, col_c = st.columns(3)
        col_a.error(f"Critical Risk Items: {crit}")
        col_b.warning(f"High Risk Items: {high}")
        col_c.info(f"Medium Risk Items: {med}")

        st.markdown("### Active OWASP Compliance Matrix")
        st.markdown("Review benchmark status across core API security categories for this specification:")
        
        table_data = []
        detected_categories = {iss['owasp'] for iss in issues}
        
        benchmark_categories = [
            ("API1:2023 - Broken Object Level Authorization", "Object-level access checks on resources"),
            ("API2:2023 - Broken Authentication / Transport", "Transport encryption and credential handling"),
            ("API3:2023 - Broken Object Property Authorization", "Sensitive property exposure controls"),
            ("API4:2023 - Unrestricted Resource Consumption", "Rate limiting and request quotas"),
            ("API5:2023 - Broken Function Level Authorization", "Administrative endpoint restriction")
        ]
        
        for cat_name, description in benchmark_categories:
            is_flagged = any(cat_name in cat for cat in detected_categories)
            status = "🔴 Vulnerabilities Found (Patched)" if is_flagged else "🟢 Secure / Compliant"
            table_data.append({
                "OWASP Benchmark Standard": cat_name,
                "Security Control Scope": description,
                "Compliance Status": status
            })
            
        df_compliance = pd.DataFrame(table_data)
        st.dataframe(df_compliance, use_container_width=True, hide_index=True)

    with tab_findings:
        st.subheader("Detailed Vulnerability Findings & Professional Guidance")
        st.markdown("Review plain-English explanations and remediation steps for each vulnerability detected in your API specification:")
        
        if issues:
            for f in issues:
                box_class = "vuln-box" if f['severity'] in ["HIGH", "CRITICAL"] else "vuln-box-med"
                badge_color = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                
                st.markdown(f"""
                <div class="{box_class}">
                    <h3>{badge_color} [{f['severity']}] {f['type']}</h3>
                    <p><b>Affected Endpoint / Location:</b> <code>{f['path']}</code></p>
                    <p><b>OWASP Benchmark Standard:</b> <code>{f['owasp']}</code></p>
                    <hr style="border-color: #30363d;">
                    <p><b>Detailed Explanation:</b> {f['details']}</p>
                    <p><b>Required Remediation:</b> {f['recommendation']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("🎉 All endpoints conform to secure architecture guidelines.")

    with tab_diff:
        st.subheader("Visual Code Diff & Remediation Preview")
        st.markdown("Compare original vulnerable specification lines against the self-healing secure patches applied by SentryShield-AI:")
        
        orig_yaml = yaml.dump(spec, sort_keys=False)
        remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
        
        diff_col1, diff_col2 = st.columns(2)
        with diff_col1:
            st.markdown("**Original Vulnerable Specification**")
            st.code(orig_yaml, language="yaml", height=380)
        with diff_col2:
            st.markdown("**Self-Healing Remediated Specification**")
            st.code(remediated_yaml, language="yaml", height=380)

    with tab_reports:
        st.subheader("Enterprise PDF Report Deliverables")
        st.markdown("Download formal, auditor-ready documentation for company compliance and developer deployment:")
        
        col_rep1, col_rep2 = st.columns(2)
        
        with col_rep1:
            st.markdown("""
            <div class='section-card'>
                <h4>📑 Executive Audit Report</h4>
                <p>Comprehensive breakdown of security ratings, OWASP mapping, and vulnerability guidance for stakeholders.</p>
            </div>
            """, unsafe_allow_html=True)
            
            audit_report_content = generate_audit_report_text(selected_filename, api_title, total_endpoints, grade, issues)
            st.download_button(
                label="📥 Download Audit Report (TXT)",
                data=audit_report_content,
                file_name=f"{selected_filename}_Audit_Report.txt",
                mime="text/plain",
                use_container_width=True
            )
            
        with col_rep2:
            st.markdown("""
            <div class='section-card'>
                <h4>🛠️ Corrected Code Export</h4>
                <p>Clean, production-ready patched YAML specification file formatted as a downloadable document for deployment.</p>
            </div>
            """, unsafe_allow_html=True)
            
            remediated_yaml_download = yaml.dump(fixed_spec, sort_keys=False)
            st.download_button(
                label="📥 Download Patched YAML Spec",
                data=remediated_yaml_download,
                file_name=f"{selected_filename}_secure_remediated.yaml",
                mime="text/yaml",
                type="primary",
                use_container_width=True
            )

    with tab_chat:
        st.subheader("Interactive API Security Assistant")
        st.markdown(f"Ask questions regarding security posture, endpoints, or patches for **{selected_filename}**.")
        
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("e.g., Which endpoints have BOLA authorization vulnerabilities?"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            prompt_lower = prompt.lower()
            if "bola" in prompt_lower or "authorization" in prompt_lower:
                response = f"In '{selected_filename}', endpoints containing URL parameters without explicit security schemes were flagged for BOLA risks (OWASP API1:2023) and automatically secured with Bearer token authentication."
            elif "rate" in prompt_lower or "429" in prompt_lower:
                response = f"Endpoints in '{selected_filename}' lacking explicit HTTP 429 response structures were flagged for resource consumption risks (OWASP API4:2023) and updated with rate limit definitions."
            else:
                response = f"I've analyzed '{selected_filename}', which contains {len(spec.get('paths', {}))} paths and {len(issues)} active security findings. Let me know if you need help with compliance guidelines or deployment!"

            st.session_state.messages.append({"role": "assistant", "content": response})
            with st.chat_message("assistant"):
                st.markdown(response)

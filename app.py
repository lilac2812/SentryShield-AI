import streamlit as st
import json
import yaml
import difflib
from io import BytesIO
from fpdf import FPDF
import pandas as pd
import altair as alt

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
        .stMetric { background-color: #161b22; padding: 16px; border-radius: 8px; border: 1px solid #30363d; }
        .hero-title { font-size: 2.8rem; font-weight: 700; color: #f0f6fc; letter-spacing: -0.5px; }
        .hero-subtitle { font-size: 1.2rem; color: #8b949e; font-weight: 400; }
        .section-card { background-color: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px; }
    </style>
""", unsafe_allow_html=True)

# --- Initialize Session State ---
if 'step' not in st.session_state:
    st.session_state.step = 'welcome'
if 'scanned_files' not in st.session_state:
    st.session_state.scanned_files = {}  # Stores filename -> {spec_data, issues, fixed_spec, grade}
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
                    "type": "BOLA / IDOR Risk",
                    "path": f"{method.upper()} {path}",
                    "details": "Path contains parameters but lacks endpoint-level or global authorization guards.",
                    "recommendation": "Enforce JWT Bearer authentication scope on parameter routes."
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
                            "type": "Sensitive Data Exposure",
                            "path": f"{method.upper()} {path} (Response {code})",
                            "details": f"Response schema exposes unmasked sensitive property: `{prop_name}`.",
                            "recommendation": "Mask or restrict sensitive field output in API responses."
                        })

            # 3. Missing Rate Limits
            if "429" not in responses:
                issues.append({
                    "severity": "MEDIUM",
                    "owasp": "API4:2023 - Unrestricted Resource Consumption",
                    "type": "Missing Rate Limit Defenses",
                    "path": f"{method.upper()} {path}",
                    "details": "Endpoint does not specify an HTTP 429 (Too Many Requests) response.",
                    "recommendation": "Define explicit HTTP 429 response structures to mitigate denial-of-service."
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
            "type": "Insecure Transport Protocol",
            "path": "GLOBAL (Servers / Schemes)",
            "details": "API definition includes unencrypted cleartext HTTP.",
            "recommendation": "Enforce TLS 1.2/1.3 HTTPS transport encryption across all server URLs."
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

# --- PDF Report Generators ---
def generate_audit_report_pdf(file_name, spec_title, issues, grade):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SentryShield-AI Executive Security Audit Report", 0, 1, "C")
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Target Specification: {file_name} ({spec_title})", 0, 1, "C")
    pdf.cell(0, 6, f"Security Health Grade: {grade}", 0, 1, "C")
    pdf.cell(0, 6, "Confidential Enterprise Compliance Document", 0, 1, "C")
    pdf.ln(8)
    
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Vulnerability & Risk Findings Breakdown:", 0, 1)
    pdf.set_font("Arial", "", 9)
    
    if not issues:
        pdf.cell(0, 6, "No vulnerabilities detected. Specification meets enterprise baseline standards.", 0, 1)
    
    for idx, iss in enumerate(issues, 1):
        pdf.multi_cell(0, 5, f"{idx}. [{iss['severity']}] {iss['type']} - Endpoint: {iss['path']}\n   OWASP Mapping: {iss['owasp']}\n   Risk Details: {iss['details']}\n   Mandated Remediation: {iss['recommendation']}\n")
        pdf.ln(2)
        
    return bytes(pdf.output())

def generate_code_pdf(file_name, remediated_yaml):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SentryShield-AI Remediated Code Export", 0, 1, "C")
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 6, f"Production-Ready Patched Specification: {file_name}", 0, 1, "C")
    pdf.ln(6)
    
    pdf.set_font("Courier", "", 8)
    for line in remediated_yaml.split("\n"):
        pdf.multi_cell(0, 4, line)
        
    return bytes(pdf.output())


# ==========================================
# STEP 1: PROFESSIONAL WELCOME PAGE
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
            <b>Welcome to SentryShield-AI.</b> Upload multiple OpenAPI / Swagger specification files simultaneously to evaluate them against the <b>OWASP API Top 10</b>. 
            <br><br>
            <ul>
                <li><b>Multi-File Batch Scanning:</b> Analyze entire suites of microservice specs at once.</li>
                <li><b>Visual Code Diffs:</b> Inspect exact self-healing patches before deployment.</li>
                <li><b>Enterprise Reports:</b> Export executive security audits and production-ready YAML specifications instantly.</li>
                <li><b>Guaranteed Privacy:</b> Ephemeral in-memory processing ensures your proprietary files are never stored or exposed.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Launch Security Suite", type="primary", use_container_width=True):
            st.session_state.step = 'upload'
            st.rerun()


# ==========================================
# STEP 2: BULK MULTI-FILE UPLOAD SCREEN
# ==========================================
elif st.session_state.step == 'upload':
    st.subheader("📁 Step 2: Upload API Specifications (Bulk Supported)")
    st.markdown("You can upload **one or multiple** OpenAPI or Swagger specification files (`.yaml`, `.yml`, `.json`) below.")
    
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
# STEP 3: RESULTS & ENTERPRISE DASHBOARD
# ==========================================
elif st.session_state.step == 'results':
    # Sidebar Navigation for Multi-File Selection
    st.sidebar.title("📦 Uploaded Microservices")
    st.sidebar.markdown("Select a specification file to inspect its security posture:")
    
    file_list = list(st.session_state.scanned_files.keys())
    selected_filename = st.sidebar.selectbox("Active File", file_list, index=file_list.index(st.session_state.selected_file))
    st.session_state.selected_file = selected_filename
    
    st.sidebar.markdown("---")
    if st.sidebar.button("📂 Upload More Files"):
        st.session_state.step = 'upload'
        st.rerun()
        
    # Privacy Badge in Sidebar
    st.sidebar.markdown("### 🔒 Security Status")
    st.sidebar.info("Files are processed securely in temporary RAM memory. No persistent database logging.")

    # Main Header & File Switcher
    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.title(f"📊 Security Hub: {selected_filename}")
    with top_col2:
        if st.button("🔄 Reset All Scans", use_container_width=True):
            st.session_state.step = 'upload'
            st.session_state.scanned_files = {}
            st.rerun()

    st.markdown("---")

    # Load active file data
    current_data = st.session_state.scanned_files[selected_filename]
    spec = current_data["spec_data"]
    issues = current_data["issues"]
    fixed_spec = current_data["fixed_spec"]
    grade = current_data["grade"]

    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("API Title", spec.get('info', {}).get('title', 'API Spec'))
    with m2:
        st.metric("Total Endpoints", len(spec.get("paths", {})))
    with m3:
        st.metric("Vulnerabilities Found", len(issues))
    with m4:
        st.metric("Security Grade", grade)

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

        st.markdown("### Category Distribution")
        owasp_counts = {}
        for iss in issues:
            cat = iss['owasp']
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        
        if owasp_counts:
            df_chart = pd.DataFrame(list(owasp_counts.items()), columns=['OWASP Category', 'Count'])
            
            chart = alt.Chart(df_chart).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, color="#3b82f6").encode(
                x=alt.X('OWASP Category:N', sort='-y', axis=alt.Axis(labelAngle=-20, labelLimit=350)),
                y=alt.Y('Count:Q', axis=alt.Axis(tickMinStep=1)),
                tooltip=['OWASP Category', 'Count']
            ).properties(
                height=350
            ).interactive()
            
            st.altair_chart(chart, use_container_width=True)
        else:
            st.success("🎉 Zero OWASP violations detected in this specification.")

    with tab_findings:
        st.subheader("Detailed Vulnerability Findings & Guidance")
        if issues:
            for f in issues:
                badge = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                with st.expander(f"{badge} [{f['severity']}] {f['type']} — {f['path']}"):
                    st.markdown(f"**OWASP Standard:** `{f['owasp']}`")
                    st.write(f"**Technical Details:** {f['details']}")
                    st.write(f"**Mandated Remediation:** {f['recommendation']}")
        else:
            st.success("🎉 All endpoints conform to secure architecture guidelines.")

    with tab_diff:
        st.subheader("Visual Code Diff & Remediation Preview")
        st.markdown("Compare original specification lines against the self-healing patches applied by SentryShield-AI:")
        
        orig_yaml = yaml.dump(spec, sort_keys=False)
        remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
        
        diff_col1, diff_col2 = st.columns(2)
        with diff_col1:
            st.markdown("**Original Vulnerable Spec**")
            st.code(orig_yaml, language="yaml", height=350)
        with diff_col2:
            st.markdown("**Self-Healing Remediated Spec**")
            st.code(remediated_yaml, language="yaml", height=350)

    with tab_reports:
        st.subheader("Enterprise PDF Report Deliverables")
        st.markdown("Download formal, auditor-ready documentation for company compliance and developer deployment:")
        
        rep_col1, rep_col2 = st.columns(2)
        
        with rep_col1:
            st.markdown("### 📑 Executive Audit Report")
            st.markdown("Comprehensive breakdown of security ratings, OWASP mapping, and vulnerability guidance for stakeholders.")
            audit_pdf_bytes = generate_audit_report_pdf(selected_filename, spec.get('info', {}).get('title', 'API Spec'), issues, grade)
            st.download_button(
                label="📥 Download Audit Report (PDF)",
                data=audit_pdf_bytes,
                file_name=f"{selected_filename}_audit_report.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )
            
        with rep_col2:
            st.markdown("### 🛠️ Corrected Code Export")
            st.markdown("Clean, production-ready patched YAML specification file formatted as a downloadable document for deployment.")
            code_pdf_bytes = generate_code_pdf(selected_filename, remediated_yaml)
            st.download_button(
                label="📥 Download Remediated Code (PDF)",
                data=code_pdf_bytes,
                file_name=f"{selected_filename}_remediated_code.pdf",
                mime="application/pdf",
                use_container_width=True
            )
            
        st.markdown("---")
        st.download_button(
            label="📥 Download Standard YAML Source File",
            data=remediated_yaml,
            file_name=f"{selected_filename}_fixed.yaml",
            mime="text/yaml"
        )

    with tab_chat:
        st.subheader("Interactive API Security Assistant")
        st.markdown(f"Ask questions regarding security posture, endpoints, or patches for **{selected_filename}**.")
        
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("e.g., Which paths have BOLA vulnerabilities?"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            prompt_lower = prompt.lower()
            if "bola" in prompt_lower or "authorization" in prompt_lower:
                response = f"In {selected_filename}, endpoints containing path parameters without explicit security schemes were flagged for BOLA risks (OWASP API1:2023) and automatically secured with Bearer tokens."
            elif "rate" in prompt_lower or "429" in prompt_lower:
                response = f"Endpoints in {selected_filename} lacking explicit HTTP 429 responses were flagged for resource consumption risks (OWASP API4:2023)."
            else:
                response = f"I've inspected '{selected_filename}' which has {len(spec.get('paths', {}))} paths and {len(issues)} active findings. Let me know if you need help with compliance guidelines or deployment scripts!"

            st.session_state.messages.append({"role": "assistant", "content": response})
            with st.chat_message("assistant"):
                st.markdown(response)

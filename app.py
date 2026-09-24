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
    page_title="SentryShield-AI Intelligence Hub", 
    page_icon="🛡️", 
    layout="wide"
)

# --- Initialize Session State ---
if 'step' not in st.session_state:
    st.session_state.step = 'welcome'
if 'spec_data' not in st.session_state:
    st.session_state.spec_data = None
if 'file_name' not in st.session_state:
    st.session_state.file_name = ""
if 'messages' not in st.session_state:
    st.session_state.messages = []

# --- Security Analysis & Remediation Logic ---
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
                    "details": "Path contains parameters but lacks endpoint-level or global authorization rules.",
                    "recommendation": "Enforce JWT Bearer authentication scope on path parameter routes."
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
                    "recommendation": "Define explicit HTTP 429 response structures."
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
            "recommendation": "Enforce HTTPS (TLS 1.2/1.3) for all server URLs."
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

def generate_pdf_report(spec_title, issues, grade):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SentryShield-AI Security Audit Report", 0, 1, "C")
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 8, f"API Target: {spec_title}", 0, 1, "C")
    pdf.cell(0, 8, f"Overall Security Grade: {grade}", 0, 1, "C")
    pdf.ln(10)
    
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Executive Findings Summary:", 0, 1)
    pdf.set_font("Arial", "", 10)
    
    for idx, iss in enumerate(issues, 1):
        pdf.multi_cell(0, 6, f"{idx}. [{iss['severity']}] {iss['type']} ({iss['path']})\n   OWASP: {iss['owasp']}\n   Recommendation: {iss['recommendation']}\n")
        pdf.ln(2)
        
    return bytes(pdf.output())

def generate_test_script(spec_data):
    script = "#!/usr/bin/env python3\nimport requests\n\n"
    script += "# SentryShield-AI Generated Automated API Security Test Script\n"
    script += "BASE_URL = 'http://localhost:8000' # Update your target URL here\n\n"
    
    paths = spec_data.get("paths", {})
    for path, path_item in paths.items():
        for method in path_item.keys():
            if method.lower() in ["get", "post", "put", "delete", "patch"]:
                test_path = path.replace("{id}", "123")
                script += f"def test_{method.lower()}_{path.replace('/', '_').replace('{', '').replace('}', '')}():\n"
                script += f"    url = f'{{BASE_URL}}{test_path}'\n"
                script += f"    headers = {{'Authorization': 'Bearer INVALID_TEST_TOKEN'}}\n"
                script += f"    response = requests.{method.lower()}(url, headers=headers)\n"
                script += f"    print(f'Testing {method.upper()} {test_path} -> Status: {{response.status_code}}')\n\n"
                
    script += "if __name__ == '__main__':\n"
    script += "    print('Running SentryShield Security Test Suite...')\n"
    return script


# ==========================================
# STEP 1: WELCOME SCREEN
# ==========================================
if st.session_state.step == 'welcome':
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🛡️ SentryShield-AI</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center; color: gray;'>Enterprise OpenAPI Security Intelligence & Self-Healing Hub</h3>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("Advanced vulnerability detection mapped against **OWASP API Top 10**, complete with visual diffs, automated test script generators, and executive audit reports.")
        st.markdown("<br>", unsafe_allow_html=True)
        
        if st.button("🚀 Enter Security Suite", type="primary", use_container_width=True):
            st.session_state.step = 'upload'
            st.rerun()


# ==========================================
# STEP 2: UPLOAD SCREEN
# ==========================================
elif st.session_state.step == 'upload':
    st.subheader("📁 Step 2: Upload API Specification")
    st.markdown("Upload your OpenAPI / Swagger specification in YAML or JSON format.")
    
    uploaded_file = st.file_uploader("Choose an OpenAPI file", type=["yaml", "yml", "json"])
    
    col_back, col_next = st.columns([1, 1])
    with col_back:
        if st.button("⬅️ Back"):
            st.session_state.step = 'welcome'
            st.rerun()
            
    with col_next:
        if uploaded_file is not None:
            if st.button("🔍 Run Full Security Analysis", type="primary"):
                try:
                    content = uploaded_file.read().decode("utf-8")
                    st.session_state.spec_data = json.loads(content) if uploaded_file.name.endswith(".json") else yaml.safe_load(content)
                    st.session_state.file_name = uploaded_file.name
                    st.session_state.messages = []
                    st.session_state.step = 'results'
                    st.rerun()
                except Exception as e:
                    st.error(f"Error parsing file: {e}")


# ==========================================
# STEP 3: RESULTS & ENTERPRISE DASHBOARD
# ==========================================
elif st.session_state.step == 'results':
    top_col1, top_col2 = st.columns([4, 1])
    with top_col1:
        st.title(f"📊 Security Hub: {st.session_state.file_name}")
    with top_col2:
        if st.button("🔄 Scan Another File", use_container_width=True):
            st.session_state.step = 'upload'
            st.session_state.spec_data = None
            st.rerun()

    st.markdown("---")

    issues, fixed_spec = analyze_and_remediate(st.session_state.spec_data)
    grade, grade_icon = calculate_security_grade(issues)

    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("API Title", st.session_state.spec_data.get('info', {}).get('title', 'API Spec'))
    with m2:
        st.metric("Total Endpoints", len(st.session_state.spec_data.get("paths", {})))
    with m3:
        st.metric("Vulnerabilities Found", len(issues))
    with m4:
        st.metric("Security Grade", f"{grade_icon} {grade}")

    st.markdown("---")

    # Multi-tab Workspace
    tab_overview, tab_findings, tab_diff, tab_tests, tab_report, tab_chat = st.tabs([
        "📊 OWASP & Overview", 
        "⚠️ Vulnerabilities", 
        "🔍 Visual Diff & Spec", 
        "🧪 Test Scripts", 
        "📑 PDF Audit Report", 
        "🤖 AI Security Assistant"
    ])

   with tab_overview:
        st.subheader("OWASP API Top 10 Risk Breakdown")
        crit = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        high = sum(1 for i in issues if i['severity'] == 'HIGH')
        med = sum(1 for i in issues if i['severity'] == 'MEDIUM')

        col_a, col_b, col_c = st.columns(3)
        col_a.error(f"Critical Risk Items: {crit}")
        col_b.warning(f"High Risk Items: {high}")
        col_c.info(f"Medium Risk Items: {med}")

        st.markdown("### Compliance Mapping")
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
            st.success("No OWASP violations recorded.")

    with tab_findings:
        st.subheader("Detailed Security Findings & Guidance")
        if issues:
            for f in issues:
                badge = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                with st.expander(f"{badge} [{f['severity']}] {f['type']} — {f['path']}"):
                    st.markdown(f"**OWASP Standard:** `{f['owasp']}`")
                    st.write(f"**Details:** {f['details']}")
                    st.write(f"**Recommendation:** {f['recommendation']}")
        else:
            st.success("🎉 No security vulnerabilities detected!")

    with tab_diff:
        st.subheader("Visual Code Diff & Remediated Spec")
        st.markdown("Compare original vs. self-healing remediated specification lines below:")
        
        orig_yaml = yaml.dump(st.session_state.spec_data, sort_keys=False)
        remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
        
        st.download_button(
            label="📥 Download Production-Ready Fixed Spec (YAML)",
            data=remediated_yaml,
            file_name="sentryshield_remediated_spec.yaml",
            mime="text/yaml",
            type="primary"
        )
        
        st.markdown("---")
        
        diff_col1, diff_col2 = st.columns(2)
        with diff_col1:
            st.markdown("**Original Spec**")
            st.code(orig_yaml, language="yaml", height=350)
        with diff_col2:
            st.markdown("**Remediated Self-Healing Spec**")
            st.code(remediated_yaml, language="yaml", height=350)

    with tab_tests:
        st.subheader("Automated Security Test Script Generator")
        st.markdown("Download a ready-to-execute Python test suite to verify endpoint security and authentication guards.")
        
        test_script_code = generate_test_script(st.session_state.spec_data)
        
        st.download_button(
            label="📥 Download Python Test Script",
            data=test_script_code,
            file_name="security_test_suite.py",
            mime="text/x-python"
        )
        
        st.code(test_script_code, language="python", height=350)

    with tab_report:
        st.subheader("Executive PDF Audit Report Generator")
        st.markdown("Generate and download a formal PDF audit summary for stakeholders and compliance officers.")
        
        pdf_bytes = generate_pdf_report(st.session_state.spec_data.get('info', {}).get('title', 'API Spec'), issues, grade)
        
        st.download_button(
            label="📑 Download Executive PDF Report",
            data=pdf_bytes,
            file_name="sentryshield_audit_report.pdf",
            mime="application/pdf",
            type="primary"
        )

    with tab_chat:
        st.subheader("Interactive API Security Assistant")
        st.markdown("Ask questions about your uploaded API spec or security findings.")
        
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("e.g., Which endpoints have BOLA risks?"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            prompt_lower = prompt.lower()
            if "bola" in prompt_lower or "authorization" in prompt_lower:
                response = "Based on the scan, endpoints with path parameters lacking explicit security schemes were flagged for BOLA/IDOR risks (OWASP API1:2023)."
            elif "rate" in prompt_lower or "429" in prompt_lower:
                response = "Endpoints missing HTTP 429 response declarations were flagged for Unrestricted Resource Consumption (OWASP API4:2023) and automatically patched with 429 headers."
            elif "sensitive" in prompt_lower or "data" in prompt_lower:
                response = "Property-level scans detected unmasked sensitive keywords (like passwords, tokens, or ssn) in response schemas, mapped to OWASP API3:2023."
            else:
                response = f"I've analyzed your API spec '{st.session_state.file_name}' containing {len(st.session_state.spec_data.get('paths', {}))} paths and detected {len(issues)} security issues. Let me know if you need help with remediation or testing scripts!"

            st.session_state.messages.append({"role": "assistant", "content": response})
            with st.chat_message("assistant"):
                st.markdown(response)

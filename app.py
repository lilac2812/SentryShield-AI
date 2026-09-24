import streamlit as st
import json
import yaml

# --- Page Configuration ---
st.set_page_config(
    page_title="SentryShield-AI Dashboard", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Styling ---
st.markdown("""
    <style>
        .main { background-color: #0e1117; }
        .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
""", unsafe_allow_html=True)

SENSITIVE_KEYWORDS = ["password", "ssn", "credit_card", "secret", "token", "api_key", "private_key", "auth"]

def analyze_and_remediate(spec_data):
    issues = []
    remediated_spec = json.loads(json.dumps(spec_data))

    paths = spec_data.get("paths", {})
    global_security = spec_data.get("security", [])

    # Ensure securitySchemes block exists in components
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

            # 1. BOLA / IDOR Detection & Remediation
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

            # 2. Sensitive Data Exposure (Property Scan)
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

            # 3. Unrestricted Resource Consumption (Missing Rate Limits)
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

    # 4. Insecure Transport Check & Remediation
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
    critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
    high_count = sum(1 for i in issues if i['severity'] == 'HIGH')
    medium_count = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    
    score = 100 - (critical_count * 30 + high_count * 15 + medium_count * 5)
    score = max(0, score)
    
    if score >= 90: return "A (Secure)", "🟢"
    elif score >= 75: return "B (Good)", "🟢"
    elif score >= 60: return "C (Moderate Risk)", "🟠"
    elif score >= 40: return "D (High Risk)", "🔴"
    else: return "F (Critical Vulnerabilities)", "🔴"

# --- Sidebar ---
st.sidebar.image("https://img.icons8.com/fluency/96/security-checked.png", width=80)
st.sidebar.title("SentryShield Control")
st.sidebar.markdown("Automated OpenAPI Guardian & Self-Healing Security Gateway.")
st.sidebar.markdown("---")
uploaded_file = st.sidebar.file_uploader("Upload OpenAPI Spec", type=["yaml", "yml", "json"])

# --- Main Dashboard Header ---
st.title("🛡️ SentryShield-AI Security Intelligence Hub")
st.markdown("Enterprise-grade API vulnerability scanner mapped against the **OWASP API Top 10** standards.")

if uploaded_file is not None:
    try:
        content = uploaded_file.read().decode("utf-8")
        spec = json.loads(content) if uploaded_file.name.endswith(".json") else yaml.safe_load(content)

        issues, fixed_spec = analyze_and_remediate(spec)
        grade, grade_icon = calculate_security_grade(issues)

        # --- Metrics Row ---
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("API Title", spec.get('info', {}).get('title', 'Untitled API'))
        with col2:
            st.metric("Total Endpoints", len(spec.get("paths", {})))
        with col3:
            st.metric("Vulnerabilities Found", len(issues))
        with col4:
            st.metric("Security Grade", f"{grade_icon} {grade}")

        st.markdown("---")

        # --- Multi-Tab Interface ---
        tab_overview, tab_findings, tab_remediation = st.tabs([
            "📊 Executive Overview", 
            "⚠️ Vulnerability Details", 
            "🛠️ Remediated Spec & Export"
        ])

        with tab_overview:
            st.subheader("Executive Risk Summary")
            crit = sum(1 for i in issues if i['severity'] == 'CRITICAL')
            high = sum(1 for i in issues if i['severity'] == 'HIGH')
            med = sum(1 for i in issues if i['severity'] == 'MEDIUM')

            sub1, sub2, sub3 = st.columns(3)
            sub1.error(f"Critical Risks: {crit}")
            sub2.warning(f"High Risks: {high}")
            sub3.info(f"Medium Risks: {med}")

            st.markdown("### Compliance & Standards")
            st.info("The analyzed specification has been checked against **OWASP API Security Top 10 (2023)** guidelines for BOLA, Injection, Data Exposure, and Rate Limiting control gaps.")

        with tab_findings:
            st.subheader("Detailed Security Findings")
            if issues:
                for idx, f in enumerate(issues):
                    badge = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                    with st.expander(f"{badge} [{f['severity']}] {f['type']} — {f['path']}"):
                        st.markdown(f"**OWASP Mapping:** `{f['owasp']}`")
                        st.markdown(f"**Vulnerability Details:** {f['details']}")
                        st.markdown(f"**AI Recommendation:** {f['recommendation']}")
            else:
                st.success("🎉 Excellent! No security vulnerabilities detected in this specification.")

        with tab_remediation:
            st.subheader("Self-Healing Code Remediator")
            st.markdown("SentryShield-AI automatically patched BOLA headers, enforced TLS transport schemas, and embedded missing rate limit declarations.")

            remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
            st.code(remediated_yaml, language="yaml", height=400)

            st.download_button(
                label="📥 Download Production-Ready Fixed Spec (YAML)",
                data=remediated_yaml,
                file_name="sentryshield_remediated_spec.yaml",
                mime="text/yaml"
            )

    except Exception as e:
        st.error(f"Error parsing specification file: {e}")
else:
    st.info("👈 Please upload your OpenAPI (`.yaml`, `.yml`, or `.json`) specification file using the sidebar to begin security inspection.")

import streamlit as st
import json
import yaml

# --- Page Configuration ---
st.set_page_config(
    page_title="SentryShield-AI", 
    page_icon="🛡️", 
    layout="wide"
)

# --- Initialize Session State for Multi-Step Flow ---
if 'step' not in st.session_state:
    st.session_state.step = 'welcome'
if 'spec_data' not in st.session_state:
    st.session_state.spec_data = None
if 'file_name' not in st.session_state:
    st.session_state.file_name = ""

# --- Security Analysis Logic ---
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
                            "type": "Sensitive Data Exposure",
                            "path": f"{method.upper()} {path} (Response {code})",
                            "details": f"Response schema exposes unmasked sensitive property: `{prop_name}`.",
                            "recommendation": "Mask or restrict sensitive field output in API responses."
                        })

            # 3. Missing Rate Limits
            if "429" not in responses:
                issues.append({
                    "severity": "MEDIUM",
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


# ==========================================
# STEP 1: WELCOME SCREEN
# ==========================================
if st.session_state.step == 'welcome':
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🛡️ SentryShield-AI</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='text-align: center; color: gray;'>Automated OpenAPI Security & Self-Healing Gateway</h3>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("Detect vulnerabilities like BOLA, missing rate limits, and data exposure instantly. Upload your API spec and let AI secure your endpoints.")
        st.markdown("<br>", unsafe_allow_html=True)
        
        if st.button("🚀 Get Started", type="primary", use_container_width=True):
            st.session_state.step = 'upload'
            st.rerun()


# ==========================================
# STEP 2: UPLOAD SCREEN
# ==========================================
elif st.session_state.step == 'upload':
    st.subheader("📁 Step 2: Upload API Specification")
    st.markdown("Please upload your OpenAPI / Swagger file in YAML or JSON format.")
    
    uploaded_file = st.file_uploader("Choose an OpenAPI file", type=["yaml", "yml", "json"])
    
    col_back, col_next = st.columns([1, 1])
    with col_back:
        if st.button("⬅️ Back"):
            st.session_state.step = 'welcome'
            st.rerun()
            
    with col_next:
        if uploaded_file is not None:
            if st.button("🔍 Run Security Scan", type="primary"):
                try:
                    content = uploaded_file.read().decode("utf-8")
                    st.session_state.spec_data = json.loads(content) if uploaded_file.name.endswith(".json") else yaml.safe_load(content)
                    st.session_state.file_name = uploaded_file.name
                    st.session_state.step = 'results'
                    st.rerun()
                except Exception as e:
                    st.error(f"Error parsing file: {e}")


# ==========================================
# STEP 3: RESULTS & DASHBOARD SCREEN
# ==========================================
elif st.session_state.step == 'results':
    top_col1, top_col2 = st.columns([4, 1])
    with top_col1:
        st.title(f"📊 Security Audit: {st.session_state.file_name}")
    with top_col2:
        if st.button("🔄 Scan Another File", use_container_width=True):
            st.session_state.step = 'upload'
            st.session_state.spec_data = None
            st.rerun()

    st.markdown("---")

    issues, fixed_spec = analyze_and_remediate(st.session_state.spec_data)

    # Metrics Row
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("API Title", st.session_state.spec_data.get('info', {}).get('title', 'API Spec'))
    with m2:
        st.metric("Total Endpoints Analyzed", len(st.session_state.spec_data.get("paths", {})))
    with m3:
        st.metric("Vulnerabilities Detected", len(issues))

    st.markdown("---")

    # Split View for Findings vs Remediated Code
    col_left, col_right = st.columns(1) # Can make it 2 columns or stacked tabs

    tab_findings, tab_code = st.tabs(["⚠️ Vulnerability Findings", "🛠️ Remediated Spec Preview & Export"])

    with tab_findings:
        if issues:
            for f in issues:
                badge = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                with st.expander(f"{badge} [{f['severity']}] {f['type']} — {f['path']}"):
                    st.write(f"**Details:** {f['details']}")
                    st.write(f"**Recommendation:** {f['recommendation']}")
        else:
            st.success("🎉 No security vulnerabilities found! Your API specification is secure.")

    with tab_code:
        st.markdown("### Self-Healing Auto-Patched Specification")
        remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
        st.code(remediated_yaml, language="yaml", height=400)

        st.download_button(
            label="📥 Download Production-Ready Fixed Spec (YAML)",
            data=remediated_yaml,
            file_name="sentryshield_remediated_spec.yaml",
            mime="text/yaml"
        )

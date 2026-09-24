import streamlit as st
import json
import yaml

SENSITIVE_KEYWORDS = ["password", "ssn", "credit_card", "secret", "token", "api_key", "private_key"]

def analyze_and_remediate(spec_data):
    issues = []
    remediated_spec = json.loads(json.dumps(spec_data)) # Deep copy for remediation

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
                    "type": "BOLA / IDOR Risk",
                    "path": f"{method.upper()} {path}",
                    "details": "Path contains parameters but has no endpoint-level or global authorization rules.",
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
                            "type": "Sensitive Data Exposure",
                            "path": f"{method.upper()} {path} (Response {code})",
                            "details": f"Response schema exposes sensitive unmasked property: `{prop_name}`.",
                            "recommendation": "Mask or restrict sensitive field output in API responses."
                        })

            # 3. Unrestricted Resource Consumption (Missing Rate Limits)
            if "429" not in responses:
                issues.append({
                    "severity": "MEDIUM",
                    "type": "Missing Rate Limit Defenses",
                    "path": f"{method.upper()} {path}",
                    "details": "Endpoint does not specify a 429 (Too Many Requests) rate limiting response.",
                    "recommendation": "Define explicit HTTP 429 response structures."
                })
                # Remediation: Add standard 429 response declaration
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

# --- Streamlit Dashboard UI ---
st.set_page_config(page_title="SentryShield-AI", page_icon="🛡️", layout="wide")

st.title("🛡️ SentryShield-AI: Automated OpenAPI Security Analyzer & Auto-Remediator")
st.markdown("Automated security risk parsing, vulnerability detection, and code remediation for OpenAPI / Swagger specs.")

uploaded_file = st.file_uploader("Upload OpenAPI File (JSON or YAML)", type=["yaml", "yml", "json"])

if uploaded_file is not None:
    try:
        content = uploaded_file.read().decode("utf-8")
        spec = json.loads(content) if uploaded_file.name.endswith(".json") else yaml.safe_load(content)

        st.success(f"Successfully Loaded: **{spec.get('info', {}).get('title', 'OpenAPI Spec')}**")

        issues, fixed_spec = analyze_and_remediate(spec)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Paths Analyzed", len(spec.get("paths", {})))
        with col2:
            st.metric("Vulnerabilities Detected", len(issues))

        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.subheader("⚠️ Security Findings")
            if issues:
                for f in issues:
                    badge_color = "🔴" if f['severity'] in ["HIGH", "CRITICAL"] else "🟠"
                    with st.expander(f"{badge_color} [{f['severity']}] {f['type']} - {f['path']}"):
                        st.write(f"**Details:** {f['details']}")
                        st.write(f"**Recommendation:** {f['recommendation']}")
            else:
                st.success("No security vulnerabilities detected!")

        with col_right:
            st.subheader("🛠️ Remediated OpenAPI Spec")
            st.info("Auto-patches applied: Enforced HTTPS, added missing auth scopes for BOLA endpoints, and added 429 Rate Limit headers.")

            remediated_yaml = yaml.dump(fixed_spec, sort_keys=False)
            st.code(remediated_yaml, language="yaml", height=350)

            st.download_button(
                label="📥 Download Fixed Spec (YAML)",
                data=remediated_yaml,
                file_name="remediated_openapi_spec.yaml",
                mime="text/yaml"
            )

    except Exception as e:
        st.error(f"Error parsing specification file: {e}")

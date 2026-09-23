import streamlit as st
import yaml
import spacy

# Load spaCy model with caching
@st.cache_resource
def load_nlp():
    return spacy.load("en_core_web_sm")

nlp = load_nlp()

def audit_openapi_spec(spec):
    extracted_data = []
    vulnerabilities = []
    paths = spec.get('paths', {}) if spec else {}
    
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
                
            summary = details.get('summary', '')
            description = details.get('description', '')
            security = details.get('security', spec.get('security', []))

            # NLP Keyword Extraction
            text_to_analyze = f"{summary}. {description}"
            doc = nlp(text_to_analyze)
            tokens = [token.text for token in doc if not token.is_stop and not token.is_punct]

            # Security Risk Engine
            is_unauthenticated = len(security) == 0
            is_sensitive = any(word in path.lower() for word in ['admin', 'auth', 'user', 'delete', 'password', 'key'])
            
            risk_level = "LOW"
            if is_unauthenticated and is_sensitive:
                risk_level = "CRITICAL"
                vulnerabilities.append({
                    "route": path,
                    "method": method.upper(),
                    "issue": "Missing authentication on sensitive route",
                    "remediation": f"Add `security` scheme to `{method.upper()} {path}`"
                })
            elif is_unauthenticated:
                risk_level = "MEDIUM"
                vulnerabilities.append({
                    "route": path,
                    "method": method.upper(),
                    "issue": "Unauthenticated endpoint detected",
                    "remediation": "Enforce JWT / OAuth2 authentication"
                })

            extracted_data.append({
                'route': path,
                'method': method.upper(),
                'summary': summary,
                'description': description,
                'tokens': tokens,
                'risk': risk_level
            })
            
    return extracted_data, vulnerabilities

# Streamlit User Interface
st.set_page_config(page_title="SentryShield-AI", page_icon="🛡️", layout="wide")

st.title("🛡️ SentryShield-AI: Security Audit Platform")
st.markdown("Upload an OpenAPI/Swagger `.yaml` spec file to perform AI-driven security auditing.")

uploaded_file = st.file_uploader("Upload OpenAPI Spec (.yaml or .yml)", type=["yaml", "yml"])

if uploaded_file is not None:
    try:
        spec = yaml.safe_load(uploaded_file)
        components, vulnerabilities = audit_openapi_spec(spec)
        
        # Calculate Security Score
        total_endpoints = len(components)
        critical_count = sum(1 for c in components if c['risk'] == 'CRITICAL')
        medium_count = sum(1 for c in components if c['risk'] == 'MEDIUM')
        score = max(0, 100 - (critical_count * 25 + medium_count * 10))

        # Metrics Overview
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Security Score", f"{score}/100")
        col2.metric("Total Endpoints", total_endpoints)
        col3.metric("Critical Risks", critical_count)
        col4.metric("Medium Risks", medium_count)

        st.divider()

        tab1, tab2, tab3 = st.tabs(["📌 Endpoints & Keywords", "🚨 Audit & Remediation", "📄 Export Report"])

        with tab1:
            for item in components:
                with st.expander(f"[{item['method']}] {item['route']} — Risk: {item['risk']}"):
                    st.write(f"**Summary:** {item['summary'] or 'N/A'}")
                    st.write(f"**Description:** {item['description'] or 'N/A'}")
                    st.write(f"**Extracted NLP Keywords:** `{', '.join(item['tokens'])}`")

        with tab2:
            if vulnerabilities:
                for v in vulnerabilities:
                    st.error(f"**{v['method']} {v['route']}**: {v['issue']}\n\n**Remediation:** `{v['remediation']}`")
            else:
                st.success("No critical security risks found in this spec!")

        with tab3:
            report_text = f"SentryShield-AI Audit Report\nScore: {score}/100\nEndpoints: {total_endpoints}\nVulnerabilities: {len(vulnerabilities)}"
            st.download_button("Download Report (.txt)", report_text, file_name="SentryShield_Report.txt")

    except Exception as e:
        st.error(f"Invalid YAML File: {e}")
else:
    st.info("Please upload a `.yaml` OpenAPI specification file to begin.")

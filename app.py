import streamlit as st
import pandas as pd
import plotly.express as px
import email
from email import policy
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from modules.website_detector import analyze_website
from modules.url_detector import analyze_url
from modules.email_analyzer import analyze_email
from modules.uba import load_logs
import streamlit as st
from modules.login import authenticate
import cv2
import numpy as np
from PIL import Image
    
st.set_page_config(
    page_title="Cyber Threat Detection System",
    page_icon="🛡️",
    layout="wide"
)

if "role" not in st.session_state:
    st.session_state.role = None

# LOGIN PAGE
if st.session_state.role is None:

    st.title("🛡️ Cyber Threat Detection & Analysis System")
    st.markdown("---")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):

        role = authenticate(username, password)

        if role:
            st.session_state.role = role
            st.rerun()
        else:
            st.error("Invalid Username or Password")

    st.stop()

# SIDEBAR
st.sidebar.title("🛡️ Security Console")
st.sidebar.success(
    f"Logged in as {st.session_state.role}"
)

if st.session_state.role == "Admin":

    menu_options = [
        "Dashboard",
        "Email Analyzer",
        "URL Detector",
        "Website Detector",
        "UBA",
        "QR Detector",
        "Reports"
    ]

elif st.session_state.role == "Analyst":

    menu_options = [
        "Dashboard",
        "Email Analyzer",
        "URL Detector",
        "Website Detector",
        "UBA",
        
    ]

elif st.session_state.role == "HR":

    menu_options = [
        "Dashboard",
        "UBA",
        "QR Detector",
        "Reports"
    ]


menu = st.sidebar.selectbox(
    "Select Module",
    menu_options
)

if st.sidebar.button("Logout"):
    st.session_state.role = None
    st.rerun()

# DASHBOARD
if menu == "Dashboard":

    st.title("📊 Security Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "📧 Email Threats",
        25
    )

    col2.metric(
        "🌐 Malicious URLs",
        15
    )

    col3.metric(
        "👤 UBA Alerts",
        17
    )

    col4.metric(
        "⚠️ Total Threats",
        57
    
    )

import pandas as pd
import plotly.express as px

data = pd.DataFrame({
    "Threat":[
        "Email",
        "URL",
        "Website",
        "UBA",
        "QR"
    ],
    "Count":[
        12,
        8,
        4,
        5,
        3
    ]
})

fig = px.pie(
    data,
    values="Count",
    names="Threat",
    title="Threat Distribution"
)

st.plotly_chart(
    fig,
    use_container_width=True
)

if menu == "Email Analyzer":

    st.title("📧 Email Phishing Analyzer")

    uploaded_file = st.file_uploader(
    "Upload Email File",
    type=["txt", "eml"]
)

    sender = ""
    subject = ""
    body = ""
    if uploaded_file is not None:

        raw_email = uploaded_file.read()

        try:

            msg = email.message_from_bytes(
                raw_email,
                policy=policy.default
            )

            sender = msg.get("From", "Unknown")

            subject = msg.get("Subject", "No Subject")

            body = ""

            if msg.is_multipart():

                for part in msg.walk():

                    if part.get_content_type() == "text/plain":

                        try:
                            body += part.get_content()
                        except:
                            pass

            else:

                body = msg.get_content()

            if not body:
                body = "Unable to extract email body."

        except Exception as e:

            sender = "Unknown"
            subject = "Unknown"
            body = f"Email parsing failed: {e}"

        st.success("✅ Email Loaded Successfully")

        st.subheader("📧 Email Summary")

        st.write("**From:**", sender)

        st.write("**Subject:**", subject)

        st.text_area(
            "Email Body",
            value=body[:3000],
            height=250,
            disabled=True
        )

        st.text_input(
            "Sender Email",
            value=sender,
            disabled=True
        )

        st.text_input(
            "Subject",
            value=subject,
            disabled=True
        )

        st.text_area(
            "Email Body",
            value=body,
            height=200
        )

    else:

        sender = st.text_input(
            "Sender Email"
        )

        subject = st.text_input(
            "Subject"
        )

        body = st.text_area(
            "Email Body"
        )

    if st.button("Analyze Email"):

        sender = ""
        subject = ""

        score, reasons = analyze_email(
            sender,
            subject,
            body
        )

        st.metric(
            "Risk Score",
            score
        )

        if score >= 40:

            status = "Phishing"

            st.error(
                "🔴 High Risk Phishing Email"
            )

        elif score >= 20:

            status = "Suspicious"

            st.warning(
                "🟡 Suspicious Email"
            )

        else:

            status = "Safe"

            st.success(
                "🟢 Safe Email"
            )

        st.subheader(
            "Detection Reasons"
        )

        for reason in reasons:
            st.write("•", reason)

        pdf_buffer = BytesIO()

        doc = SimpleDocTemplate(pdf_buffer)

        styles = getSampleStyleSheet()

        content = []

        content.append(
            Paragraph(
                "Email Phishing Analysis Report",
                styles["Title"]
            )
        )

        content.append(Spacer(1, 12))

        content.append(
            Paragraph(
                f"<b>Sender:</b> {sender}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Subject:</b> {subject}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Risk Score:</b> {score}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Status:</b> {status}",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 12))

        content.append(
            Paragraph(
                "<b>Detection Reasons</b>",
                styles["Heading2"]
            )
        )

        for reason in reasons:

            content.append(
                Paragraph(
                    f"• {reason}",
                    styles["Normal"]
                )
            )

        doc.build(content)

        pdf_data = pdf_buffer.getvalue()

        st.success("✅ Analysis Completed Successfully")
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_data,
            file_name="Email_Phishing_Report.pdf",
            mime="application/pdf"
        )

if menu == "URL Detector":

    st.title("URL Threat Detector")

    sample_urls = {
    "Select Sample URL": "",
    "Google (Safe)": "https://www.google.com",
    "Bank Phishing Example": "http://secure-login-bank.xyz",
    "PayPal Scam Example": "http://verify-paypal-account-security-update.com"
}

    selected = st.selectbox(
        "Quick Test URLs",
        list(sample_urls.keys())
    )

    url = st.text_input(
            "Enter URL",
            value=sample_urls[selected]
        )
    if st.button("Analyze URL"):

        score, reasons = analyze_url(url)

        st.metric("Risk Score", score)

        if score >= 40:

            st.error(
            "🔴 Malicious URL"
        )

        elif score >= 20:

            st.warning(
            "🟡 Suspicious URL"
        )

        else:

            st.success(
            "🟢 Safe URL"
        )
        st.write("Reasons")

        for r in reasons:
            st.write("-", r)


if menu == "Website Detector":

    st.title("Fake Website Detector")

    sample_sites = {
    "Select Sample Website": "",
    "Google (Legitimate)": "https://www.google.com",
    "Amazon (Legitimate)": "https://www.amazon.in",
    "Fake PayPal Website": "http://paypal-account-verify-login.xyz",
    "Fake SBI Banking Website": "http://sbi-secure-login-update.xyz"
}

    selected_site = st.selectbox(
        "Quick Test Websites",
        list(sample_sites.keys())
    )

    website = st.text_input(
        "Enter Website URL",
        value=sample_sites[selected_site]
    )
    if st.button("Analyze Website"):

        score, reasons = analyze_website(website)

        st.metric("Risk Score", score)

        if score >= 40:
            st.error("Potential Fake Website")
        elif score >= 20:
            st.warning("Suspicious Website")
        else:
            st.success("Legitimate Website")

        for r in reasons:
            st.write("-", r)

if menu == "UBA":

    st.title("👤 User Behavior Analytics (UBA)")
    st.markdown("Analyze user activities and identify potential insider threats.")

    df = load_logs()

    # Risk Summary
    high_risk = len(df[df["Risk_Score"] >= 80])

    medium_risk = len(
    df[(df["Risk_Score"] >= 40) &
       (df["Risk_Score"] < 80)]
)

    safe_users = len(df[df["Risk_Score"] < 40])

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "🔴 High Risk Users",
        high_risk
    )

    c2.metric(
        "🟡 Suspicious Users",
        medium_risk
    )

    c3.metric(
        "🟢 Safe Users",
        safe_users
    )

    st.markdown("---")

    st.subheader("📋 User Activity Log")

    st.dataframe(
        df,
        use_container_width=True
    )

    st.markdown("---")

    selected_user = st.selectbox(
        "🔍 Select User for Analysis",
        df["username"]
    )

    user = df[
        df["username"] ==
        selected_user
    ].iloc[0]

    st.subheader("📊 Threat Interpretation")

    if user["Risk_Score"] >= 80:

        st.error(
            f"""
### 🚨 Critical Insider Threat Detected

**User:** {selected_user}

**Risk Score:** {user['Risk_Score']}

#### Observations
- Multiple suspicious activities detected
- Excessive failed login attempts
- Unusual access behaviour observed
- High-risk activity pattern identified

#### Recommendation
Immediate investigation is recommended.
Review login history, accessed resources,
and device activity.
"""
        )

    elif user["Risk_Score"] >= 40:

        st.warning(
            f"""
### ⚠️ Suspicious Behaviour Detected

**User:** {selected_user}

**Risk Score:** {user['Risk_Score']}

#### Observations
- Some unusual activity patterns detected
- Behaviour deviates from normal baseline

#### Recommendation
Monitor user activity and review access logs.
Further observation is advised.
"""
        )

    else:

        st.success(
            f"""
### ✅ Normal Behaviour

**User:** {selected_user}

**Risk Score:** {user['Risk_Score']}

#### Observations
No significant anomalies detected.

#### Recommendation
Continue regular monitoring.
"""
        )
if menu == "QR Detector":

    st.title("🔐 QR Code Phishing Detector")

    uploaded_file = st.file_uploader(
        "Upload QR Image",
        type=["png", "jpg", "jpeg"]
    )

    # -----------------------------
    # QR Decode Function
    # -----------------------------
    def decode_qr_opencv(image):

        img = image.convert("RGB")          # FIX 1: ensure RGB
        img = np.array(img)                # convert to numpy
        gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)  # FIX 2: grayscale

        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(gray)

        if data:
            return data
        return None

    # -----------------------------
    # Risk Analysis
    # -----------------------------
    def analyze_qr_url(url):

        score = 0
        reasons = []

        url = url.lower()

        if any(k in url for k in ["login", "verify", "bank", "secure", "otp", "password"]):
            score += 40
            reasons.append("Sensitive keyword detected")

        if any(ext in url for ext in [".xyz", ".tk", ".top", ".ml"]):
            score += 30
            reasons.append("Suspicious domain extension")

        if url.startswith("http://"):
            score += 20
            reasons.append("Not secure HTTP link")

        if len(url) > 60:
            score += 10
            reasons.append("Long suspicious URL")

        score = min(score, 100)

        if score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level, reasons


    # -----------------------------
    # MAIN LOGIC
    # -----------------------------
    if uploaded_file is not None:

        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded QR Code", use_container_width=True)

        qr_url = decode_qr_opencv(image)

        if qr_url:

            st.success("✅ QR Code Detected")

            st.subheader("🔗 Extracted URL")
            st.code(qr_url)

            score, level, reasons = analyze_qr_url(qr_url)

            st.subheader("🛡 Security Result")

            if level == "HIGH":
                st.error(f"🚨 HIGH RISK ({score}/100)")
            elif level == "MEDIUM":
                st.warning(f"⚠️ MEDIUM RISK ({score}/100)")
            else:
                st.success(f"✅ LOW RISK ({score}/100)")

            st.markdown("### 📌 Reasons")

            for r in reasons:
                st.write("•", r)

        else:
            st.error("❌ No QR code detected in image")

if menu == "Reports":

    st.title("Threat Reports")

    df = load_logs()

    st.dataframe(df)

    csv = df.to_csv(index=False)

    st.download_button(
        label="Download Report",
        data=csv,
        file_name="UBA_Report.csv",
        mime="text/csv"
    )
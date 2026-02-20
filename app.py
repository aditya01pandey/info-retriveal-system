import streamlit as st
import PyPDF2
import os
import hashlib
import secrets
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv
from groq import Groq
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# ─── Load Environment Variables ───
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI = "http://localhost:8501/"

# ─── Database Setup ───
engine = create_engine("sqlite:///users.db", connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=True)
    google_id = Column(String, nullable=True)


Base.metadata.create_all(bind=engine)


# ─── Password Hashing (pure hashlib, no bcrypt) ───
def safe_hash(password: str) -> str:
    """Hash password with SHA256 + random salt."""
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${pw_hash}"


def safe_verify(password: str, stored: str) -> bool:
    """Verify password against stored salt$hash."""
    try:
        salt, pw_hash = stored.split("$", 1)
        return hashlib.sha256((salt + password).encode("utf-8")).hexdigest() == pw_hash
    except Exception:
        return False


# ─── Groq Client ───
groq_client = None
if GROQ_API_KEY:
    groq_client = Groq(api_key=GROQ_API_KEY)

# ─── Page Config ───
st.set_page_config(page_title="PDF Analyzer", page_icon="📄", layout="wide")

# ─── Premium Instagram-Style CSS ───
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    .stApp { font-family: 'Inter', sans-serif; }

    /* Hide default Streamlit elements on auth pages */
    .auth-page header[data-testid="stHeader"],
    .auth-page [data-testid="stSidebar"] { display: none !important; }

    /* ── Auth card ── */
    .auth-card {
        max-width: 380px;
        margin: 30px auto 0;
        padding: 32px 36px;
        background: #1a1a2e;
        border: 1px solid #2a2a4a;
        border-radius: 8px;
        text-align: center;
    }

    .auth-card-bottom {
        max-width: 380px;
        margin: 12px auto 0;
        padding: 20px 36px;
        background: #1a1a2e;
        border: 1px solid #2a2a4a;
        border-radius: 8px;
        text-align: center;
        font-size: 14px;
        color: #a0a0b8;
    }

    .auth-card-bottom a {
        color: #818cf8;
        text-decoration: none;
        font-weight: 600;
    }

    .app-logo {
        font-size: 32px;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 24px;
        letter-spacing: -0.5px;
    }

    /* ── Google Button ── */
    .g-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        width: 100%;
        padding: 10px 0;
        background: #2563eb;
        border: none;
        border-radius: 8px;
        color: white;
        font-size: 14px;
        font-weight: 600;
        text-decoration: none;
        transition: background 0.2s;
    }
    .g-btn:hover { background: #1d4ed8; color: white; text-decoration: none; }

    /* ── Divider ── */
    .or-divider {
        display: flex;
        align-items: center;
        margin: 20px 0;
        color: #4a4a6a;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .or-divider::before, .or-divider::after {
        content: '';
        flex: 1;
        height: 1px;
        background: #2a2a4a;
    }
    .or-divider::before { margin-right: 16px; }
    .or-divider::after { margin-left: 16px; }

    /* ── Alert messages ── */
    .alert-error {
        padding: 10px 14px;
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.25);
        border-radius: 6px;
        color: #fca5a5;
        font-size: 13px;
        margin: 12px 0 0;
        text-align: left;
    }

    .alert-success {
        padding: 10px 14px;
        background: rgba(34, 197, 94, 0.1);
        border: 1px solid rgba(34, 197, 94, 0.25);
        border-radius: 6px;
        color: #86efac;
        font-size: 13px;
        margin: 12px 0 0;
        text-align: left;
    }

    /* ── Tighten Streamlit form inputs ── */
    .auth-card .stTextInput > div > div > input {
        background: #0f0f23 !important;
        border: 1px solid #2a2a4a !important;
        border-radius: 6px !important;
        color: #e2e8f0 !important;
        font-size: 14px !important;
        padding: 10px 14px !important;
    }

    .auth-card .stTextInput > div > div > input:focus {
        border-color: #818cf8 !important;
        box-shadow: 0 0 0 1px #818cf8 !important;
    }

    .auth-card .stTextInput > label {
        display: none !important;
    }

    .auth-card .stFormSubmitButton > button {
        width: 100%;
        background: #818cf8 !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 0 !important;
        font-size: 14px !important;
        font-weight: 600 !important;
        transition: background 0.2s !important;
    }
    .auth-card .stFormSubmitButton > button:hover {
        background: #6366f1 !important;
    }
</style>
""", unsafe_allow_html=True)


# ─── Session State ───
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_name" not in st.session_state:
    st.session_state.user_name = ""
if "user_email" not in st.session_state:
    st.session_state.user_email = ""
if "auth_page" not in st.session_state:
    st.session_state.auth_page = "login"
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pdf_text" not in st.session_state:
    st.session_state.pdf_text = ""


# ─── Auth Helpers ───
def create_user(name, email, password):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == email).first():
            return False, "Email already registered."
        user = User(name=name, email=email, hashed_password=safe_hash(password))
        db.add(user)
        db.commit()
        return True, "Account created!"
    except Exception as e:
        db.rollback()
        return False, str(e)
    finally:
        db.close()


def verify_user(email, password):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.hashed_password:
            return None
        if not safe_verify(password, user.hashed_password):
            return None
        return {"name": user.name, "email": user.email}
    finally:
        db.close()


def get_or_create_google_user(name, email, google_id):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(name=name, email=email, google_id=google_id)
            db.add(user)
            db.commit()
        return {"name": user.name, "email": user.email}
    except Exception:
        db.rollback()
        return None
    finally:
        db.close()


def get_google_auth_url():
    if not GOOGLE_CLIENT_ID:
        return None
    state = secrets.token_urlsafe(32)
    st.session_state["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


def exchange_google_code(code):
    try:
        token_resp = requests.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
        })
        if token_resp.status_code != 200:
            return None
        tokens = token_resp.json()
        user_resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {tokens.get('access_token')}"}
        )
        if user_resp.status_code != 200:
            return None
        return user_resp.json()
    except Exception:
        return None


# ─── Handle Google OAuth Callback ───
query_params = st.query_params
if "code" in query_params and not st.session_state.authenticated:
    code = query_params["code"]
    user_info = exchange_google_code(code)
    if user_info:
        name = user_info.get("name", "User")
        email = user_info.get("email", "")
        google_id = user_info.get("id", "")
        user = get_or_create_google_user(name, email, google_id)
        if user:
            st.session_state.authenticated = True
            st.session_state.user_name = user["name"]
            st.session_state.user_email = user["email"]
            st.query_params.clear()
            st.rerun()
    st.query_params.clear()


# ═══════════════════════════════════════════════════
#  AUTH PAGES
# ═══════════════════════════════════════════════════

def show_login_page():
    # Center the card using columns
    _, center, _ = st.columns([1, 1.3, 1])
    with center:
        st.markdown('<div class="auth-card">', unsafe_allow_html=True)
        st.markdown('<div class="app-logo">PDF Analyzer</div>', unsafe_allow_html=True)

        # Google button
        google_url = get_google_auth_url()
        if google_url:
            st.markdown(f'''
                <a href="{google_url}" class="g-btn">
                    <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18">
                    Log in with Google
                </a>
            ''', unsafe_allow_html=True)
            st.markdown('<div class="or-divider">or</div>', unsafe_allow_html=True)

        # Login form
        with st.form("login_form", clear_on_submit=False):
            email = st.text_input("email", placeholder="Email address", label_visibility="collapsed")
            password = st.text_input("password", placeholder="Password", type="password", label_visibility="collapsed")
            submitted = st.form_submit_button("Log In", use_container_width=True, type="primary")

            if submitted:
                if not email or not password:
                    st.markdown('<div class="alert-error">Please fill in all fields.</div>', unsafe_allow_html=True)
                else:
                    user = verify_user(email, password)
                    if user:
                        st.session_state.authenticated = True
                        st.session_state.user_name = user["name"]
                        st.session_state.user_email = user["email"]
                        st.rerun()
                    else:
                        st.markdown('<div class="alert-error">Invalid email or password.</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        # Bottom card
        st.markdown('<div class="auth-card-bottom">', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Switch button
    _, btn_col, _ = st.columns([1, 1.3, 1])
    with btn_col:
        if st.button("Don't have an account? **Sign up**", use_container_width=True):
            st.session_state.auth_page = "signup"
            st.rerun()


def show_signup_page():
    _, center, _ = st.columns([1, 1.3, 1])
    with center:
        st.markdown('<div class="auth-card">', unsafe_allow_html=True)
        st.markdown('<div class="app-logo">PDF Analyzer</div>', unsafe_allow_html=True)
        st.markdown('<p style="color:#8a8aa0; font-size:15px; margin-bottom:20px;">Sign up to analyze your PDFs with AI</p>', unsafe_allow_html=True)

        # Google button
        google_url = get_google_auth_url()
        if google_url:
            st.markdown(f'''
                <a href="{google_url}" class="g-btn">
                    <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18">
                    Sign up with Google
                </a>
            ''', unsafe_allow_html=True)
            st.markdown('<div class="or-divider">or</div>', unsafe_allow_html=True)

        # Signup form
        with st.form("signup_form", clear_on_submit=False):
            name = st.text_input("name", placeholder="Full Name", label_visibility="collapsed")
            email = st.text_input("email", placeholder="Email address", label_visibility="collapsed")
            password = st.text_input("password", placeholder="Password", type="password", label_visibility="collapsed")
            confirm = st.text_input("confirm", placeholder="Confirm password", type="password", label_visibility="collapsed")
            submitted = st.form_submit_button("Sign Up", use_container_width=True, type="primary")

            if submitted:
                if not name or not email or not password:
                    st.markdown('<div class="alert-error">Please fill in all fields.</div>', unsafe_allow_html=True)
                elif password != confirm:
                    st.markdown('<div class="alert-error">Passwords do not match.</div>', unsafe_allow_html=True)
                elif len(password) < 6:
                    st.markdown('<div class="alert-error">Password must be at least 6 characters.</div>', unsafe_allow_html=True)
                else:
                    ok, msg = create_user(name, email, password)
                    if ok:
                        st.markdown(f'<div class="alert-success">✅ {msg} Please log in.</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="alert-error">{msg}</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="auth-card-bottom">', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    _, btn_col, _ = st.columns([1, 1.3, 1])
    with btn_col:
        if st.button("Have an account? **Log in**", use_container_width=True):
            st.session_state.auth_page = "login"
            st.rerun()


# ═══════════════════════════════════════════════════
#  PDF ANALYZER (after login)
# ═══════════════════════════════════════════════════

def extract_text_from_pdf(uploaded_file):
    try:
        pdf_reader = PyPDF2.PdfReader(uploaded_file)
        text = ""
        with st.spinner(f"📖 Reading {len(pdf_reader.pages)} pages..."):
            for page in pdf_reader.pages:
                text += page.extract_text()
        return text
    except Exception as e:
        st.error(f"Error reading PDF: {str(e)}")
        return None


def analyze_with_groq(prompt, pdf_text=None, max_length=8000, model="llama-3.3-70b-versatile", temp=0.7):
    if not groq_client:
        return "Error: Groq API not configured."
    try:
        context = f"PDF Content:\n{pdf_text[:max_length]}\n\n" if pdf_text else ""
        full_prompt = f"{context}{prompt}\n\nProvide a detailed response based on the PDF content above."
        resp = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are an intelligent PDF document analyzer."},
                {"role": "user", "content": full_prompt}
            ],
            model=model, temperature=temp, max_tokens=4096,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"


def show_pdf_analyzer():
    with st.sidebar:
        st.markdown(f"### 👤 {st.session_state.user_name}")
        st.caption(st.session_state.user_email)
        if st.button("🚪 Sign Out", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_name = ""
            st.session_state.user_email = ""
            st.session_state.auth_page = "login"
            st.rerun()

        st.markdown("---")
        st.title("⚙️ Settings")
        model_name = st.selectbox("Model:", ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"])
        temperature = st.slider("Temperature:", 0.0, 1.0, 0.7, 0.1)
        max_chunk_size = st.slider("Max Chunk:", 1000, 20000, 8000, 500)
        st.markdown("---")
        if GROQ_API_KEY:
            st.success("✅ Groq Connected")
        st.caption("Powered by Groq")

    st.title("📄 Intelligent PDF Analyzer")
    st.markdown("Upload PDF documents and get AI-powered analysis, summaries, and answers.")

    if not GROQ_API_KEY:
        st.error("GROQ_API_KEY not found in .env")
        st.stop()

    st.subheader("📤 Upload Document")
    uploaded_file = st.file_uploader("Upload your PDF file", type="pdf")

    if uploaded_file:
        c1, c2 = st.columns(2)
        with c1:
            st.info(f"📄 **{uploaded_file.name}**")
        with c2:
            st.info(f"📊 **{uploaded_file.size / 1024:.1f} KB**")

        pdf_text = extract_text_from_pdf(uploaded_file)
        if pdf_text:
            st.session_state.pdf_text = pdf_text
            with st.expander("📝 Extracted Text Preview"):
                st.text_area("", pdf_text[:1500], height=200)

            st.subheader("📊 Document Statistics")
            c1, c2, c3, c4 = st.columns(4)
            pdf_reader = PyPDF2.PdfReader(uploaded_file)
            c1.metric("Pages", len(pdf_reader.pages))
            c2.metric("Characters", len(pdf_text))
            c3.metric("Words", len(pdf_text.split()))
            c4.metric("Lines", pdf_text.count('\n'))

            st.markdown("---")
            st.subheader("🔍 Analysis")
            tab1, tab2, tab3 = st.tabs(["📋 Summary", "❓ Q&A", "🔧 Advanced"])


            with tab1:
                stype = st.selectbox("Type:", ["Brief Overview", "Detailed Summary", "Executive Summary", "Chapter-wise Summary"])
                if st.button("Generate Summary", type="primary", key="sum_btn"):
                    with st.spinner("Generating..."):
                        out = analyze_with_groq(f"Provide a {stype.lower()} of this document.", pdf_text, max_chunk_size, model_name, temperature)
                        st.markdown("### 📋 Summary")
                        st.markdown(out)
                        st.download_button("📥 Download Summary", out, f"{uploaded_file.name}_summary.txt")

            with tab2:
                st.markdown("### ❓ Ask Questions")
                qs = ["What is the main topic?", "What are the key findings?", "What methodology was used?", "What are the conclusions?"]
                sel = st.selectbox("Question:", ["Write your own..."] + qs)
                q = st.text_input("Your question:") if sel == "Write your own..." else sel
                if st.button("Get Answer", type="primary", key="qa_btn") and q:
                    with st.spinner("Analyzing..."):
                        ans = analyze_with_groq(q, pdf_text, max_chunk_size, model_name, temperature)
                        st.markdown("### 💡 Answer")
                        st.markdown(ans)
                        st.session_state.chat_history.append({"question": q, "answer": ans})

            with tab3:
                st.markdown("### 🔧 Advanced")
                opts = st.multiselect("Analyses:", ["Extract Key Points", "Identify Action Items", "Find Statistics & Data", "SWOT Analysis", "Sentiment Analysis"])
                custom = st.text_area("Custom prompt:", placeholder="e.g., Analyze risks...", height=100)
                if st.button("Run Analysis", type="primary", key="adv_btn"):
                    if opts or custom:
                        with st.spinner("Analyzing..."):
                            p = custom if custom else f"Perform: {', '.join(opts)}"
                            out = analyze_with_groq(p, pdf_text, max_chunk_size, model_name, temperature)
                            st.markdown("### 📈 Results")
                            st.markdown(out)
                            st.download_button("📥 Download", out, f"{uploaded_file.name}_analysis.txt")

            if st.session_state.chat_history:
                st.markdown("---")
                st.subheader("💬 History")
                for ch in st.session_state.chat_history[-5:]:
                    with st.expander(f"Q: {ch['question'][:50]}..."):
                        st.markdown(f"**Q:** {ch['question']}")
                        st.markdown(f"**A:** {ch['answer']}")
        else:
            st.error("Failed to extract text from PDF.")


# ═══════════════════════════════════════════════════
#  MAIN ROUTER
# ═══════════════════════════════════════════════════

if st.session_state.authenticated:
    show_pdf_analyzer()
else:
    if st.session_state.auth_page == "signup":
        show_signup_page()
    else:
        show_login_page()
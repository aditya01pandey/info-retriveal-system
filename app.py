import streamlit as st
import google.generativeai as genai
import PyPDF2
import os
import tempfile
from pathlib import Path

# Configure Streamlit page
st.set_page_config(
    page_title="Intelligent PDF Analyzer with Gemini",
    page_icon="📄",
    layout="wide"
)

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'pdf_text' not in st.session_state:
    st.session_state.pdf_text = ""
if 'gemini_model' not in st.session_state:
    st.session_state.gemini_model = None

# Sidebar for API Key and Settings
with st.sidebar:
    st.title("⚙️ Settings")
    
    # API Key Input
    st.subheader("1. API Configuration")
    api_key_method = st.radio(
        "API Key Source:",
        ["Enter Manually", "Use .env file"]
    )
    
    api_key = ""
    if api_key_method == "Enter Manually":
        api_key = st.text_input(
            "Enter Google Gemini API Key:",
            type="password",
            placeholder="AIzaSy...",
            help="Get your API key from: https://makersuite.google.com/app/apikey"
        )
    else:
        # Try to load from environment
        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            st.success("✓ API Key loaded from .env file")
        else:
            st.error("❌ No API key found in .env file")
            st.info("Create a `.env` file with: GEMINI_API_KEY=your_key_here")
    
    st.markdown("---")
    
    # Model Selection
    st.subheader("2. Model Settings")
    model_name = st.selectbox(
        "Select Gemini Model:",
        ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"],
        index=0
    )
    
    # Temperature control
    temperature = st.slider(
        "Temperature (Creativity):",
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        step=0.1
    )
    
    # Chunk size for processing
    max_chunk_size = st.slider(
        "Max Text Chunk Size (characters):",
        min_value=1000,
        max_value=10000,
        value=5000,
        step=500
    )
    
    st.markdown("---")
    st.caption("Made with Google Gemini AI")

# Main Content
st.title("📄 Intelligent PDF Analyzer with Google Gemini")
st.markdown("Upload PDF documents and get AI-powered analysis, summaries, and answers.")

# Function to extract text from PDF
def extract_text_from_pdf(uploaded_file):
    """Extract text from PDF using PyPDF2"""
    try:
        pdf_reader = PyPDF2.PdfReader(uploaded_file)
        text = ""
        
        with st.spinner(f"📖 Reading {len(pdf_reader.pages)} pages..."):
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += page.extract_text()
                
        return text
    except Exception as e:
        st.error(f"Error reading PDF: {str(e)}")
        return None

# Function to initialize Gemini
def initialize_gemini(api_key):
    """Initialize Google Gemini with API key"""
    if not api_key:
        st.error("❌ Please enter your Google Gemini API Key")
        return None
    
    try:
        genai.configure(api_key=api_key)
        
        # Test the API key
        test_model = genai.GenerativeModel('gemini-pro')
        test_response = test_model.generate_content("Hello")
        
        # Store the model in session state
        st.session_state.gemini_model = genai.GenerativeModel(
            model_name=model_name,
            generation_config={"temperature": temperature}
        )
        
        st.sidebar.success("✅ Gemini API Connected!")
        return st.session_state.gemini_model
    except Exception as e:
        st.error(f"❌ Error connecting to Gemini: {str(e)}")
        return None

# Function to analyze PDF with Gemini
def analyze_with_gemini(prompt, pdf_text=None, max_length=10000):
    """Analyze text using Google Gemini"""
    if not st.session_state.gemini_model:
        return "Error: Gemini model not initialized. Please check your API key."
    
    try:
        # Prepare the text
        context = ""
        if pdf_text:
            # Use only the first max_length characters to avoid token limits
            context = f"PDF Content:\n{pdf_text[:max_length]}\n\n"
        
        full_prompt = f"{context}{prompt}\n\nPlease provide a detailed response based on the PDF content above."
        
        response = st.session_state.gemini_model.generate_content(full_prompt)
        return response.text
    except Exception as e:
        return f"Error during analysis: {str(e)}"

# Main application logic
def main():
    # Check if API key is provided
    if not api_key:
        st.warning("👈 Please enter your Google Gemini API Key in the sidebar")
        
        # Display API key help
        with st.expander("ℹ️ How to get Google Gemini API Key"):
            st.markdown("""
            1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
            2. Sign in with your Google account
            3. Click "Create API Key"
            4. Copy the key and paste it in the sidebar
            5. Or create a `.env` file with: `GEMINI_API_KEY=your_key_here`
            """)
        return
    
    # Initialize Gemini
    if not st.session_state.gemini_model:
        initialize_gemini(api_key)
    
    # File Upload Section
    st.subheader("📤 Upload Document")
    uploaded_file = st.file_uploader(
        "Upload your PDF file",
        type="pdf",
        help="Maximum file size: 200MB"
    )
    
    if uploaded_file is not None:
        # Display file info
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"📄 **File:** {uploaded_file.name}")
        with col2:
            st.info(f"📊 **Size:** {uploaded_file.size / 1024:.1f} KB")
        
        # Extract text
        pdf_text = extract_text_from_pdf(uploaded_file)
        
        if pdf_text:
            # Store in session state
            st.session_state.pdf_text = pdf_text
            
            # Display text preview
            with st.expander("📝 View Extracted Text (Preview)"):
                st.text_area("", pdf_text[:1500], height=200)
            
            # Display statistics
            st.subheader("📊 Document Statistics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                pdf_reader = PyPDF2.PdfReader(uploaded_file)
                st.metric("Pages", len(pdf_reader.pages))
            with col2:
                st.metric("Characters", len(pdf_text))
            with col3:
                st.metric("Words", len(pdf_text.split()))
            with col4:
                st.metric("Lines", pdf_text.count('\n'))
            
            st.markdown("---")
            
            # Analysis Options
            st.subheader("🔍 Analysis Options")
            
            tab1, tab2, tab3 = st.tabs(["📋 Summary", "❓ Q&A", "🔧 Advanced"])
            
            with tab1:
                # Summary Tab
                col1, col2 = st.columns([3, 1])
                with col1:
                    summary_type = st.selectbox(
                        "Summary Type:",
                        ["Brief Overview", "Detailed Summary", "Executive Summary", "Chapter-wise Summary"]
                    )
                with col2:
                    if st.button("Generate Summary", type="primary"):
                        with st.spinner("Generating summary..."):
                            prompt = f"Provide a {summary_type.lower()} of this document."
                            summary = analyze_with_gemini(prompt, pdf_text)
                            
                            st.markdown("### 📋 Document Summary")
                            st.markdown(summary)
                            
                            # Download option
                            st.download_button(
                                label="📥 Download Summary",
                                data=summary,
                                file_name=f"{uploaded_file.name}_summary.txt",
                                mime="text/plain"
                            )
            
            with tab2:
                # Q&A Tab
                st.markdown("### ❓ Ask Questions About the Document")
                
                # Pre-defined questions
                questions = [
                    "What is the main topic?",
                    "What are the key findings?",
                    "What methodology was used?",
                    "What are the conclusions?",
                    "Who is the target audience?",
                    "What problems are addressed?"
                ]
                
                selected_question = st.selectbox(
                    "Choose a question or write your own:",
                    ["Write your own..."] + questions
                )
                
                if selected_question == "Write your own...":
                    user_question = st.text_input("Your question:")
                else:
                    user_question = selected_question
                
                if st.button("Get Answer", type="primary") and user_question:
                    with st.spinner("Analyzing document..."):
                        answer = analyze_with_gemini(user_question, pdf_text)
                        
                        # Display answer
                        st.markdown("### 💡 Answer")
                        st.success(answer)
                        
                        # Add to chat history
                        st.session_state.chat_history.append({
                            "question": user_question,
                            "answer": answer
                        })
            
            with tab3:
                # Advanced Analysis Tab
                st.markdown("### 🔧 Advanced Analysis")
                
                analysis_options = st.multiselect(
                    "Select analysis types:",
                    ["Extract Key Points", "Identify Action Items", "Find Statistics & Data", 
                     "Timeline Analysis", "Risk Assessment", "SWOT Analysis", "Sentiment Analysis"]
                )
                
                custom_prompt = st.text_area(
                    "Or enter custom prompt:",
                    placeholder="e.g., Analyze the document for potential risks and mitigation strategies...",
                    height=100
                )
                
                if st.button("Run Analysis", type="primary"):
                    if analysis_options or custom_prompt:
                        with st.spinner("Performing analysis..."):
                            if custom_prompt:
                                prompt = custom_prompt
                            else:
                                prompt = f"Perform the following analyses: {', '.join(analysis_options)}"
                            
                            analysis = analyze_with_gemini(prompt, pdf_text)
                            
                            st.markdown("### 📈 Analysis Results")
                            st.markdown(analysis)
                            
                            # Download analysis
                            st.download_button(
                                label="📥 Download Full Analysis",
                                data=analysis,
                                file_name=f"{uploaded_file.name}_analysis.txt",
                                mime="text/plain"
                            )
                    else:
                        st.warning("Please select analysis options or enter a custom prompt")
            
            # Chat History
            if st.session_state.chat_history:
                st.markdown("---")
                st.subheader("💬 Conversation History")
                
                for i, chat in enumerate(st.session_state.chat_history[-5:]):  # Show last 5
                    with st.expander(f"Q: {chat['question'][:50]}..."):
                        st.markdown(f"**Question:** {chat['question']}")
                        st.markdown(f"**Answer:** {chat['answer']}")
        
        else:
            st.error("Failed to extract text from PDF. The PDF might be scanned or corrupted.")

if __name__ == "__main__":
    main()
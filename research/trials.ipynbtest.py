from dotenv import load_dotenv
import os
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
print(GOOGLE_API_KEY)

import streamlit as st
from PIL import Image

st.set_page_config(page_title="Information Retrieval")
st.title("■ Information Retrieval System")
try:
    image = Image.open('your_image.png')
    st.image(image, caption='Your Image', use_container_width=True)
except Exception as e:
    st.error(f"Error loading image: {e}")
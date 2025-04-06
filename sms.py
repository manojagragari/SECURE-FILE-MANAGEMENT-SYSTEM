import os
import streamlit as st
import hashlib
import shutil
from pathlib import Path
import time
from streamlit_lottie import st_lottie
import requests
import pandas as pd

# Function to load Lottie animations with error handling
def load_lottie_url(url):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# Set up Streamlit app with enhanced configuration
def main():
    st.set_page_config(
        page_title="Secure File Management System",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            'Get Help': None,
            'Report a bug': None,
            'About': None
        }
    )
    
    # Hide deployment and other options from the top menu
    hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            .stDeployButton {display:none;}
            </style>
            """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)

    # Load animations with new URLs and error handling
    lottie_security = load_lottie_url("https://assets9.lottiefiles.com/packages/lf20_yRyM3f.json")
    lottie_upload = load_lottie_url("https://assets2.lottiefiles.com/packages/lf20_u25cckyh.json")
    lottie_chart = load_lottie_url("https://assets4.lottiefiles.com/packages/lf20_qp1q7ypz.json")
    
    # Custom CSS for improved appearance
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #2e7bcf;
        text-align: center;
        margin-bottom: 1rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .card {
        border-radius: 10px;
        padding: 1.5rem;
        background-color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
        transition: transform 0.3s ease;
    }
    .card:hover {
        transform: translateY(-5px);
    }
    .card-header {
        font-size: 1.2rem;
        font-weight: bold;
        color: #2e7bcf;
        margin-bottom: 0.5rem;
    }
    .sidebar .sidebar-content {
        background-image: linear-gradient(#2e7bcf,#2e7bcf);
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

    # Sidebar with navigation
    with st.sidebar:
        menu = ["Home/Dashboard", "Upload File", "View Files", "File Encryption"]
        choice = st.selectbox("Menu", menu)
        
        # Add a sidebar divider
        st.markdown("---")
        
        # Quick stats in sidebar
        folder = "uploaded_files"
        if os.path.exists(folder):
            all_files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
            regular_files = [f for f in all_files if not f.endswith('.enc')]
            encrypted_files = [f for f in all_files if f.endswith('.enc')]
            
            st.markdown("### Quick Stats")
            st.markdown(f"📊 **Total Files:** {len(all_files)}")
            st.markdown(f"📄 **Regular Files:** {len(regular_files)}")
            st.markdown(f"🔒 **Encrypted Files:** {len(encrypted_files)}")

    # Enhanced Home/Dashboard page
    if choice == "Home/Dashboard":
        # Top section with header and animation
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown("<h1 class='main-header'>🔒 Secure File Management System</h1>", unsafe_allow_html=True)
            st.markdown("""
            Welcome to your secure file management dashboard. This system allows you to:
            - 📤 Upload and store files securely
            - 📁 Browse and preview your files easily
            - 🔐 Encrypt important files with strong passwords
            - 🔓 Decrypt files when needed
            
            Get started by exploring the metrics below or using the navigation menu.
            """)
        
        with col2:
            if lottie_security:
                st_lottie(lottie_security, height=180, key="security_animation")
        
        # System stats section
        st.markdown("---")
        
        folder = "uploaded_files"
        if os.path.exists(folder):
            # Filter out _decrypted files
            all_files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not "_decrypted" in f]
            regular_files = [f for f in all_files if not f.endswith('.enc')]
            encrypted_files = [f for f in all_files if f.endswith('.enc')]
            total_size = sum(os.path.getsize(os.path.join(folder, f)) for f in all_files)
            
            # Display statistics in metric cards
            st.markdown("<h2 style='text-align: center;'>📊 System Statistics</h2>", unsafe_allow_html=True)
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.metric("Total Files", len(all_files))
                st.markdown("</div>", unsafe_allow_html=True)
                
            with col2:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.metric("Regular Files", len(regular_files))
                st.markdown("</div>", unsafe_allow_html=True)
                
            with col3:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.metric("Encrypted Files", len(encrypted_files))
                st.markdown("</div>", unsafe_allow_html=True)
                
            with col4:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.metric("Total Size (MB)", round(total_size/1024/1024, 2))
                st.markdown("</div>", unsafe_allow_html=True)
            
            # File management and charts section
            st.markdown("---")
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.markdown("<div class='card-header'>Recently Uploaded Files</div>", unsafe_allow_html=True)
                
                # Show most recent files
                recent_files = []
                for file in all_files:
                    file_path = os.path.join(folder, file)
                    modified = os.path.getmtime(file_path)
                    recent_files.append({
                        "File Name": file,
                        "Last Modified": pd.to_datetime(modified, unit='s'),
                        "Encrypted": "🔒" if file.endswith('.enc') else "📄"
                    })
                
                if recent_files:
                    df_recent = pd.DataFrame(recent_files)
                    df_recent = df_recent.sort_values(by="Last Modified", ascending=False).head(5)
                    st.dataframe(df_recent[["File Name", "Encrypted", "Last Modified"]], use_container_width=True)
                else:
                    st.info("No files uploaded yet.")
                
                # Quick actions
                st.markdown("#### Quick Actions")
                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button("📤 Upload File", use_container_width=True):
                        st.session_state.navigate_to = "Upload File"
                        st.rerun()
                with col_b:
                    if st.button("📁 View Files", use_container_width=True):
                        st.session_state.navigate_to = "View Files"
                        st.rerun()
                
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.markdown("<div class='card-header'>File Type Distribution</div>", unsafe_allow_html=True)
                
                if lottie_chart:
                    col_a, col_b = st.columns([1, 2])
                    with col_a:
                        st_lottie(lottie_chart, height=150, key="chart_animation")
                    
                    with col_b:
                        # File type distribution for regular files
                        if regular_files:
                            file_types = {}
                            for file in regular_files:
                                ext = os.path.splitext(file)[1].upper()[1:] or "No Extension"
                                file_types[ext] = file_types.get(ext, 0) + 1
                            
                            df_types = pd.DataFrame(list(file_types.items()), columns=['File Type', 'Count'])
                            
                            # Create a horizontal bar chart
                            st.bar_chart(df_types.set_index('File Type'))
                        else:
                            st.info("No regular files to analyze.")
                else:
                    # File type distribution without animation
                    if regular_files:
                        file_types = {}
                        for file in regular_files:
                            ext = os.path.splitext(file)[1].upper()[1:] or "No Extension"
                            file_types[ext] = file_types.get(ext, 0) + 1
                        
                        df_types = pd.DataFrame(list(file_types.items()), columns=['File Type', 'Count'])
                        st.bar_chart(df_types.set_index('File Type'))
                    else:
                        st.info("No regular files to analyze.")
                
                st.markdown("</div>", unsafe_allow_html=True)
            
            # Security status section
            st.markdown("---")
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.markdown("<div class='card-header'>Security Status</div>", unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                encryption_percentage = len(encrypted_files) / len(all_files) * 100 if len(all_files) > 0 else 0
                st.markdown(f"### {encryption_percentage:.1f}%")
                st.markdown("Files Protected")
                
                # Security status based on encryption percentage
                if encryption_percentage >= 75:
                    st.success("Excellent protection level")
                elif encryption_percentage >= 50:
                    st.info("Good protection level")
                elif encryption_percentage >= 25:
                    st.warning("Moderate protection level")
                else:
                    st.error("Low protection level")
            
            with col2:
                if encrypted_files:
                    st.markdown("### Recent Encrypted Files")
                    for file in encrypted_files[:3]:
                        st.markdown(f"🔒 {file.replace('.enc', '')}")
                else:
                    st.info("No encrypted files.")
            
            with col3:
                if len(encrypted_files) < len(regular_files) and len(regular_files) > 0:
                    st.markdown("### Encryption Suggestions")
                    st.markdown("Consider encrypting these files:")
                    for file in regular_files[:3]:
                        if any(ext in file.lower() for ext in ['.doc', '.pdf', '.xlsx', '.csv', '.txt']):
                            st.markdown(f"🔓 {file}")
                else:
                    st.success("All important files are encrypted!")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        else:
            # If no files have been uploaded yet
            st.info("No files have been uploaded to the system yet. Start by uploading a file!")
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("<div class='card'>", unsafe_allow_html=True)
                st.markdown("<div class='card-header'>Get Started</div>", unsafe_allow_html=True)
                st.markdown("""
                1. Click the 'Upload File' button below to add files
                2. Use 'View Files' to browse and preview your files
                3. Encrypt important files for added security
                """)
                
                if st.button("📤 Upload Your First File", use_container_width=True):
                    st.session_state.navigate_to = "Upload File"
                    st.rerun()
                
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col2:
                if lottie_upload:
                    st_lottie(lottie_upload, height=200, key="upload_animation")

    # Handle navigation from buttons
    if 'navigate_to' in st.session_state:
        if st.session_state.navigate_to == "Upload File":
            # Code for Upload File page
            st.header("📤 Upload Your Files")
            col1, col2 = st.columns([2, 1])
            
            with col1:
                uploaded_file = st.file_uploader("Choose a file to upload", 
                    type=["txt", "pdf", "jpg", "png", "csv", "xlsx"])
                if uploaded_file:
                    with st.spinner('Uploading file...'):
                        file_save_path = save_file(uploaded_file)
                        time.sleep(1)  # Simulate processing
                        st.success(f"File saved successfully at {file_save_path}")
                        st.balloons()
            
            with col2:
                if lottie_upload:
                    st_lottie(lottie_upload, height=200)
                else:
                    st.image("https://img.icons8.com/color/96/000000/upload-to-cloud.png", width=200)
            
            # Clear navigation state after processing
            del st.session_state.navigate_to
        
        elif st.session_state.navigate_to == "View Files":
            # Code for View Files page
            st.header("📁 File Explorer")
            view_files_enhanced()
            
            # Clear navigation state after processing
            del st.session_state.navigate_to
    
    # Process other menu choices as before
    elif choice == "Upload File":
        st.header("📤 Upload Your Files")
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader("Choose a file to upload", 
                type=["txt", "pdf", "jpg", "png", "csv", "xlsx"])
            if uploaded_file:
                with st.spinner('Uploading file...'):
                    file_save_path = save_file(uploaded_file)
                    time.sleep(1)  # Simulate processing
                    st.success(f"File saved successfully at {file_save_path}")
                    st.balloons()
        
        with col2:
            if lottie_upload:
                st_lottie(lottie_upload, height=200)
            else:
                st.image("https://img.icons8.com/color/96/000000/upload-to-cloud.png", width=200)

    elif choice == "View Files":
        st.header("📁 File Explorer")
        view_files_enhanced()

    elif choice == "File Encryption":
        st.header("🔐 File Encryption & Decryption")
        
        tabs = st.tabs(["Encrypt", "Decrypt"])
        
        with tabs[0]:
            encrypt_tab()
        
        with tabs[1]:
            decrypt_tab()

# Utility Functions
def save_file(uploaded_file):
    folder = "uploaded_files"
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path


def view_files_enhanced():
    folder = "uploaded_files"
    if not os.path.exists(folder):
        st.warning("No files uploaded yet.")
    else:
        files_data = []
        # Only get non-encrypted files and skip files that end with _decrypted
        for root, _, files in os.walk(folder):
            for file in files:
                # Skip encrypted files and files that were results of decryption
                if not file.endswith('.enc') and not "_decrypted" in file:
                    file_path = os.path.join(root, file)
                    size = os.path.getsize(file_path)
                    modified = os.path.getmtime(file_path)
                    files_data.append({
                        "File Name": file,
                        "Size (KB)": round(size/1024, 2),
                        "Last Modified": pd.to_datetime(modified, unit='s'),
                        "Type": os.path.splitext(file)[1].upper()[1:] or "No Extension"
                    })
        
        if files_data:
            st.write("📁 Available Files")
            df = pd.DataFrame(files_data)
            st.dataframe(df, use_container_width=True)
            
            # File statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Files", len(files_data))
            with col2:
                st.metric("Total Size (KB)", round(sum(df["Size (KB)"]), 2))
            with col3:
                st.metric("Latest Upload", df["Last Modified"].max().strftime("%Y-%m-%d %H:%M"))

            # File preview section
            st.markdown("---")
            st.subheader("📄 File Preview")
            
            selected_file = st.selectbox("Select a file to view:", df["File Name"].tolist())
            if selected_file:
                file_path = os.path.join(folder, selected_file)
                file_extension = os.path.splitext(selected_file)[1].lower()
                
                # Preview file based on type
                try:
                    if file_extension in ['.txt', '.csv']:
                        with open(file_path, 'r', encoding='utf-8') as file:
                            content = file.read()
                            st.text_area("File Content", content, height=300)
                    
                    elif file_extension in ['.jpg', '.jpeg', '.png']:
                        st.image(file_path, caption=selected_file)
                    
                    elif file_extension == '.pdf':
                        st.warning("PDF preview is not available. Please download to view.")
                    
                    elif file_extension in ['.xlsx', '.xls']:
                        df = pd.read_excel(file_path)
                        st.dataframe(df, use_container_width=True)
                    
                    else:
                        st.info("Preview not available for this file type.")

                    # Add download button
                    with open(file_path, "rb") as file:
                        st.download_button(
                            label="📥 Download File",
                            data=file,
                            file_name=selected_file,
                            mime="application/octet-stream"
                        )
                
                except Exception as e:
                    st.error(f"Error previewing file: {str(e)}")
        else:
            st.info("No viewable files available.")

        # Show count of encrypted files
        encrypted_files = [f for f in os.listdir(folder) if f.endswith('.enc')]
        if encrypted_files:
            st.markdown("---")
            st.info(f"🔒 There are {len(encrypted_files)} encrypted files. Go to File Encryption > Decrypt to access them.")

def encrypt_tab():
    folder = "uploaded_files"
    if not os.path.exists(folder):
        st.warning("No files available for encryption. Please upload files first.")
        return
    
    files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not f.endswith('.enc')]
    
    if not files:
        st.warning("No files available for encryption. Please upload files first.")
        return
    
    st.write("📝 Select a file and set a strong password for encryption")
    selected_file = st.selectbox("Select file to encrypt:", files)
    file_to_encrypt = os.path.join(folder, selected_file)
    
    # Add password strength requirements
    st.write("Password requirements:")
    st.write("- Minimum 8 characters")
    st.write("- At least one uppercase letter")
    st.write("- At least one number")
    
    password = st.text_input("Enter encryption password:", type="password")
    confirm_password = st.text_input("Confirm encryption password:", type="password")
    
    if st.button("🔒 Encrypt File", use_container_width=True):
        if not selected_file:
            st.warning("Please select a file!")
            return
            
        if not password or not confirm_password:
            st.warning("Please enter and confirm your password!")
            return
            
        if password != confirm_password:
            st.error("Passwords do not match!")
            return
            
        # Check password strength
        if len(password) < 8:
            st.error("Password must be at least 8 characters long!")
            return
            
        if not any(c.isupper() for c in password):
            st.error("Password must contain at least one uppercase letter!")
            return
            
        if not any(c.isdigit() for c in password):
            st.error("Password must contain at least one number!")
            return
        
        with st.spinner("Encrypting file..."):
            encrypt_file(file_to_encrypt, password)

def decrypt_tab():
    folder = "uploaded_files"
    if not os.path.exists(folder):
        st.warning("No files available for decryption. Please upload files first.")
        return
    
    # Get only encrypted files
    encrypted_files = [f for f in os.listdir(folder) if f.endswith('.enc')]
    
    if not encrypted_files:
        st.warning("No encrypted files available for decryption.")
        return
    
    # Show encrypted files details
    encrypted_files_data = []
    for file in encrypted_files:
        file_path = os.path.join(folder, file)
        size = os.path.getsize(file_path)
        modified = os.path.getmtime(file_path)
        original_name = file.replace('.enc', '')
        encrypted_files_data.append({
            "Encrypted File": file,
            "Original Name": original_name,
            "Size (KB)": round(size/1024, 2),
            "Encrypted On": pd.to_datetime(modified, unit='s').strftime("%Y-%m-%d %H:%M")
        })
    
    st.write("🔒 Encrypted Files")
    df_encrypted = pd.DataFrame(encrypted_files_data)
    st.dataframe(df_encrypted, use_container_width=True)
    
    # Decryption interface
    st.markdown("---")
    st.write("🔓 Decrypt File")
    selected_file = st.selectbox("Select file to decrypt:", encrypted_files)
    
    if selected_file:
        file_to_decrypt = os.path.join(folder, selected_file)
        password = st.text_input("Enter decryption password:", type="password")
        
        if st.button("🔓 Decrypt File", use_container_width=True):
            if not password:
                st.warning("Please enter the password!")
                return
            
            with st.spinner("Decrypting file..."):
                decrypt_file(file_to_decrypt, password)

# File Encryption and Decryption using password-based key
def generate_key(password):
    # Use the entire SHA-256 hash for better security
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(file_path, password):
    try:
        key = generate_key(password)
        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = bytearray()
        # Use the entire key for encryption
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]  # Cycle through all key bytes
            encrypted_data.append(byte ^ key_byte)

        # Add password verification hash to the encrypted data
        password_hash = hashlib.sha256(password.encode()).hexdigest()[:32]
        encrypted_data = password_hash.encode() + encrypted_data

        encrypted_file_path = f"{file_path}.enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_data)

        # Remove original file (optional - can be uncommented if you want to remove the original after encryption)
        # os.remove(file_path)

        st.success(f"File encrypted and saved as {os.path.basename(encrypted_file_path)}")
        st.info("Please remember your password. Files can only be decrypted with the same password used for encryption.")
        
    except Exception as e:
        st.error(f"Encryption failed: {str(e)}")

def decrypt_file(file_path, password):
    try:
        key = generate_key(password)
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract password verification hash
        stored_hash = data[:32].decode()
        encrypted_data = data[32:]

        # Verify password
        current_hash = hashlib.sha256(password.encode()).hexdigest()[:32]
        if stored_hash != current_hash:
            st.error("Incorrect password! Please try again with the correct password.")
            return

        decrypted_data = bytearray()
        # Use the entire key for decryption
        for i, byte in enumerate(encrypted_data):
            key_byte = key[i % len(key)]  # Cycle through all key bytes
            decrypted_data.append(byte ^ key_byte)

        # Extract the original file name without the .enc extension
        original_file_name = os.path.basename(file_path).replace(".enc", "")
        original_file_path = os.path.join(os.path.dirname(file_path), original_file_name)
        
        # If the file already exists, add a suffix
        if os.path.exists(original_file_path):
            file_name, file_ext = os.path.splitext(original_file_name)
            original_file_path = os.path.join(
                os.path.dirname(file_path), 
                f"{file_name}_{int(time.time())}{file_ext}"
            )

        with open(original_file_path, "wb") as f:
            f.write(decrypted_data)

        st.success(f"File decrypted and saved as {os.path.basename(original_file_path)}")
        
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    main()

# python.exe -m pip install --upgrade pip
# pip install -r requirements.txt
# streamlit run app.py

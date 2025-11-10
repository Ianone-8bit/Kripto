
import os
import io
import time
import base64
import mysql.connector
import streamlit as st
from PIL import Image


from kripto import (
    hash_password,
    verify_password,
    encrypt_email_cast5,
    decrypt_email_cast5,
    encrypt_title_super,
    decrypt_title_super,
    derive_key_from_message,
    encrypt_file_bytes_ctr,
    decrypt_file_bytes_ctr,
    encode_edge_lsb_bytes,
    decode_edge_lsb_bytes
)

# ---------------------------
# Config: Database & Folders
# ---------------------------
DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "crypto"
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COVERS_DIR = os.path.join(BASE_DIR, "assets", "covers")
BOOKS_DIR = os.path.join(BASE_DIR, "assets", "buku")
os.makedirs(COVERS_DIR, exist_ok=True)
os.makedirs(BOOKS_DIR, exist_ok=True)

# ---------------------------
# Database Operations
# ---------------------------
def get_connection():
    """Get MySQL connection"""
    conn = mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"]
    )
    try:
        conn.database = DB_CONFIG["database"]
    except Exception:
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        conn.database = DB_CONFIG["database"]
        cur.close()
    return conn


def register_user_db(nama, email_plain, password):
    """Register new user with encrypted email and hashed password"""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    # Check duplicate email (by decrypting existing emails)
    cur.execute("SELECT id, email FROM user")
    rows = cur.fetchall()
    for r in rows:
        try:
            dec = decrypt_email_cast5(r["email"])
            if dec.lower() == email_plain.lower():
                cur.close()
                conn.close()
                return False, "Email sudah terdaftar."
        except Exception:
            continue

    # Encrypt email and hash password
    enc_email = encrypt_email_cast5(email_plain)
    pw_hash_hex, salt_hex = hash_password(password)
    salt_bytes = bytes.fromhex(salt_hex)
    
    try:
        cur_ins = conn.cursor()
        cur_ins.execute(
            "INSERT INTO user (nama_lengkap, email, password_hash, salt, role) VALUES (%s,%s,%s,%s,%s)",
            (nama, enc_email, pw_hash_hex, salt_bytes, 'user')
        )
        conn.commit()
        cur_ins.close()
    except mysql.connector.IntegrityError:
        cur.close()
        conn.close()
        return False, "Email sudah terdaftar."
    except Exception as e:
        cur.close()
        conn.close()
        return False, f"Error DB: {e}"
    
    cur.close()
    conn.close()
    return True, "Berhasil membuat akun."

def find_user_by_email_plain(email_plain):
    """Find user by plain email (decrypt and compare)"""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM user")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    
    for r in rows:
        try:
            dec = decrypt_email_cast5(r["email"])
            if dec.lower() == email_plain.lower():
                salt_val = r.get("salt")
                if isinstance(salt_val, (bytes, bytearray)):
                    salt_hex = salt_val.hex()
                else:
                    try:
                        salt_hex = salt_val.hex()
                    except Exception:
                        import binascii
                        salt_hex = binascii.hexlify(
                            salt_val.encode() if isinstance(salt_val, str) else salt_val
                        ).decode()
                
                return {
                    "id": r["id"],
                    "nama_lengkap": r["nama_lengkap"],
                    "email_enc": r["email"],
                    "password_hash": r["password_hash"],
                    "salt_hex": salt_hex,
                    "role": r["role"]
                }
        except Exception:
            continue
    return None

def save_book_record_db(judul_enc_hex, author, cover_relpath, file_relpath):
    """Save book record to database"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO buku (judul, author, cover, file_pdf) VALUES (%s,%s,%s,%s)",
        (judul_enc_hex, author, cover_relpath, file_relpath)
    )
    conn.commit()
    cur.close()
    conn.close()

def list_books_db():
    """List all books from database"""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM buku ORDER BY id DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def get_book_by_id(book_id):
    """Get book by ID"""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM buku WHERE id=%s", (book_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

#UI
st.set_page_config(page_title="Web Baca BukuKriptografi", layout="wide")
st.title("📚 Web Baca Buku Kriptografi")

# SESIION
if "user" not in st.session_state:
    st.session_state["user"] = None
if "decrypted_books" not in st.session_state:
    st.session_state["decrypted_books"] = {}

# LOGIN
if not st.session_state["user"]:
    tab_login, tab_signup = st.tabs(["🔐 Login", "📝 Sign Up"])

    with tab_login:
        st.header("Login")
        email = st.text_input("Email", key="li_email")
        password = st.text_input("Password", type="password", key="li_pass")
        
        if st.button("Masuk", key="li_btn"):
            user = find_user_by_email_plain(email)
            if not user:
                st.error("Email tidak ditemukan.")
            elif verify_password(password, user["password_hash"], user["salt_hex"]):
                st.success(f"Login berhasil. Selamat datang, {user['nama_lengkap']}!")
                st.session_state["user"] = user
                st.rerun()
            else:
                st.error("Password salah.")

        st.markdown("Belum punya akun? pilih **Sign Up** di atas.")

    with tab_signup:
        st.header("Daftar Akun Baru")
        nama = st.text_input("Nama Lengkap", key="su_nama")
        email = st.text_input("Email", key="su_email")
        password = st.text_input("Password", type="password", key="su_pass")
        
        if st.button("Daftar", key="su_btn"):
            if not nama or not email or not password:
                st.warning("Lengkapi semua field.")
            else:
                ok, msg = register_user_db(nama, email, password)
                if ok:
                    st.success("Akun berhasil dibuat. Silakan login di tab Login.")
                else:
                    st.error(msg)


#MENU
else:
    user = st.session_state["user"]
    
    # Sidebar
    st.sidebar.write(f"Login sebagai: **{user['nama_lengkap']}** ({user['role']})")
    
    if st.sidebar.button("🚪 Logout"):
        st.session_state["user"] = None
        st.session_state["decrypted_books"] = {}
        st.rerun()
    
    st.sidebar.markdown("---")
    
    if user["role"] == "admin":
        menu = st.sidebar.selectbox("Menu", ["Daftar Buku", "Upload Buku", "Ekstrak Pesan dari Cover"])
    else:
        menu = st.sidebar.selectbox("Menu", ["Daftar Buku", "Dekripsi Buku", "Ekstrak Pesan dari Cover"])

   
    if menu == "Daftar Buku":
        st.header("📘 Daftar Buku")
        rows = list_books_db()
        
        if not rows:
            st.info("Belum ada buku.")
        else:
            for b in rows:
                st.markdown("---")
                col1, col2 = st.columns([1, 3])
                
                with col1:
                    if b["cover"] and os.path.exists(b["cover"]):
                        st.image(b["cover"], use_container_width=True)
                        
                        # Download cover stego button
                        with open(b["cover"], "rb") as f:
                            cover_bytes = f.read()
                        st.download_button(
                            label="⬇️ Download Cover",
                            data=cover_bytes,
                            file_name=f"cover_stego_{b['id']}.png",
                            mime="image/png",
                            key=f"dl_cover_{b['id']}"
                        )
                    else:
                        st.text("Cover tidak ditemukan")
                
                with col2:
                    st.write(f"**ID Buku:** {b['id']}")
                    st.write(f"**Author:** {b['author']}")
                    st.write("**Judul (terenkripsi):**")
                    st.code(b["judul"][:100] + "...", language="text")
                    
                    # Check if decrypted
                    if b['id'] in st.session_state["decrypted_books"]:
                        book_data = st.session_state["decrypted_books"][b['id']]
                        st.success(f"✅ **Judul:** {book_data['title']}")
                        
                        st.download_button(
                            label="📥 Download PDF",
                            data=book_data['pdf_bytes'],
                            file_name=f"{book_data['title']}.pdf",
                            mime="application/pdf",
                            key=f"dl_pdf_{b['id']}"
                        )
                    else:
                        st.info(" Buku terenkripsi. Gunakan menu Dekripsi untuk membuka.")

# UPLOAD BUKU
    elif menu == "Upload Buku":
        st.header("📤 Upload Buku Baru")
        
        with st.form(key="admin_form"):
            title = st.text_input("Judul Buku")
            author = st.text_input("Author")
            secret_msg = st.text_input("Pesan Rahasia", help="Pesan ini akan disembunyikan di cover")
            
            col1, col2 = st.columns(2)
            with col1:
                cover_file = st.file_uploader("Cover (PNG)", type=["png"])
            with col2:
                pdf_file = st.file_uploader("File PDF", type=["pdf"])
            
            submit = st.form_submit_button("🔒 Upload & Enkripsi", use_container_width=True)

            if submit:
                if not (title and author and secret_msg and cover_file and pdf_file):
                    st.error("⚠️ Lengkapi semua field!")
                else:
                    with st.spinner("Mengenkripsi buku..."):
                        try:
                            # 1. Encrypt title (Playfair + AES-192-CBC)
                            judul_enc_hex = encrypt_title_super(title)
                            
                            # 2. Embed message in cover (Edge-LSB)
                            cover_bytes = cover_file.read()
                            stego_bytes = encode_edge_lsb_bytes(cover_bytes, secret_msg)
                            
                            timestamp = str(int(time.time()))
                            cover_path = os.path.join(COVERS_DIR, f"cover_{timestamp}.png")
                            with open(cover_path, "wb") as f:
                                f.write(stego_bytes)
                            
                            # 3. Encrypt PDF (AES-256-CTR)
                            pdf_bytes = pdf_file.read()
                            key = derive_key_from_message(secret_msg)
                            enc_pdf = encrypt_file_bytes_ctr(pdf_bytes, key)
                            
                            pdf_path = os.path.join(BOOKS_DIR, f"book_{timestamp}.enc")
                            with open(pdf_path, "wb") as f:
                                f.write(enc_pdf)
                            
                            # 4. Save to database
                            save_book_record_db(judul_enc_hex, author, cover_path, pdf_path)
                            
                            st.success("🎉 Buku berhasil diupload!")
                            st.balloons()
                            time.sleep(1)
                            st.rerun()
                            
                        except Exception as e:
                            st.error(f"❌ Error: {e}")

    #DESKRIPSI BUKU
    elif menu == "Dekripsi & Baca Buku":
        st.header("🔓 Dekripsi & Baca Buku")
        
        books = list_books_db()
        if not books:
            st.info("Belum ada buku tersedia.")
        else:
            book_options = {f"{b['id']} - {b['author']}": b['id'] for b in books}
            selected = st.selectbox("Pilih Buku", list(book_options.keys()))
            book_id = book_options[selected]
            book = get_book_by_id(book_id)
            
            if book:
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    if book["cover"] and os.path.exists(book["cover"]):
                        st.image(book["cover"], use_container_width=True)
                
                with col2:
                    st.write(f"**Author:** {book['author']}")
                    
                    # Check if already decrypted
                    if book_id in st.session_state["decrypted_books"]:
                        book_data = st.session_state["decrypted_books"][book_id]
                        st.success(f"✅ **Judul:** {book_data['title']}")
                        
                        # Display PDF
                        b64_pdf = base64.b64encode(book_data['pdf_bytes']).decode()
                        pdf_display = f'<iframe src="data:application/pdf;base64,{b64_pdf}" width="100%" height="800px"></iframe>'
                        st.markdown(pdf_display, unsafe_allow_html=True)
                        
                        # Download button
                        st.download_button(
                            label="📥 Download PDF",
                            data=book_data['pdf_bytes'],
                            file_name=f"{book_data['title']}.pdf",
                            mime="application/pdf"
                        )
                        
                        if st.button("🔄 Dekripsi Ulang"):
                            del st.session_state["decrypted_books"][book_id]
                            st.rerun()
                    
                    else:
                        # Decryption form
                        st.markdown("### 🔑 Masukkan Pesan Rahasia")
                        secret_msg = st.text_input(
                            "Pesan dari Cover",
                            type="password",
                            key=f"secret_{book_id}"
                        )
                        
                        if st.button("🔓 Dekripsi", use_container_width=True):
                            if not secret_msg:
                                st.error("⚠️ Masukkan pesan rahasia!")
                            else:
                                with st.spinner("Mendekripsi..."):
                                    try:
                                        # Decrypt title
                                        title_plain = decrypt_title_super(book["judul"])
                                        st.success(f"✅ Judul: **{title_plain}**")
                                        
                                        # Decrypt PDF
                                        with open(book["file_pdf"], "rb") as f:
                                            enc_pdf = f.read()
                                        
                                        key = derive_key_from_message(secret_msg)
                                        pdf_bytes = decrypt_file_bytes_ctr(enc_pdf, key)
                                        
                                        # Verify PDF
                                        if pdf_bytes[:4] == b'%PDF':
                                            st.success("✅ PDF terdekripsi!")
                                            st.session_state["decrypted_books"][book_id] = {
                                                "title": title_plain,
                                                "pdf_bytes": pdf_bytes
                                            }
                                            st.balloons()
                                            time.sleep(1)
                                            st.rerun()
                                        else:
                                            st.error("❌ Pesan rahasia salah!")
                                    
                                    except Exception as e:
                                        st.error(f"❌ Gagal dekripsi: {e}")

    #EKSTRAKS PESAN
    elif menu == "Ekstrak Pesan dari Cover":
        st.header("🕵️ Ekstrak Pesan dari Cover")
        
        uploaded = st.file_uploader("Upload Cover (PNG)", type=["png"])
        
        if uploaded:
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.image(uploaded, use_container_width=True)
            
            with col2:
                if st.button("🔍 Ekstrak Pesan", use_container_width=True):
                    with st.spinner("Mengekstrak..."):
                        try:
                            uploaded.seek(0)
                            pesan = decode_edge_lsb_bytes(uploaded.read())
                            
                            if pesan:
                                st.success("✅ Pesan ditemukan!")
                                st.text_area(" Pesan:", value=pesan, height=150)
                                
                                st.download_button(
                                    label=" Salin",
                                    data=pesan,
                                    file_name="pesan_rahasia.txt"
                                )
                            else:
                                st.warning("⚠️ Tidak ada pesan tersembunyi")
                        
                        except Exception as e:
                            st.error(f" Error: {e}")
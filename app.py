import streamlit as st
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pandas as pd
from io import StringIO
import logging
from dataclasses import dataclass
from typing import Optional, Tuple, List
from data_vizz import process_uploaded_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Configuration
@dataclass
class Config:
    USER_DB_PATH: str = 'user_data.db'
    DOC_DB_PATH: str = 'documents.db'
    MIN_PASSWORD_LENGTH: int = 8
    SESSION_EXPIRE_HOURS: int = 24


# Database Models
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the database with proper schema and indices."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()

                # Create users table with improved schema
                c.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE,
                        failed_login_attempts INTEGER DEFAULT 0,
                        last_failed_login TIMESTAMP
                    )
                ''')

                # Create index on username for faster lookups
                c.execute('''
                    CREATE INDEX IF NOT EXISTS idx_username
                    ON users(username)
                ''')

                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise


class DocumentDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the document database with proper schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()

                # Create documents table
                c.execute('''
                    CREATE TABLE IF NOT EXISTS documents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        document_name TEXT NOT NULL,
                        document_content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Document database initialization error: {e}")
            raise


class SecurityService:
    ph = PasswordHasher()

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using argon2 and return as string."""
        return SecurityService.ph.hash(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash stored as string."""
        try:
            return SecurityService.ph.verify(hashed, password)
        except VerifyMismatchError:
            return False

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        return True, "Password is valid"


class UserService:
    def __init__(self, db: Database, security: SecurityService):
        self.db = db
        self.security = security

    def create_user(self, username: str, password: str, name: str, email: str) -> bool:
        try:
            # Validate password
            is_valid, msg = self.security.validate_password(password)
            if not is_valid:
                st.error(msg)
                return False

            # Hash password and create user
            password_hash = self.security.hash_password(password)

            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO users (username, password_hash, name, email)
                    VALUES (?, ?, ?, ?)
                """, (username, password_hash, name, email))
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            st.error("Username or email already exists")
            return False
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            st.error("An error occurred while creating the user")
            return False

    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                result = c.fetchone()

                if result and self.security.verify_password(password, result[0]):
                    # Update last login timestamp
                    c.execute("""
                        UPDATE users
                        SET last_login = CURRENT_TIMESTAMP
                        WHERE username = ?
                    """, (username,))
                    conn.commit()
                    return username
                return None
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return None

    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                result = c.fetchone()

                if result and self.security.verify_password(current_password, result[0]):
                    is_valid, msg = self.security.validate_password(new_password)
                    if not is_valid:
                        st.error(msg)
                        return False

                    new_password_hash = self.security.hash_password(new_password)
                    c.execute("""
                        UPDATE users
                        SET password_hash = ?
                        WHERE username = ?
                    """, (new_password_hash, username))
                    conn.commit()
                    return True
                else:
                    st.error("Current password is incorrect")
                    return False
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False


class DocumentService:
    def __init__(self, db: DocumentDatabase):
        self.db = db

    def get_user_documents(self, username: str) -> List[dict]:
        """Retrieve user's documents."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT id, document_name, document_content FROM documents WHERE username = ?", (username,))
                result = c.fetchall()
                return [{"id": row[0], "name": row[1], "content": row[2]} for row in result]
        except Exception as e:
            logger.error(f"Error retrieving documents: {e}")
            return []

    def get_document_by_name(self, username: str, document_name: str) -> Optional[dict]:
        """Retrieve a specific document by name for a user."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT id, document_name, document_content
                    FROM documents
                    WHERE username = ? AND document_name = ?
                """, (username, document_name))
                result = c.fetchone()
                if result:
                    return {"id": result[0], "name": result[1], "content": result[2]}
                return None
        except Exception as e:
            logger.error(f"Error retrieving document: {e}")
            return None

    def add_document(self, username: str, document: dict) -> bool:
        """Add a new document to user's documents."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO documents (username, document_name, document_content)
                    VALUES (?, ?, ?)
                """, (username, document['name'], document['content']))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error adding document: {e}")
            return False

    def delete_document(self, document_id: int) -> bool:
        """Delete a document by its ID."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                c = conn.cursor()
                c.execute("DELETE FROM documents WHERE id = ?", (document_id,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            return False


class UI:
    @staticmethod
    def navigate_to(destination):
        """Callback function for navigation"""
        if 'navigation_callback' not in st.session_state:
            st.session_state.navigation_callback = destination
            st.rerun()

    @staticmethod
    def render_login_page() -> Tuple[str, str, bool]:
        st.title("📊 Welcome to Data Analysis Platform")

        # Two-column layout for login form
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("""
                ### Sign in to your account
                Don't have an account? Use the sidebar menu to sign up!
            """)

            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                login_clicked = st.form_submit_button("Login", use_container_width=True)

        return username, password, login_clicked

    @staticmethod
    def render_signup_page() -> Tuple[str, str, str, str, bool]:
        st.title("Create Your Account")

        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("signup_form"):
                st.markdown("### Let's get you started!")

                username = st.text_input("Username", placeholder="Choose a unique username")
                name = st.text_input("Full Name", placeholder="Enter your full name")
                email = st.text_input("Email", placeholder="Enter your email address")

                # Password field with requirements display
                st.markdown("##### Password Requirements:")
                st.markdown("""
                - At least 8 characters long
                - One uppercase letter
                - One lowercase letter
                - One number
                """)
                password = st.text_input("Password", type="password", placeholder="Create a strong password")

                signup_clicked = st.form_submit_button("Create Account", use_container_width=True)

        return username, password, name, email, signup_clicked

    @staticmethod
    def render_main_page(username: str, user_service: UserService, document_service: DocumentService):
        st.title("Data Analysis Dashboard")

        # Enhanced sidebar with better organization
        with st.sidebar:
            st.title(f"👤 {username}")
            st.markdown("---")

            menu = ["📊 Dashboard", "📈 Data Exploration", "📁 My Documents", "⚙️ Settings"]
            selected_menu = st.radio("Navigation", menu)

        # Initialize the upload status in session state if it doesn't exist
        if 'upload_status' not in st.session_state:
            st.session_state.upload_status = None

        # Render page content based on menu selection
        if selected_menu == "📊 Dashboard":
            st.write("## Welcome to Your Dashboard")

            # Quick stats
            col1, col2 = st.columns(2)
            with col1:
                documents = document_service.get_user_documents(username)
                st.metric("Total Documents", len(documents))

            # File upload section with better guidance
            st.markdown("### Upload New Data")
            upload_col1, upload_col2 = st.columns([2, 1])
            with upload_col1:
                uploaded_file = st.file_uploader(
                    "Drag and drop your file here",
                    type=["csv", "txt", "xlsx", "xls", "html"],
                    help="Supported formats: CSV, TXT, Excel files",
                    key="dashboard_file_uploader"
                )
            with upload_col2:
                st.markdown("""
                    #### Supported Files
                    - CSV files
                    - Excel sheets
                    - Text files
                    - HTML tables
                """)

            if uploaded_file is not None:
                # Check if this file hasn't been processed yet
                file_id = f"{uploaded_file.name}_{uploaded_file.size}"

                # Only process if we haven't shown a success message for this file
                if st.session_state.upload_status != file_id:
                    with st.spinner('Processing your file...'):
                        try:
                            df, content = process_uploaded_file(uploaded_file)
                            document = {
                                'name': uploaded_file.name,
                                'content': content
                            }
                            if document_service.add_document(username, document):
                                st.session_state.upload_status = file_id
                                st.success("✅ File uploaded successfully!")
                                st.balloons()
                            else:
                                st.error("❌ Failed to upload file")
                        except Exception as e:
                            st.error(f"Error processing file: {str(e)}")
                            st.info("Please ensure your file is properly formatted and try again.")

        elif selected_menu == "📁 My Documents":
            st.write("### Your Document Library")
            documents = document_service.get_user_documents(username)

            if documents:
                # Create a more visual document selection interface
                for doc in documents:
                    with st.expander(f"📄 {doc['name']}", expanded=False):
                        col1, col2, col3 = st.columns([2, 1, 1])
                        with col1:
                            st.markdown(f"**Upload date:** {doc.get('created_at', 'N/A')}")
                        with col2:
                            if st.button("📊 Analyze", key=f"analyze_{doc['id']}"):
                                try:
                                    df = pd.read_csv(StringIO(doc['content']))
                                    st.session_state['current_df'] = df
                                    st.session_state['current_document'] = doc['name']
                                except Exception as e:
                                    st.error(f"Error loading document: {str(e)}")
                        with col3:
                            if st.button("🗑️ Delete", key=f"delete_{doc['id']}"):
                                if document_service.delete_document(doc['id']):
                                    st.success(f"Deleted {doc['name']}")
                                    st.rerun()
                                else:
                                    st.error("Failed to delete document")
            else:
                st.info("📭 Your document library is empty. Upload some data to get started!")

        elif selected_menu == "📈 Data Exploration":
            if 'current_df' in st.session_state:
                st.write(f"### Analyzing: {st.session_state.get('current_document', 'Dataset')}")
                from data_vizz import perform_data_exploration
                perform_data_exploration(username, st.session_state['current_df'])
            else:
                st.warning("⚠️ No dataset selected for analysis")
                st.info("Please select a document from your library to begin analysis")

        elif selected_menu == "⚙️ Settings":
            st.write("### Account Settings")
            with st.expander("Change Password"):
                with st.form("change_password"):
                    current_password = st.text_input("Current Password", type="password")
                    new_password = st.text_input("New Password", type="password")
                    confirm_password = st.text_input("Confirm New Password", type="password")
                    if st.form_submit_button("Update Password"):
                        if new_password != confirm_password:
                            st.error("New passwords do not match")
                        else:
                            if user_service.change_password(username, current_password, new_password):
                                st.success("Password updated successfully")
                            else:
                                st.error("Failed to update password")


def main():
    # Initialize services
    st.set_page_config(
        page_title="Data Analysis Platform",
        page_icon="📊",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    user_db = Database(Config.USER_DB_PATH)
    doc_db = DocumentDatabase(Config.DOC_DB_PATH)
    security_service = SecurityService()
    user_service = UserService(user_db, security_service)
    document_service = DocumentService(doc_db)

    # Session state management
    if 'authenticated_user' not in st.session_state:
        st.session_state.authenticated_user = None

    # Handle navigation callback
    if 'navigation_callback' in st.session_state:
        destination = st.session_state.navigation_callback
        del st.session_state.navigation_callback
        st.radio("Navigation", ["📊 Dashboard", "📈 Data Exploration", "📁 My Documents", "⚙️ Settings"],
                 key="navigation",
                 index=["📊 Dashboard", "📈 Data Exploration", "📁 My Documents", "⚙️ Settings"].index(destination))

    # Main application flow
    if st.session_state.authenticated_user:
        st.sidebar.title(f"Welcome {st.session_state.authenticated_user}")
        UI.render_main_page(st.session_state.authenticated_user, user_service, document_service)

        if st.sidebar.button("Logout"):
            st.session_state.authenticated_user = None
            st.session_state.upload_status = None  # Clear upload status on logout
            st.rerun()
    else:
        menu = ["Login", "Sign Up"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Login":
            username, password, login_clicked = UI.render_login_page()
            if login_clicked:
                if authenticated_user := user_service.authenticate_user(username, password):
                    st.session_state.authenticated_user = authenticated_user
                    st.rerun()
                else:
                    st.error("Invalid username or password")

        elif choice == "Sign Up":
            username, password, name, email, signup_clicked = UI.render_signup_page()
            if signup_clicked:
                if user_service.create_user(username, password, name, email):
                    st.success("Account created successfully! Please login.")


if __name__ == '__main__':
    main()
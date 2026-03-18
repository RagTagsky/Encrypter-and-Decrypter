import sys
import os
import threading
import time
import base64
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ----------------------------------------------------------------------
# Configuration & Constants
# ----------------------------------------------------------------------

# Cryptography Settings
CHUNK_SIZE = 64 * 1024  # 64 KB
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LENGTH = 32         # 256-bit key for AES-256

# Argon2id Parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

# UI Configuration
WINDOW_TITLE = "Encrypter & Decrypter"
WINDOW_GEOMETRY = "600x480"
MIN_WINDOW_SIZE = (550, 480)
THEME_MODE = "System"
ACCENT_COLOR = "blue"

# Fonts
FONT_PRIMARY_BOLD = ("Inter", 20, "bold")
FONT_TOAST_BOLD = ("Inter", 13, "bold")
FONT_LABEL_BOLD = ("Inter", 12, "bold")

# Toast Colors
COLORS = {
    "success": "#4CAF50",
    "error": "#F44336",
    "info": "#2196F3",
    "warning": "#FF9800",
    "danger_hover": "#D32F2F"
}

# ----------------------------------------------------------------------
# Core Cryptography Logic (Argon2id + AES-GCM)
# ----------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit key from a password and salt using Argon2id.

    Args:
        password: The input password string.
        salt: The salt bytes to use for derivation.

    Returns:
        The derived 256-bit key as bytes.
    """
    ph = PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        salt_len=SALT_SIZE
    )
    
    # Argon2id hash format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    hashed_str = ph.hash(password, salt=salt)
    raw_hash_b64 = hashed_str.split("$")[-1]
    
    # Decode the base64-encoded hash (adding padding if necessary)
    return base64.b64decode(raw_hash_b64 + "==")


def encrypt_file(input_path: str, output_path: str, password: str, progress_callback=None) -> bool | str:
    """
    Encrypts a file using AES-256 GCM with an Argon2id derived key.

    Args:
        input_path: Path to the source file.
        output_path: Path to save the encrypted file.
        password: Password for encryption.
        progress_callback: Optional function called with progress (float 0.0 to 1.0).

    Returns:
        True if successful, otherwise an error message string.
    """
    try:
        total_size = os.path.getsize(input_path)
        salt = os.urandom(SALT_SIZE)
        base_nonce = os.urandom(NONCE_SIZE)
        
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write header
            f_out.write(salt)
            f_out.write(base_nonce)
            
            bytes_read = 0
            chunk_index = 0
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                bytes_read += len(chunk)
                
                # Derive nonce for current chunk to prevent reuse
                current_nonce_int = int.from_bytes(base_nonce, 'big') + chunk_index
                current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                
                # Encrypt and package
                encrypted_chunk = aesgcm.encrypt(current_nonce, chunk, associated_data=None)
                chunk_len_bytes = len(encrypted_chunk).to_bytes(4, 'big')
                
                f_out.write(chunk_len_bytes)
                f_out.write(encrypted_chunk)
                
                chunk_index += 1
                
                if progress_callback and total_size > 0:
                    progress_callback(bytes_read / total_size)
                    
        if progress_callback:
            progress_callback(1.0)
            
        return True
    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_file(input_path: str, output_path: str, password: str, progress_callback=None) -> bool | str:
    """
    Decrypts a file using AES-256 GCM with an Argon2id derived key.

    Args:
        input_path: Path to the encrypted file.
        output_path: Path to save the decrypted file.
        password: Password for decryption.
        progress_callback: Optional function called with progress (float 0.0 to 1.0).

    Returns:
        True if successful, otherwise an error message string.
    """
    try:
        file_size = os.path.getsize(input_path)
        header_size = SALT_SIZE + NONCE_SIZE
        
        if file_size < header_size:
             return "File is too small to be a valid encrypted file."
             
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Read header
            salt = f_in.read(SALT_SIZE)
            base_nonce = f_in.read(NONCE_SIZE)
            
            try:
                key = derive_key(password, salt)
            except Exception:
                 return "Internal Error: Could not derive key."
            
            aesgcm = AESGCM(key)
            bytes_processed = header_size
            chunk_index = 0
            
            while bytes_processed < file_size:
                 # Read chunk metadata
                 chunk_len_bytes = f_in.read(4)
                 if not chunk_len_bytes:
                     break
                 
                 chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                 bytes_processed += 4
                 
                 encrypted_chunk = f_in.read(chunk_len)
                 bytes_processed += len(encrypted_chunk)
                 
                 # Derive expected nonce
                 current_nonce_int = int.from_bytes(base_nonce, 'big') + chunk_index
                 current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                 
                 # Decrypt and authenticate
                 try:
                     decrypted_chunk = aesgcm.decrypt(current_nonce, encrypted_chunk, associated_data=None)
                 except Exception:
                     # Critical failure: Password wrong or data corrupted
                     f_out.close()
                     if os.path.exists(output_path):
                        os.remove(output_path)
                     return "Authentication Failed: Incorrect password or corrupted data."
                 
                 f_out.write(decrypted_chunk)
                 chunk_index += 1
                 
                 if progress_callback and file_size > 0:
                      progress_callback(bytes_processed / file_size)
                      
        if progress_callback:
            progress_callback(1.0)
            
        return True
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        return f"Decryption failure: {str(e)}"

# ----------------------------------------------------------------------
# Modern CustomTkinter UI 
# ----------------------------------------------------------------------

class CTkEngine(ctk.CTk, TkinterDnD.DnDWrapper):
    """Base class for CustomTkinter with Drag and Drop support."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)


class ToastNotification(ctk.CTkFrame):
    """Modern animated toast notification widget."""
    def __init__(self, parent, message, notification_type="info", duration=3000):
        super().__init__(parent, fg_color="transparent", border_width=0)
        
        self.parent = parent
        self.message = message
        self.duration = duration
        
        bg_color = COLORS.get(notification_type, COLORS["info"])
        
        self.inner_frame = ctk.CTkFrame(self, corner_radius=15, fg_color=bg_color, border_width=0)
        self.inner_frame.pack(padx=0, pady=0)
        
        self.label = ctk.CTkLabel(
            self.inner_frame, 
            text=self.message, 
            text_color="white", 
            font=ctk.CTkFont(family=FONT_TOAST_BOLD[0], size=FONT_TOAST_BOLD[1], weight=FONT_TOAST_BOLD[2])
        )
        self.label.pack(padx=20, pady=10)
        
        self.target_y = 0.95
        self.current_y = 1.2 # Off-screen start
        self.place(relx=0.5, rely=self.current_y, anchor="s")
        
        self._animate_in()
        if self.duration > 0:
            self.after(self.duration, self._animate_out)
            
    def _animate_in(self):
        if self.current_y > self.target_y:
            self.current_y -= 0.02
            self.place(relx=0.5, rely=self.current_y, anchor="s")
            self.after(10, self._animate_in)
            
    def _animate_out(self):
        if self.current_y < 1.2:
            self.current_y += 0.02
            self.place(relx=0.5, rely=self.current_y, anchor="s")
            self.after(10, self._animate_out)
        else:
            self.destroy()


class App(CTkEngine):
    """Main application window."""
    def __init__(self):
        super().__init__()
        
        self._setup_window()
        self._create_widgets()
        self._setup_events()
        
    def _setup_window(self):
        """Configure main window properties."""
        self.title(WINDOW_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.minsize(MIN_WINDOW_SIZE[0], MIN_WINDOW_SIZE[1])
        
        ctk.set_appearance_mode(THEME_MODE) 
        ctk.set_default_color_theme(ACCENT_COLOR) 
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _create_widgets(self):
        """Initialize and layout components."""
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tab_pack = self.tabview.add("Pack 🔒")
        self.tab_unpack = self.tabview.add("Unpack 🔓")
        
        self._setup_packing_tab()
        self._setup_unpacking_tab()

    def _setup_packing_tab(self):
        """Build the encryption (Pack) tab."""
        tab = self.tab_pack
        tab.grid_columnconfigure(1, weight=1)
        
        # Header
        ctk.CTkLabel(tab, text="Secure Packing", font=ctk.CTkFont(family=FONT_PRIMARY_BOLD[0], size=FONT_PRIMARY_BOLD[1], weight=FONT_PRIMARY_BOLD[2])).grid(row=0, column=0, columnspan=2, pady=(10, 20))
        
        # Inputs
        self.pack_input = self._create_input_row(tab, "File to Encrypt:", "Drag and drop file here...", row=1)
        self.pack_output = self._create_input_row(tab, "Save As:", "Path to save encrypted file...", row=2)
        self.pack_pwd = self._create_input_row(tab, "Password:", "Enter a strong password...", row=3, is_password=True)
        self.pack_pwd_conf = self._create_input_row(tab, "Confirm:", "Confirm password...", row=4, is_password=True)
        
        # Progress
        self.pack_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.pack_progress.grid(row=5, column=0, columnspan=2, padx=10, pady=(15, 5), sticky="ew")
        self.pack_progress.set(0)
        
        # Action Button
        self.pack_btn = ctk.CTkButton(tab, text="Pack File 🚀", height=40, font=ctk.CTkFont(weight="bold"), command=self.handle_pack_action)
        self.pack_btn.grid(row=6, column=0, columnspan=2, padx=10, pady=15)

    def _setup_unpacking_tab(self):
        """Build the decryption (Unpack) tab."""
        tab = self.tab_unpack
        tab.grid_columnconfigure(1, weight=1)
        
        # Header
        ctk.CTkLabel(tab, text="Secure Unpacking", font=ctk.CTkFont(family=FONT_PRIMARY_BOLD[0], size=FONT_PRIMARY_BOLD[1], weight=FONT_PRIMARY_BOLD[2])).grid(row=0, column=0, columnspan=2, pady=(10, 20))
        
        # Inputs
        self.unpack_input = self._create_input_row(tab, "Encrypted File:", "Drag and drop encrypted file here...", row=1)
        self.unpack_output = self._create_input_row(tab, "Save As:", "Path to save decrypted file...", row=2)
        self.unpack_pwd = self._create_input_row(tab, "Password:", "Enter decryption password...", row=3, is_password=True)
        
        # Spacer
        ctk.CTkLabel(tab, text="").grid(row=4, column=0, pady=10)
        
        # Progress
        self.unpack_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.unpack_progress.grid(row=5, column=0, columnspan=2, padx=10, pady=(15, 5), sticky="ew")
        self.unpack_progress.set(0)
        
        # Action Button
        self.unpack_btn = ctk.CTkButton(tab, text="Unpack File 🔓", height=40, fg_color=COLORS["error"], hover_color=COLORS["danger_hover"], font=ctk.CTkFont(weight="bold"), command=self.handle_unpack_action)
        self.unpack_btn.grid(row=6, column=0, columnspan=2, padx=10, pady=15)

    def _create_input_row(self, parent, label_text, placeholder, row, is_password=False):
        """Helper to create a label and entry pair."""
        ctk.CTkLabel(parent, text=label_text, font=ctk.CTkFont(weight="bold")).grid(row=row, column=0, padx=10, pady=10, sticky="w")
        entry = ctk.CTkEntry(parent, placeholder_text=placeholder, show="*" if is_password else "")
        entry.grid(row=row, column=1, padx=10, pady=10, sticky="ew")
        return entry

    def _setup_events(self):
        """Bind global events."""
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self._handle_file_drop)
        self.bind("<Return>", lambda e: self._on_enter_pressed())

    def show_toast(self, message, m_type="info", duration=3000):
        """Shortcut for showing toast notifications."""
        ToastNotification(self, message, notification_type=m_type, duration=duration)

    def _handle_file_drop(self, event):
        """Process dragged and dropped files."""
        files = self.tk.splitlist(event.data)
        if not files:
            return
            
        file_path = files[0]
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
            
        # Context-aware routing
        if file_path.lower().endswith('.enc'):
            self.tabview.set("Unpack 🔓")
            self._update_entry(self.unpack_input, file_path)
            self._update_entry(self.unpack_output, file_path[:-4])
            self.show_toast("Encrypted file loaded.", "info", 1500)
        else:
            self.tabview.set("Pack 🔒")
            self._update_entry(self.pack_input, file_path)
            self._update_entry(self.pack_output, file_path + ".enc")
            self.show_toast("File ready for packing.", "info", 1500)

    def _update_entry(self, entry, text):
        """Helper to clear and update text in an entry."""
        entry.delete(0, 'end')
        entry.insert(0, text)

    def _on_enter_pressed(self):
        """Handle Enter key based on active tab."""
        active_tab = self.tabview.get()
        if active_tab == "Pack 🔒":
            self.handle_pack_action()
        else:
            self.handle_unpack_action()

    # ------------------------------------------------------------------
    # Action Handlers
    # ------------------------------------------------------------------

    def handle_pack_action(self):
        """Validate and start the encryption process."""
        input_path = self.pack_input.get()
        output_path = self.pack_output.get()
        password = self.pack_pwd.get()
        password_confirm = self.pack_pwd_conf.get()
        
        if not all([input_path, output_path, password]):
            self.show_toast("Required fields are missing.", "error")
            return
            
        if password != password_confirm:
            self.show_toast("Passwords do not match!", "error")
            return
            
        if not os.path.exists(input_path):
             self.show_toast("Source file not found.", "error")
             return
             
        self.pack_btn.configure(state="disabled", text="Packing...")
        self.pack_progress.set(0)
        
        threading.Thread(
            target=self._run_engine, 
            args=(encrypt_file, input_path, output_path, password, self.pack_progress, self.pack_btn, "Pack File 🚀"),
            daemon=True
        ).start()

    def handle_unpack_action(self):
        """Validate and start the decryption process."""
        input_path = self.unpack_input.get()
        output_path = self.unpack_output.get()
        password = self.unpack_pwd.get()
        
        if not all([input_path, output_path, password]):
            self.show_toast("Required fields are missing.", "error")
            return
            
        if not os.path.exists(input_path):
             self.show_toast("Encrypted file not found.", "error")
             return
             
        self.unpack_btn.configure(state="disabled", text="Unpacking...")
        self.unpack_progress.set(0)
        
        threading.Thread(
            target=self._run_engine, 
            args=(decrypt_file, input_path, output_path, password, self.unpack_progress, self.unpack_btn, "Unpack File 🔓"),
            daemon=True
        ).start()

    def _run_engine(self, engine_func, input_path, output_path, password, progress_bar, button, button_text):
        """Generic worker to handle core processing and UI updates."""
        success_msg = "Packed Successfully!" if engine_func.__name__ == "encrypt_file" else "Unpacked Successfully!"
        
        def update_progress(val):
            self.after(0, lambda: progress_bar.set(val))
            self.after(0, self.update_idletasks)

        result = engine_func(input_path, output_path, password, progress_callback=update_progress)
        
        if result is True:
            # Delete source file after success
            try:
                os.remove(input_path)
                self.after(0, lambda: self.show_toast(f"{success_msg} Source removed.", "success"))
            except Exception as e:
                self.after(0, lambda: self.show_toast(f"Done, but failed to cleanup source: {e}", "warning"))
        else:
             self.after(0, lambda: self.show_toast(f"Error: {result}", "error"))
             
        # Reset UI
        self.after(0, lambda: button.configure(state="normal", text=button_text))
        self.after(0, lambda: progress_bar.set(0))


if __name__ == "__main__":
    app = App()
    app.mainloop()

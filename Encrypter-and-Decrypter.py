import sys
import os
import threading
import time
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# ----------------------------------------------------------------------
# Core Cryptography Logic (Argon2id + AES-GCM)
# ----------------------------------------------------------------------
CHUNK_SIZE = 64 * 1024  # 64 KB
SALT_SIZE = 16
NONCE_SIZE = 12

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from a password and salt using Argon2id."""
    ph = PasswordHasher(
        time_cost=3,          # Number of iterations
        memory_cost=65536,    # 64 MB memory
        parallelism=4,        # Number of threads
        hash_len=32,          # 256-bit key length for AES-256
        salt_len=SALT_SIZE
    )
    # password_hash returns a string like $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    # We extract the raw hash bytes from the string representations
    raw_hash = ph.hash(password, salt=salt).split("$")[-1]
    import base64
    # The hash part is base64 (without padding) encoded, we decode it
    return base64.b64decode(raw_hash + "==")


def encrypt_file(input_file: str, output_file: str, password: str, progress_callback=None) -> bool | str:
    """Encrypts a file using AES-256 GCM with an Argon2id derived key."""
    try:
        file_size = os.path.getsize(input_file)
        
        # 1. Generate unique Salt and Nonce for this specific file
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        
        # 2. Derive the master AES key from the password
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # 3. Write non-secret material to the file header
            f_out.write(salt)
            f_out.write(nonce)
            
            # Since AES-GCM requires all data to calculate the MAC, and python's cryptography 
            # AESGCM interface doesn't natively support streaming chunks for MAC calculation without
            # external wrappers like `aes-gcm-stream`, we will implement chunking manually 
            # by treating each chunk as an independent GCM message with an incremented nonce.
            
            # Note: For production large files, encrypting chunk-by-chunk with incremented nonces 
            # is a standard way to avoid keeping the entire file in RAM.
            
            bytes_read = 0
            chunk_index = 0
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                bytes_read += len(chunk)
                
                if len(chunk) == 0:
                    break
                    
                # Increment the nonce for each chunk securely to prevent nonce reuse
                # We use int.to_bytes to add the chunk index to the 96-bit base nonce.
                current_nonce_int = int.from_bytes(nonce, 'big') + chunk_index
                current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                
                # Encrypt the chunk and append the MAC (AESGCM.encrypt does both)
                encrypted_chunk = aesgcm.encrypt(current_nonce, chunk, associated_data=None)
                
                # Write the size of this encrypted chunk (4 bytes) followed by the data
                chunk_len_bytes = len(encrypted_chunk).to_bytes(4, 'big')
                f_out.write(chunk_len_bytes)
                f_out.write(encrypted_chunk)
                
                chunk_index += 1
                
                if progress_callback and file_size > 0:
                    progress_callback(bytes_read / file_size)
                    
        if progress_callback:
            progress_callback(1.0)
            
        return True
    except Exception as e:
        return str(e)


def decrypt_file(input_file: str, output_file: str, password: str, progress_callback=None) -> bool | str:
    """Decrypts a file using AES-256 GCM with an Argon2id derived key. 
    Verifies authenticity automatically."""
    try:
        file_size = os.path.getsize(input_file)
        if file_size < SALT_SIZE + NONCE_SIZE:
             return "File is too small to be a valid encrypted file."
             
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # 1. Read non-secret material from header
            salt = f_in.read(SALT_SIZE)
            base_nonce = f_in.read(NONCE_SIZE)
            
            # 2. Derive the key using the same salt
            try:
                key = derive_key(password, salt)
            except Exception:
                 return "Failed to derive key from password. Processing error."
            
            aesgcm = AESGCM(key)
            
            bytes_processed = SALT_SIZE + NONCE_SIZE
            chunk_index = 0
            
            while bytes_processed < file_size:
                 # Read chunk size (4 bytes)
                 chunk_len_bytes = f_in.read(4)
                 if not chunk_len_bytes:
                     break
                 
                 chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                 bytes_processed += 4
                 
                 encrypted_chunk = f_in.read(chunk_len)
                 bytes_processed += len(encrypted_chunk)
                 
                 # Calculate the expected nonce for this chunk
                 current_nonce_int = int.from_bytes(base_nonce, 'big') + chunk_index
                 current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                 
                 # Decrypt and authenticate simultaneously
                 try:
                     decrypted_chunk = aesgcm.decrypt(current_nonce, encrypted_chunk, associated_data=None)
                 except Exception:
                     # Since AES-GCM throws cryptography.exceptions.InvalidTag, we catch it
                     # IF the file is deleted mid-decryption, we delete the partial malicious output
                     f_out.close()
                     os.remove(output_file)
                     return "Authentication Failed: Incorrect password or file is corrupted/tampered."
                 
                 f_out.write(decrypted_chunk)
                 chunk_index += 1
                 
                 if progress_callback and file_size > 0:
                      progress_callback(bytes_processed / file_size)
                      
        if progress_callback:
            progress_callback(1.0)
            
        return True
    except Exception as e:
        # Cleanup partial files on random errors
        if os.path.exists(output_file):
             os.remove(output_file)
        return str(e)

# ----------------------------------------------------------------------
# Modern CustomTkinter UI 
# ----------------------------------------------------------------------

class CTkEngine(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)

class ToastNotification(ctk.CTkFrame):
    """ Modern animated toast notification. """
    def __init__(self, parent, message, type="info", duration=3000):
        # We make the background transparent and add a rounded corner to the inner frame
        super().__init__(parent, fg_color="transparent", border_width=0)
        self.parent = parent
        self.message = message
        self.duration = duration
        
        bg_color = "#4CAF50" if type=="success" else "#F44336" if type=="error" else "#2196F3"
        
        # Inner frame with actual rounded corners, ensuring no border protrudes
        self.inner_frame = ctk.CTkFrame(self, corner_radius=15, fg_color=bg_color, border_width=0)
        self.inner_frame.pack(padx=0, pady=0)
        
        self.label = ctk.CTkLabel(self.inner_frame, text=self.message, text_color="white", font=ctk.CTkFont(family="Inter", size=13, weight="bold"))
        self.label.pack(padx=20, pady=10)
        
        # Positioning
        self.target_y = 0.95
        self.current_y = 1.2 # Start below screen
        self.place(relx=0.5, rely=self.current_y, anchor="s")
        
        self.animate_in()
        if self.duration > 0:
            self.after(self.duration, self.animate_out)
            
    def animate_in(self):
        if self.current_y > self.target_y:
            self.current_y -= 0.02
            self.place(relx=0.5, rely=self.current_y, anchor="s")
            self.after(10, self.animate_in)
            
    def animate_out(self):
        if self.current_y < 1.2:
            self.current_y += 0.02
            self.place(relx=0.5, rely=self.current_y, anchor="s")
            self.after(10, self.animate_out)
        else:
            self.destroy()

class App(CTkEngine):
    def __init__(self):
        super().__init__()
        
        self.title("Encrypter & Decrypter")
        self.geometry("600x480")
        self.minsize(550, 480)
        
        ctk.set_appearance_mode("System") 
        ctk.set_default_color_theme("blue") 
        
        # UI Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tab_encrypt = self.tabview.add("Pack 🔒")
        self.tab_decrypt = self.tabview.add("Unpack 🔓")
        
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        
        # Global Drag and Drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.handle_global_drop)
        
        # Bind Enter key
        self.bind("<Return>", self.handle_return_key)
        
    def show_toast(self, message, m_type="info", duration=3000):
        ToastNotification(self, message, type=m_type, duration=duration)
        
    def setup_encryption_tab(self):
        tab = self.tab_encrypt
        tab.grid_columnconfigure(1, weight=1)
        
        title = ctk.CTkLabel(tab, text="Secure Packing", font=ctk.CTkFont(family="Inter", size=20, weight="bold"))
        title.grid(row=0, column=0, columnspan=2, pady=(10, 20))
        
        # File Input
        ctk.CTkLabel(tab, text="File to Encrypt:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.enc_input_entry = ctk.CTkEntry(tab, placeholder_text="Drag and drop file here...")
        self.enc_input_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        # Output Input
        ctk.CTkLabel(tab, text="Save As:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.enc_out_entry = ctk.CTkEntry(tab, placeholder_text="Path to save encrypted file...")
        self.enc_out_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        # Password Input
        ctk.CTkLabel(tab, text="Password:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.enc_pwd_entry = ctk.CTkEntry(tab, placeholder_text="Enter a strong password...", show="*")
        self.enc_pwd_entry.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
        
        # Confirm Password Input
        ctk.CTkLabel(tab, text="Confirm:", font=ctk.CTkFont(weight="bold")).grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.enc_pwd_conf_entry = ctk.CTkEntry(tab, placeholder_text="Confirm password...", show="*")
        self.enc_pwd_conf_entry.grid(row=4, column=1, padx=10, pady=10, sticky="ew")
        
        # Progress Bar
        self.enc_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.enc_progress.grid(row=5, column=0, columnspan=2, padx=10, pady=(15, 5), sticky="ew")
        self.enc_progress.set(0)
        
        # Encrypt Button
        self.enc_btn = ctk.CTkButton(tab, text="Pack File 🚀", height=40, font=ctk.CTkFont(weight="bold"), command=self.start_encryption)
        self.enc_btn.grid(row=6, column=0, columnspan=2, padx=10, pady=15)
        
    def setup_decryption_tab(self):
        tab = self.tab_decrypt
        tab.grid_columnconfigure(1, weight=1)
        
        title = ctk.CTkLabel(tab, text="Secure Unpacking", font=ctk.CTkFont(family="Inter", size=20, weight="bold"))
        title.grid(row=0, column=0, columnspan=2, pady=(10, 20))
        
        # File Input
        ctk.CTkLabel(tab, text="Encrypted File:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.dec_input_entry = ctk.CTkEntry(tab, placeholder_text="Drag and drop encrypted file here...")
        self.dec_input_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        # Output
        ctk.CTkLabel(tab, text="Save As:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.dec_out_entry = ctk.CTkEntry(tab, placeholder_text="Path to save decrypted file...")
        self.dec_out_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        # Password Input
        ctk.CTkLabel(tab, text="Password:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.dec_pwd_entry = ctk.CTkEntry(tab, placeholder_text="Enter decryption password...", show="*")
        self.dec_pwd_entry.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
        
        # Empty space to align with encryption tab
        ctk.CTkLabel(tab, text="").grid(row=4, column=0, pady=10)
        
        # Progress Bar
        self.dec_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.dec_progress.grid(row=5, column=0, columnspan=2, padx=10, pady=(15, 5), sticky="ew")
        self.dec_progress.set(0)
        
        # Decrypt Button
        self.dec_btn = ctk.CTkButton(tab, text="Unpack File 🔓", height=40, fg_color="#F44336", hover_color="#D32F2F", font=ctk.CTkFont(weight="bold"), command=self.start_decryption)
        self.dec_btn.grid(row=6, column=0, columnspan=2, padx=10, pady=15)
    def handle_global_drop(self, event):
        files = self.tk.splitlist(event.data)
        for file_path in files:
            if file_path.startswith('{') and file_path.endswith('}'):
                file_path = file_path[1:-1]
                
            # Smart Routing
            if file_path.endswith('.enc'):
                self.tabview.set("Unpack 🔓")
                self.dec_input_entry.delete(0, 'end')
                self.dec_input_entry.insert(0, file_path)
                self.dec_out_entry.delete(0, 'end')
                self.dec_out_entry.insert(0, file_path[:-4])
                self.show_toast("Encrypted file loaded.", "info", 1500)
            else:
                self.tabview.set("Pack 🔒")
                self.enc_input_entry.delete(0, 'end')
                self.enc_input_entry.insert(0, file_path)
                self.enc_out_entry.delete(0, 'end')
                self.enc_out_entry.insert(0, file_path + ".enc")
                self.show_toast("File ready for packing.", "info", 1500)
            
    def handle_return_key(self, event):
        """ Triggers the action of the currently active tab when Enter is pressed. """
        active_tab = self.tabview.get()
        if active_tab == "Pack 🔒":
            self.start_encryption()
        elif active_tab == "Unpack 🔓":
            self.start_decryption()
    def set_enc_progress(self, val):
        self.enc_progress.set(val)
        self.update_idletasks()
        
    def set_dec_progress(self, val):
        self.dec_progress.set(val)
        self.update_idletasks()

    def start_encryption(self):
        in_p = self.enc_input_entry.get()
        out_p = self.enc_out_entry.get()
        pwd = self.enc_pwd_entry.get()
        pwd_conf = self.enc_pwd_conf_entry.get()
        
        if not in_p or not out_p:
            self.show_toast("Please provide input and output paths.", "error")
            return
            
        if not pwd:
            self.show_toast("Please enter a password.", "error")
            return
            
        if pwd != pwd_conf:
            self.show_toast("Passwords do not match!", "error")
            return
            
        if not os.path.exists(in_p):
             self.show_toast("Input file does not exist.", "error")
             return
             
        self.enc_btn.configure(state="disabled", text="Packing...")
        self.enc_progress.set(0)
        
        threading.Thread(target=self._encryption_worker, args=(in_p, out_p, pwd), daemon=True).start()
        
    def _encryption_worker(self, in_p, out_p, pwd):
        res = encrypt_file(in_p, out_p, pwd, progress_callback=lambda v: self.after(0, self.set_enc_progress, v))
        
        if res is True:
            # Delete source file after successful packing
            try:
                os.remove(in_p)
                self.after(0, lambda: self.show_toast("Packed Successfully! Source removed.", "success"))
            except Exception as e:
                self.after(0, lambda: self.show_toast(f"Packed, but failed to remove source: {e}", "warning"))
        else:
             self.after(0, lambda: self.show_toast(f"Error: {res}", "error"))
             
        self.after(0, lambda: self.enc_btn.configure(state="normal", text="Pack File 🚀"))
        self.after(0, lambda: self.set_enc_progress(0))

    def start_decryption(self):
        in_p = self.dec_input_entry.get()
        out_p = self.dec_out_entry.get()
        pwd = self.dec_pwd_entry.get()
        
        if not in_p or not out_p or not pwd:
            self.show_toast("Missing paths or password.", "error")
            return
            
        if not os.path.exists(in_p):
             self.show_toast("Encrypted file not found on disk.", "error")
             return
             
        self.dec_btn.configure(state="disabled", text="Unpacking...")
        self.dec_progress.set(0)
        
        threading.Thread(target=self._decryption_worker, args=(in_p, out_p, pwd), daemon=True).start()
        
    def _decryption_worker(self, in_p, out_p, pwd):
        res = decrypt_file(in_p, out_p, pwd, progress_callback=lambda v: self.after(0, self.set_dec_progress, v))
        if res is True:
            # Delete encrypted source after successful unpacking
            try:
                os.remove(in_p)
                self.after(0, lambda: self.show_toast("Unpacked Successfully! Source removed.", "success"))
            except Exception as e:
                self.after(0, lambda: self.show_toast(f"Unpacked, but failed to remove source: {e}", "warning"))
        else:
            self.after(0, lambda: self.show_toast(f"Error: {res}", "error"))
            
        self.after(0, lambda: self.dec_btn.configure(state="normal", text="Unpack File 🔓"))
        self.after(0, lambda: self.set_dec_progress(0))

if __name__ == "__main__":
    app = App()
    app.mainloop()

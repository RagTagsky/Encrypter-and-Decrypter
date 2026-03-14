import sys
import os
import hmac
import hashlib
import threading
import time
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ----------------------------------------------------------------------
# Core Cryptography Logic (Chunked for Progress Bar and memory efficiency)
# ----------------------------------------------------------------------
CHUNK_SIZE = 64 * 1024  # 64 KB

def generate_key_iv():
    key = os.urandom(32)  # 256-bit key for AES-256
    iv = os.urandom(16)   # 128-bit IV for CBC
    return key, iv

def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_file(input_file, output_file, key, iv, progress_callback=None):
    return _chunked_encrypt(input_file, output_file, key, iv, progress_callback)

def _chunked_encrypt(input_file, output_file, key, iv, progress_callback):
    try:
        file_size = os.path.getsize(input_file)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
        
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(iv)
            
            bytes_read = 0
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                bytes_read += len(chunk)
                
                if len(chunk) == 0:
                    break
                
                padded_chunk = padder.update(chunk)
                if padded_chunk:
                    cipher_chunk = encryptor.update(padded_chunk)
                    if cipher_chunk:
                        f_out.write(cipher_chunk)
                        hmac_obj.update(cipher_chunk)
                
                if progress_callback and file_size > 0:
                    progress_callback(bytes_read / file_size)
                    
            # Finalize padding
            final_padded = padder.finalize()
            if final_padded:
                final_cipher = encryptor.update(final_padded) + encryptor.finalize()
            else:
                final_cipher = encryptor.finalize()
                
            if final_cipher:
                f_out.write(final_cipher)
                hmac_obj.update(final_cipher)
                
            # Write HMAC
            f_out.write(hmac_obj.digest())
            
        if progress_callback:
            progress_callback(1.0)
            
        return True
    except Exception as e:
        return str(e)


def decrypt_file(input_file, output_file, key, progress_callback=None):
    try:
        file_size = os.path.getsize(input_file)
        if file_size < 16 + 32: # IV + HMAC
            return "File is too small to be a valid encrypted file."
            
        hmac_expected = generate_hmac_for_file(input_file, key)
        with open(input_file, 'rb') as f:
            f.seek(-32, os.SEEK_END)
            hmac_actual = f.read(32)
            
        if hmac_expected != hmac_actual:
            return "HMAC signature mismatch! File is corrupted or key is invalid."
            
        with open(input_file, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            
            with open(output_file, 'wb') as f_out:
                bytes_to_read = file_size - 16 - 32 # Exclude IV and HMAC
                bytes_read = 0
                
                while bytes_read < bytes_to_read:
                    chunk_size = min(CHUNK_SIZE, bytes_to_read - bytes_read)
                    chunk = f_in.read(chunk_size)
                    bytes_read += len(chunk)
                    
                    plain_chunk = decryptor.update(chunk)
                    if plain_chunk:
                        unpadded_chunk = unpadder.update(plain_chunk)
                        if unpadded_chunk:
                            f_out.write(unpadded_chunk)
                            
                    if progress_callback and bytes_to_read > 0:
                        progress_callback(bytes_read / bytes_to_read)
                        
                plain_chunk = decryptor.finalize()
                if plain_chunk:
                    unpadded_chunk = unpadder.update(plain_chunk)
                    if unpadded_chunk:
                        f_out.write(unpadded_chunk)
                        
                final_unpadded = unpadder.finalize()
                if final_unpadded:
                    f_out.write(final_unpadded)
                    
        if progress_callback:
            progress_callback(1.0)
        return True
    except Exception as e:
        return str(e)

def generate_hmac_for_file(input_file, key):
    hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
    file_size = os.path.getsize(input_file)
    bytes_to_read = file_size - 16 - 32
    with open(input_file, 'rb') as f:
        f.seek(16)
        bytes_read = 0
        while bytes_read < bytes_to_read:
             chunk_size = min(CHUNK_SIZE, bytes_to_read - bytes_read)
             chunk = f.read(chunk_size)
             hmac_obj.update(chunk)
             bytes_read += len(chunk)
    return hmac_obj.digest()

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
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self.message = message
        self.duration = duration
        
        bg_color = "#4CAF50" if type=="success" else "#F44336" if type=="error" else "#2196F3"
        
        # Inner frame with actual rounded corners
        self.inner_frame = ctk.CTkFrame(self, corner_radius=15, fg_color=bg_color)
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
        
        self.title("Encryptbox Native")
        self.geometry("600x450")
        self.minsize(550, 450)
        
        ctk.set_appearance_mode("System") 
        ctk.set_default_color_theme("blue") 
        
        # UI Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.tabview = ctk.CTkTabview(self, corner_radius=15)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tab_encrypt = self.tabview.add("Encryption 🔒")
        self.tab_decrypt = self.tabview.add("Decryption 🔓")
        
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        
        # Global Drag and Drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.handle_global_drop)
        
    def show_toast(self, message, m_type="info"):
        ToastNotification(self, message, type=m_type)
        
    def setup_encryption_tab(self):
        tab = self.tab_encrypt
        tab.grid_columnconfigure(1, weight=1)
        
        title = ctk.CTkLabel(tab, text="Secure File Encryption", font=ctk.CTkFont(family="Inter", size=20, weight="bold"))
        title.grid(row=0, column=0, columnspan=3, pady=(10, 20))
        
        # File Input
        ctk.CTkLabel(tab, text="File to Encrypt:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.enc_input_entry = ctk.CTkEntry(tab, placeholder_text="Drag and drop file here...")
        self.enc_input_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.enc_input_btn = ctk.CTkButton(tab, text="Browse 📁", width=80, command=self.enc_browse_input)
        self.enc_input_btn.grid(row=1, column=2, padx=10, pady=10)
        
        # Output Input
        ctk.CTkLabel(tab, text="Save As:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.enc_out_entry = ctk.CTkEntry(tab, placeholder_text="Path to save encrypted file...")
        self.enc_out_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky="ew")
        
        # Progress Bar
        self.enc_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.enc_progress.grid(row=3, column=0, columnspan=3, padx=10, pady=(20, 10), sticky="ew")
        self.enc_progress.set(0)
        
        # Encrypt Button
        self.enc_btn = ctk.CTkButton(tab, text="Encrypt File 🚀", height=40, font=ctk.CTkFont(weight="bold"), command=self.start_encryption)
        self.enc_btn.grid(row=4, column=0, columnspan=3, padx=10, pady=20)
        
    def setup_decryption_tab(self):
        tab = self.tab_decrypt
        tab.grid_columnconfigure(1, weight=1)
        
        title = ctk.CTkLabel(tab, text="Secure File Decryption", font=ctk.CTkFont(family="Inter", size=20, weight="bold"))
        title.grid(row=0, column=0, columnspan=3, pady=(10, 20))
        
        # File Input
        ctk.CTkLabel(tab, text="Encrypted File:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.dec_input_entry = ctk.CTkEntry(tab, placeholder_text="Drag and drop encrypted file here...")
        self.dec_input_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.dec_input_btn = ctk.CTkButton(tab, text="Browse 📁", width=80, command=self.dec_browse_input)
        self.dec_input_btn.grid(row=1, column=2, padx=10, pady=10)
        
        # Key Input
        ctk.CTkLabel(tab, text="Key File:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.dec_key_entry = ctk.CTkEntry(tab, placeholder_text="Drag and drop key file here...")
        self.dec_key_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        self.dec_key_btn = ctk.CTkButton(tab, text="Browse 🔑", width=80, command=self.dec_browse_key)
        self.dec_key_btn.grid(row=2, column=2, padx=10, pady=10)
        
        # Output
        ctk.CTkLabel(tab, text="Save As:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.dec_out_entry = ctk.CTkEntry(tab, placeholder_text="Path to save decrypted file...")
        self.dec_out_entry.grid(row=3, column=1, columnspan=2, padx=10, pady=10, sticky="ew")
        
        # Progress Bar
        self.dec_progress = ctk.CTkProgressBar(tab, mode="determinate")
        self.dec_progress.grid(row=4, column=0, columnspan=3, padx=10, pady=(15, 5), sticky="ew")
        self.dec_progress.set(0)
        
        # Decrypt Button
        self.dec_btn = ctk.CTkButton(tab, text="Decrypt File 🔓", height=40, fg_color="#F44336", hover_color="#D32F2F", font=ctk.CTkFont(weight="bold"), command=self.start_decryption)
        self.dec_btn.grid(row=5, column=0, columnspan=3, padx=10, pady=15)

    def handle_global_drop(self, event):
        files = self.tk.splitlist(event.data)
        for file_path in files:
            # Handle Windows paths correctly if they are wrapped in braces
            if file_path.startswith('{') and file_path.endswith('}'):
                file_path = file_path[1:-1]
                
            # Smart Routing
            if file_path.endswith('.enc'):
                # This is an encrypted file -> go to Decryption input
                self.tabview.set("Decryption 🔓")
                self.dec_input_entry.delete(0, 'end')
                self.dec_input_entry.insert(0, file_path)
                self.dec_out_entry.delete(0, 'end')
                self.dec_out_entry.insert(0, file_path[:-4])
                self.show_toast("Encrypted file loaded.", "info", 1500)
            elif file_path.endswith('.key.bin') or file_path.endswith('.bin'):
                # This is a key -> go to Decryption key input
                self.tabview.set("Decryption 🔓")
                self.dec_key_entry.delete(0, 'end')
                self.dec_key_entry.insert(0, file_path)
                self.show_toast("Key file loaded.", "info", 1500)
            else:
                # Normal file -> go to Encryption input
                self.tabview.set("Encryption 🔒")
                self.enc_input_entry.delete(0, 'end')
                self.enc_input_entry.insert(0, file_path)
                self.enc_out_entry.delete(0, 'end')
                self.enc_out_entry.insert(0, file_path + ".enc")
                self.show_toast("File ready for encryption.", "info", 1500)

    def enc_browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.enc_input_entry.delete(0, 'end')
            self.enc_input_entry.insert(0, file_path)
            self.enc_out_entry.delete(0, 'end')
            self.enc_out_entry.insert(0, file_path + ".enc")
            
    def dec_browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.dec_input_entry.delete(0, 'end')
            self.dec_input_entry.insert(0, file_path)
            self.dec_out_entry.delete(0, 'end')
            if file_path.endswith(".enc"):
                self.dec_out_entry.insert(0, file_path[:-4])
            else:
                self.dec_out_entry.insert(0, file_path + ".dec")
                
    def dec_browse_key(self):
         file_path = filedialog.askopenfilename(filetypes=[("Key Files", "*.bin"), ("All Files", "*.*")])
         if file_path:
            self.dec_key_entry.delete(0, 'end')
            self.dec_key_entry.insert(0, file_path)
            
    def set_enc_progress(self, val):
        self.enc_progress.set(val)
        self.update_idletasks()
        
    def set_dec_progress(self, val):
        self.dec_progress.set(val)
        self.update_idletasks()

    def start_encryption(self):
        in_p = self.enc_input_entry.get()
        out_p = self.enc_out_entry.get()
        
        if not in_p or not out_p:
            self.show_toast("Please provide input and output paths.", "error")
            return
            
        if not os.path.exists(in_p):
             self.show_toast("Input file does not exist.", "error")
             return
             
        self.enc_btn.configure(state="disabled", text="Encrypting...")
        self.enc_progress.set(0)
        
        threading.Thread(target=self._encryption_worker, args=(in_p, out_p), daemon=True).start()
        
    def _encryption_worker(self, in_p, out_p):
        key, iv = generate_key_iv()
        start = time.time()
        res = encrypt_file(in_p, out_p, key, iv, progress_callback=lambda v: self.after(0, self.set_enc_progress, v))
        
        if res is True:
            # Suggest key filename based on standard name
            base_name = os.path.basename(in_p)
            suggested_key_name = base_name + ".key.bin"
            
            key_path = filedialog.asksaveasfilename(
                initialfile=suggested_key_name,
                defaultextension=".bin", 
                filetypes=[("Binary Key", "*.bin")], 
                title="Save Encryption Key"
            )
            
            if key_path:
                with open(key_path, 'wb') as f:
                    f.write(key)
                self.after(0, lambda: self.show_toast("Encrypt Success & Key Saved!", "success"))
            else:
                self.after(0, lambda: self.show_toast("File encrypted, but key NOT saved!", "error"))
        else:
             self.after(0, lambda: self.show_toast(f"Error: {res}", "error"))
             
        self.after(0, lambda: self.enc_btn.configure(state="normal", text="Encrypt File 🚀"))
        self.after(0, lambda: self.set_enc_progress(0))

    def start_decryption(self):
        in_p = self.dec_input_entry.get()
        out_p = self.dec_out_entry.get()
        k_p = self.dec_key_entry.get()
        
        if not in_p or not out_p or not k_p:
            self.show_toast("Missing paths for decryption.", "error")
            return
            
        if not os.path.exists(in_p) or not os.path.exists(k_p):
             self.show_toast("File or Key not found on disk.", "error")
             return
             
        self.dec_btn.configure(state="disabled", text="Decrypting...")
        self.dec_progress.set(0)
        
        threading.Thread(target=self._decryption_worker, args=(in_p, out_p, k_p), daemon=True).start()
        
    def _decryption_worker(self, in_p, out_p, k_p):
        try:
            with open(k_p, 'rb') as f:
                key = f.read()
            res = decrypt_file(in_p, out_p, key, progress_callback=lambda v: self.after(0, self.set_dec_progress, v))
            if res is True:
                self.after(0, lambda: self.show_toast("File decrypted successfully!", "success"))
            else:
                 self.after(0, lambda: self.show_toast(f"Error: {res}", "error"))
        except Exception as e:
            self.after(0, lambda: self.show_toast(f"Error: {e}", "error"))
            
        self.after(0, lambda: self.dec_btn.configure(state="normal", text="Decrypt File 🔓"))
        self.after(0, lambda: self.set_dec_progress(0))

if __name__ == "__main__":
    app = App()
    app.mainloop()

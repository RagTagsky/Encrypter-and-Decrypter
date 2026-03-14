# 🔐 Encrypter & Decrypter

## 🇷🇺 Русский язык

**Encrypter & Decrypter** — это современное высокозащищенное приложение для «упаковки» ваших файлов в зашифрованные контейнеры. Забудьте про сложные ключи в файлах: теперь ваша безопасность строится на мощном пароле и передовых криптографических стандартах.

### ✨ Ключевые особенности
*   **Argon2id**: Современное хеширование паролей, устойчивое к взлому на GPU.
*   **AES-GCM (256-bit)**: Проверенный временем алгоритм шифрования с автоматической проверкой целостности (AEAD).
*   **Режим архиватора**: Программа работает по принципу "Pack/Unpack" — исходный файл заменяется на защищённую версию и наоборот.
*   **Glassmorphism UI**: Эстетичный интерфейс на `CustomTkinter` с поддержкой системных тем (светлая/темная) и плавными анимациями.
*   **Smart Drag-and-Drop**: Просто перетащите любой файл в окно, и программа сама поймет, нужно его зашифровать или расшифровать.
*   **Zero-Knowledge**: Ваши пароли никогда не сохраняются и не передаются.

### 🛠 Требования
*   Python 3.10+
*   Библиотеки: `customtkinter`, `cryptography`, `argon2-cffi`, `pillow`, `tkinterdnd2`

### 🚀 Быстрый старт
1. Установите зависимости:
   ```powershell
   pip install customtkinter cryptography argon2-cffi pillow tkinterdnd2-universal
   ```
2. Запустите приложение:
   ```powershell
   python Encrypter-and-Decrypter.py
   ```

---

## 🇺🇸 English Language

**Encrypter & Decrypter** is a modern, high-security utility designed to "pack" your files into encrypted containers. No more clunky key files: your security is now built on robust passwords and state-of-the-art cryptographic standards.

### ✨ Key Features
*   **Argon2id**: Modern password hashing resistant to GPU brute-force attacks.
*   **AES-GCM (256-bit)**: Industry-standard authenticated encryption (AEAD) ensuring both privacy and integrity.
*   **Archiver Workflow**: The app follows a "Pack/Unpack" logic — replacing the source file with its protected version and vice versa.
*   **Glassmorphism UI**: Beautiful `CustomTkinter` interface with native theme support (Light/Dark) and smooth micro-animations.
*   **Smart Drag-and-Drop**: Toss any file into the window, and let the smart routing decide whether to pack or unpack it.
*   **Zero-Knowledge**: Your passwords are never stored or transmitted anywhere.

### 🛠 Requirements
*   Python 3.10+
*   Dependencies: `customtkinter`, `cryptography`, `argon2-cffi`, `pillow`, `tkinterdnd2`

### 🚀 Quick Start
1. Install dependencies:
   ```powershell
   pip install customtkinter cryptography argon2-cffi pillow tkinterdnd2-universal
   ```
2. Run the application:
   ```powershell
   python Encrypter-and-Decrypter.py
   ```

## 📜 Disclaimer
This tool uses strong military-grade encryption. If you lose your password, **it is impossible to recover your data**. Use a password manager to keep your secrets safe.
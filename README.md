# Encrypter & Decrypter

# Russian language \ Русский язык

Простое кроссплатформенное графическое приложение для шифрования и расшифровки файлов с использованием алгоритма AES-256 в режиме CBC и проверкой целостности через HMAC-SHA256. Написано на Python с использованием PyQt5 и библиотеки cryptography.

## Возможности
- Шифрование с помощью AES-256 в режиме CBC
- Проверка целостности с использованием HMAC-SHA256
- Простой и интуитивно понятный интерфейс на PyQt5
- Отдельные вкладки для шифрования и расшифровки
- Генерация и экспорт ключа
- Обработка ошибок с понятными сообщениями для пользователя

## Интерфейс
Светлая вкладочная тема с удобным вводом путей и кнопками для выбора файлов.

## Требования
- Python 3.8+
- PyQt5
- cryptography

## Установка

1. Клонируй репозиторий:

    git clone https://github.com/RagTagsky/Encrypter-and-Decrypter.git
    cd Encrypter-and-Decrypter

2. Установи зависимости:

    pip install -r requirements.txt

3. Запусти приложение:

python Encrypter-and-Decrypter.py

## Использование
- Шифрование файла:
    Выбери файл для шифрования.
    Укажи имя выходного файла.

    Нажми «Encrypt File».

    Сохрани сгенерированный файл с ключом (.bin) - он понадобится для расшифровки

- Расшифровка файла:

    Выбери зашифрованный файл.
    Укажи путь для сохранения расшифрованного файла.

    Выбери ранее сохранённый ключ.

    Нажми «Decrypt File».

- Если ключ неверен или файл был изменён, проверка HMAC завершится с ошибкой.

## Формат выходного файла
Формат .enc файла:

[16 байт IV] + [зашифрованные данные] + [32 байта HMAC-SHA256]

## Дисклеймер
Этот проект создан в образовательных целях. Не предназначен для использования в системах, требующих высокой степени безопасности.


# English language \ Английский язык

A simple, cross-platform GUI application for encrypting and decrypting files using AES-256 in CBC mode with HMAC-SHA256 verification. Built with Python, PyQt5, and "cryptography".

## Features

- AES-256 encryption in CBC mode
- HMAC-SHA256 integrity verification
- Simple and intuitive PyQt5 interface
- Separate tabs for encryption and decryption
- Key generation and export
- Error handling with user-friendly messages

## Interface Preview

Light-themed tabbed interface with drag-and-drop paths and buttons to browse files. 

## Requirements

- Python 3.8+
- PyQt5
- cryptography

## Installation

1. Clone the repository:

   git clone https://github.com/RagTagsky/Encrypter-and-Decrypter.git
   cd Encrypter-and-Decrypter

2. Install dependencies:

    pip install -r requirements.txt

3. Run the app:

    python Encrypter-and-Decrypter.py

## Usage

- Encrypt a file:
    Select the file you want to encrypt.
    Specify the output file name.

    Click "Encrypt File".

    Save the generated key (.bin) file - you will need it to decrypt!

- Decrypt a file:
    Select the encrypted file.
    Provide the output file path.

    Select the key file you saved earlier.

    Click "Decrypt File".

- If the key is incorrect or the file has been tampered with, HMAC verification will fail.

## Output File Format
The output .enc file structure:
    - [16 bytes IV] + [ciphertext] + [32 bytes HMAC-SHA256]

## Disclaimer
This project is intended for educational purposes. Do not use it for serious production-level security.
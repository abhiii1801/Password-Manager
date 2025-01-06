# 🔒 Secure Password Manager
A robust password management tool designed with security at its core, using advanced encryption techniques to keep your data safe.

## 🔐 Key Features
### 1. Account Creation: 
Strong password hashing using bcrypt to store master passwords securely.

### 2. Encryption: 
Passwords are encrypted using Fernet with AES encryption for maximum privacy.

### 3. Login Authentication: 
Secure login with bcrypt password verification.

### 4. Data Protection:
All stored passwords are encrypted and only decrypted with the master password.


## 🛠️ Technologies
- ### Encryption:
  bcrypt for password hashing, Fernet for AES encryption.
- ### Database:
  SQLite (data stored locally and securely).
- ### GUI:
  Tkinter (for a simple and clean user experience).

## Security Flow
### 1. Account Creation: 
Master password hashed and stored safely.
### 2. Login: 
Master password checked via bcrypt for authentication.
### 3. Password Storage: 
All passwords are encrypted before storing.
### 4. Data Access: 
Passwords decrypted only using a securely hashed key.

## Screenshots

- ### Main Interface
![Screenshot (100)](https://github.com/user-attachments/assets/cd609cff-9e34-4b28-9e40-7b48b35fd019)

- ### Adding New Password
![Screenshot (101)](https://github.com/user-attachments/assets/198e0cf1-5e36-41ac-82cc-7d93e1bdfb2c)

- ### Viewing Passwords
![Screenshot (102)](https://github.com/user-attachments/assets/449daf6d-0b5f-4ff8-adc2-79a21fb3eb3a)

- ### Registering New User
![Screenshot (97)](https://github.com/user-attachments/assets/d3a4ef15-4049-480b-9437-951a0f978c7a)

- ### Login
![Screenshot (98)](https://github.com/user-attachments/assets/3a9f7ebb-7dbc-4844-a0fb-016ecd90099c)

- ### Storing Passwords
![Screenshot (104)](https://github.com/user-attachments/assets/ce4f2555-a6ba-439b-93dc-40c92c23c189)

### Your passwords stay private and protected. 🌐



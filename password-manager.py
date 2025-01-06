import bcrypt
import sqlite3
import hashlib
from cryptography.fernet import Fernet
import base64
import random
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

class Password_Manager:
    def __init__(self, root):
        self.conn = sqlite3.connect('passwords.db')
        self.cursor = self.conn.cursor()

        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        label = tk.Label(root, text="Password Manager", font=("Courier", 48))
        label.pack(pady=20, padx=20)

        self.current_frame = None

        self.opening_screen()

    def opening_screen(self):
        opening_frame = tk.Frame(self.root)
        opening_frame.pack(pady=50)

        self.current_frame = opening_frame

        create_acc_btn = tk.Button(opening_frame, text="Create Account",font=("Courier", 18) ,command=self.create_account)
        create_acc_btn.pack(pady=20)

        login_btn = tk.Button(opening_frame, text="Login",font=("Courier", 18) ,command=self.login)
        login_btn.pack(pady=20)

    def create_account(self):
        self.current_frame.pack_forget()

        create_account_frame = tk.Frame(self.root)
        create_account_frame.pack(pady=50, expand=True)

        self.current_frame = create_account_frame


        name_label = tk.Label(create_account_frame, text="Name",font=("Courier", 22))
        name_label.pack()
        name_entry = tk.Entry(create_account_frame, font=("Courier", 18))
        name_entry.pack(pady=10)

        master_password_label = tk.Label(create_account_frame, text="Master Password",font=("Courier", 22))
        master_password_label.pack()
        master_password_entry = tk.Entry(create_account_frame, font=("Courier", 18), show="*")
        master_password_entry.pack(pady=10)

        confirm_master_password_label = tk.Label(create_account_frame, text="Confirm Master Password",font=("Courier", 22))
        confirm_master_password_label.pack()
        confirm_master_password_entry = tk.Entry(create_account_frame, font=("Courier", 18), show="*")
        confirm_master_password_entry.pack(pady=10)

        back_to_login_btn = tk.Button(create_account_frame, text="Back to Login",font=("Courier", 14) ,command=self.login)
        back_to_login_btn.pack(side='bottom')

        def create_account_pressed():
            master_password = master_password_entry.get()
            confirm_master_password = confirm_master_password_entry.get()
            name = name_entry.get()

            if not name or not master_password or not confirm_master_password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            if not len(master_password) >= 8:
                messagebox.showerror("Error", "Password should be atleast 8 digits")
                return
            
            if master_password == confirm_master_password:
                username = f'{name.split()[0].lower()}_{random.randint(1000, 9999)}'

                username_label = tk.Label(create_account_frame, text= f"Username: {username}",font=("Courier", 48))
                username_label.pack()

                name_label.destroy()
                master_password_label.destroy()
                confirm_master_password_label.destroy()
                back_to_login_btn.destroy()

                master_password_entry.destroy()
                confirm_master_password_entry.destroy()
                name_entry.destroy()
                confirm_btn.destroy()

                master_password_hash = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

                self.cursor.execute("INSERT INTO users (name, username, master_password_hash) VALUES (?, ?, ?)", (name, username, master_password_hash))
                self.conn.commit()

                messagebox.showinfo("Success", f"Account created successfully!\n USERNAME: {username}")
                self.login()

            else:
                messagebox.showerror("Error", "Passwords do not match")

        confirm_btn = tk.Button(create_account_frame, text="Confirm",font=("Courier", 18) ,command=create_account_pressed)
        confirm_btn.pack(pady=20)

    def login(self):
        self.current_frame.pack_forget()

        login_frame = tk.Frame(self.root)
        login_frame.pack(pady=30, expand=True)

        self.current_frame = login_frame

        username_label = tk.Label(login_frame, text="Username",font=("Courier", 22))
        username_label.pack()
        username_entry = tk.Entry(login_frame, font=("Courier", 18))
        username_entry.pack(pady=10)

        master_password_label = tk.Label(login_frame, text="Master Password",font=("Courier", 22))
        master_password_label.pack()
        master_password_entry = tk.Entry(login_frame, font=("Courier", 18), show="*")
        master_password_entry.pack(pady=10)

        def login_pressed():
            master_password = master_password_entry.get()
            user_name = username_entry.get()

            self.cursor.execute("SELECT master_password_hash FROM users WHERE username = ?", (user_name,))
            user = self.cursor.fetchone()

            if user:
                stored_hash = user[0]
                if bcrypt.checkpw(master_password.encode(), stored_hash):
                    messagebox.showinfo("Success", "Login successful!")
                    self.username = user_name
                    self.user_id = self.cursor.execute("SELECT user_id FROM users WHERE username = ?", (self.username,)).fetchone()[0]
                    self.master_password = master_password
                    self.logged_in_screen()
                    
                else:
                    messagebox.showerror("Error", "Invalid password")
            else:
                messagebox.showerror("Error", "Invalid username")

        login_btn = tk.Button(login_frame, text="Login",font=("Courier", 18) ,command=login_pressed)
        login_btn.pack(pady=20)

        back_to_create_acc_btn = tk.Button(login_frame, text="Create New Account",font=("Courier", 14) ,command=self.create_account)
        back_to_create_acc_btn.pack()

    def logged_in_screen(self):
        self.current_frame.pack_forget()

        logged_in_frame = tk.Frame(self.root)
        logged_in_frame.pack(pady=50)

        self.current_frame = logged_in_frame

        view_old_passwords_btn = tk.Button(logged_in_frame, text="View Old Passwords",font=("Courier", 18) ,command=self.view_old_passwords)
        view_old_passwords_btn.pack(pady=20)

        add_new_password_btn = tk.Button(logged_in_frame, text="Add New Password",font=("Courier", 18) ,command=self.add_new_password)
        add_new_password_btn.pack(pady=20)
    
    def add_new_password(self):
        self.current_frame.pack_forget()

        add_new_password_frame = tk.Frame(self.root)
        add_new_password_frame.pack(pady=50)

        self.current_frame = add_new_password_frame

        password_name_label = tk.Label(add_new_password_frame, text="Password Name",font=("Courier", 22))
        password_name_label.pack()
        password_name_entry = tk.Entry(add_new_password_frame, font=("Courier", 18))
        password_name_entry.pack(pady=10)

        password_value_label = tk.Label(add_new_password_frame, text="Password: ",font=("Courier", 22))
        password_value_label.pack()
        password_value_entry = tk.Entry(add_new_password_frame, font=("Courier", 18))
        password_value_entry.pack(pady=10)

        password_description_label = tk.Label(add_new_password_frame, text="Password Description",font=("Courier", 22))
        password_description_label.pack()
        password_description_entry = tk.Entry(add_new_password_frame, font=("Courier", 18))
        password_description_entry.pack(pady=10)


        def add_new_password_pressed():
            password_name = password_name_entry.get()
            password_value = password_value_entry.get()
            password_description = password_description_entry.get()

            if not password_name or not password_value or not password_description:
                messagebox.showerror("Error", "All fields must be filled!")
                return

            key = hashlib.sha256(self.master_password.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key)
            cipher = Fernet(fernet_key)

            encrypted_password_value = cipher.encrypt(password_value.encode())  

            self.cursor.execute("INSERT INTO passwords (user_id, password_name, encrypted_password, password_desc) VALUES (?, ?, ?, ?)", (self.user_id, password_name, encrypted_password_value, password_description))
            self.conn.commit()

            messagebox.showinfo("Success", "Password added successfully!")

            self.logged_in_screen()


        add_new_password_btn = tk.Button(add_new_password_frame, text="Add New Password",font=("Courier", 18) ,command=add_new_password_pressed)
        add_new_password_btn.pack(pady=20)

        back_btn = tk.Button(add_new_password_frame, text="Back to Menu", font=("Courier", 14), command=self.logged_in_screen)
        back_btn.pack(side="bottom", pady=20)

    def view_old_passwords(self):
        self.current_frame.pack_forget()

        view_old_passwords_frame = tk.Frame(self.root)
        view_old_passwords_frame.pack(pady=50, side="left", fill="both", expand=True)

        self.current_frame = view_old_passwords_frame

        canvas = tk.Canvas(view_old_passwords_frame)
        scrollbar = tk.Scrollbar(view_old_passwords_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.cursor.execute("SELECT password_name, encrypted_password, password_desc FROM passwords WHERE user_id = ?", (self.user_id,))
        passwords = self.cursor.fetchall()

        key = hashlib.sha256(self.master_password.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key)
        cipher = Fernet(fernet_key)

        for i, (name, password_value, password_desc) in enumerate(passwords):
            decrypted_password = cipher.decrypt(password_value).decode()

            entry_text = f"{i+1}. {name}:\n    Password: {decrypted_password}\n    Description: {password_desc}\n"
            password_label = tk.Label(scrollable_frame, text=entry_text, font=("Courier", 14), justify="left", anchor="w")
            password_label.pack(anchor="w", pady=(0, 10), padx=10)

            del_up_frame = tk.Frame(scrollable_frame)
            del_up_frame.pack(pady=(0, 10), padx=10)

            del_btn = tk.Button(del_up_frame, text="Delete", font=("Courier", 10), command=lambda i=i: self.delete_password(name))
            del_btn.grid(row=0, column=0, pady=10)

            update_btn = tk.Button(del_up_frame, text="Update", font=("Courier", 10), command=lambda i=i: self.update_password(name))
            update_btn.grid(row=0, column=1, pady=10)
        
        back_btn = tk.Button(view_old_passwords_frame, text="Back to Menu", font=("Courier", 14), command=self.logged_in_screen)
        back_btn.pack(side="bottom", pady=20)

    def delete_password(self, name):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            self.cursor.execute("DELETE FROM passwords WHERE user_id = ? AND password_name = ?", (self.user_id, name,))
            self.conn.commit()

            messagebox.showinfo("Success", "Password deleted successfully!")
            self.view_old_passwords()

    def update_password(self, name):
        updated_password = simpledialog.askstring("Input", "Enter New Password:")

        if updated_password:
            key = hashlib.sha256(self.master_password.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key)
            cipher = Fernet(fernet_key)

            encrypted_password = cipher.encrypt(updated_password.encode())

            self.cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE user_id = ? AND password_name = ?", (encrypted_password, self.user_id, name,))
            self.conn.commit()

            messagebox.showinfo("Success", "Password updated successfully!")

            self.view_old_passwords()
        

if __name__ == '__main__':
    root = tk.Tk()
    app = Password_Manager(root)
    root.mainloop()

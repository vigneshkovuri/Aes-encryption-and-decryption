from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Encryption
def encrypt():
    password = code.get()
    if password:
        # 16-byte key from the password
        key = password.encode("utf-8")[:16].ljust(16, b'\0')
        iv = os.urandom(16)  # Generate a random initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        
        message = text1.get(1.0, END).strip()
        if not message:
            messagebox.showerror("Encryption", "Input message is empty.")
            return
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode("utf-8")) + padder.finalize()
        
        # Encrypt the message
        encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
        
        # encrypted message
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")
        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)
        text2.insert(END, encrypted_message.hex())
    else:
        messagebox.showerror("Encryption", "Please enter a password.")

# Decryption function
def decrypt():
    password = code.get()
    if password:
        key = password.encode("utf-8")[:16].ljust(16, b'\0')
        encrypted_message_hex = text1.get(1.0, END).strip()
        if not encrypted_message_hex:
            messagebox.showerror("Decryption", "Input message is empty.")
            return
        try:
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            iv = encrypted_message[:16]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()

            # Unpadding  message
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
            
            #  decrypted message
            screen2 = Toplevel(screen)
            screen2.title("Decryption")
            screen2.geometry("400x200")
            screen2.configure(bg="#00bd56")
            Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
            text2 = Text(screen2, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, decrypted_message.decode("utf-8"))
        except Exception as e:
            messagebox.showerror("Decryption", "Decryption failed. Check your password or message.")
    else:
        messagebox.showerror("Decryption", "Please enter a password.")

# Main function
def main_screen():
    global screen
    global code
    global text1

    screen = Tk()
    screen.geometry("375x398")
    screen.title("CRiptyFY")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Enter the Encryption and Decryption", fg="black", font=("Calibri", 13)).place(x=10, y=1)
    text1 = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Enter Secret key for Encryption and Decryption", fg="black", font=("Calibri", 13)).place(x=10, y=170)
    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("Arial", 25), show="*").place(x=10, y=200)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=300)

    screen.mainloop()

main_screen()

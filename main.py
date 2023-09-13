from tkinter import *
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)


window = Tk()
window.minsize(width=400,height=900)
window.configure(pady=30,padx=20)
window.title("Secret Notes")


FONT = ("Arial", 15)

#foto
image = PhotoImage(file="logo.png")
resized = image.subsample(12)
label = Label(window, image=resized, pady=30)
label.pack(pady=30)

#title
title_label = Label(text="Set a name for your secret note",font=FONT)
title_label.pack()
title_entry = Entry(width=40)
title_entry.pack()

#secret
secret_label = Label(text="Enter your secret note", font=FONT)
secret_label.pack()
secret_text = Text(width=60)
secret_text.pack()

#masterkey
master_label = Label(text="Enter master key", font=FONT)
master_label.pack()
master_entry = Entry(width=40)
master_entry.pack()
message = Label(text="", font=FONT)
message.pack()

def set_cipher_suite(master_password):
    global cipher_suite
    master_key = master_password.encode()
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

def show_error_message(message_text):
    error_window = Toplevel(window)
    error_window.title("Hata")
    error_label = Label(error_window, text=message_text, font=FONT)
    error_label.pack()
    ok_button = Button(error_window, text="Tamam", command=error_window.destroy)
    ok_button.pack()

def encrypt_and_save():
    ismi = title_entry.get()
    secretNote = secret_text.get(0.1, "end")
    password = master_entry.get()

    if ismi == "" and secretNote.strip() == "":
        show_error_message("İki değeri de eksik girdiniz, lütfen tamamlayın.")
        return
    elif ismi == "":
        show_error_message("You didn't set a name for your secret note")
        return
    elif secretNote.strip() == "":
        show_error_message("You didn't write a secret node")
        return

    elif password.strip() == "":
        show_error_message("You didn't enter a password")
        return

    encrypted_note = cipher_suite.encrypt(secretNote.encode())
    fileName = str(ismi + "_not.txt")
    with open(fileName, "wb") as dosya:
            dosya.write(secretNote)
            show_error_message(f"Secret note created. \n File name: {ismi}_not.txt")

def decrypt_and_display():
    ismi = title_entry.get()
    master_password = master_entry.get()

    if ismi == "":
        show_error_message("Please enter the name of the secret note")
        return
    elif master_password == "":
        show_error_message("Please enter the master key to decrypt the note")
        return

    set_cipher_suite(master_password)

    fileName = str(ismi + "_not.txt")
    try:
        with open(fileName, "rb") as dosya:
            encrypted_note = dosya.read()
            decrypted_note = cipher_suite.decrypt(encrypted_note)
            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", decrypted_note.decode())
    except FileNotFoundError:
        show_error_message(f"Secret note with the name {ismi} not found")


#save button
save = Button(text="Save / Encrypt", command=encrypt_and_save)
save.pack(pady=20)

#Decrypt
decrypt = Button(text="Decrypt", command=decrypt_and_display)
decrypt.pack()

#button






window.mainloop()



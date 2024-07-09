import base64
import random
import string
import tkinter as tk
from tkinter import scrolledtext, messagebox

def generate_key(secret_key):
    random.seed(secret_key)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    return key

def obfuscate_js(js_code, secret_key):
    key = generate_key(secret_key)
    combined = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(js_code, key * (len(js_code) // len(key) + 1)))
    obfuscated_code = ''.join(random.sample(combined, len(combined)))
    encoded_code = base64.b64encode(obfuscated_code.encode()).decode()
    return encoded_code

def deobfuscate_js(encoded_code, secret_key):
    obfuscated_code = base64.b64decode(encoded_code).decode()
    key = generate_key(secret_key)
    combined = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(obfuscated_code, key * (len(obfuscated_code) // len(key) + 1)))
    return combined

def obfuscate_action():
    js_code = js_code_text.get("1.0", tk.END).strip()
    secret_key = secret_key_entry.get().strip()
    if not js_code or not secret_key:
        messagebox.showerror("Error", "Please provide both JavaScript code and a secret key.")
        return
    obfuscated_code = obfuscate_js(js_code, secret_key)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, obfuscated_code)

def deobfuscate_action():
    encoded_code = result_text.get("1.0", tk.END).strip()
    secret_key = secret_key_entry.get().strip()
    if not encoded_code or not secret_key:
        messagebox.showerror("Error", "Please provide both encoded code and a secret key.")
        return
    decoded_code = deobfuscate_js(encoded_code, secret_key)
    js_code_text.delete("1.0", tk.END)
    js_code_text.insert(tk.END, decoded_code)

# GUI 
root = tk.Tk()
root.title("JavaScript Obfuscator")
root.geometry("600x400")

tk.Label(root, text="JavaScript Code:").pack()
js_code_text = scrolledtext.ScrolledText(root, height=10)
js_code_text.pack()

tk.Label(root, text="Secret Key:").pack()
secret_key_entry = tk.Entry(root, show="*")
secret_key_entry.pack()

tk.Button(root, text="Obfuscate", command=obfuscate_action).pack()
tk.Button(root, text="Deobfuscate", command=deobfuscate_action).pack()

tk.Label(root, text="Result:").pack()
result_text = scrolledtext.ScrolledText(root, height=10)
result_text.pack()

root.mainloop()

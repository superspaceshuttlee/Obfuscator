import base64
import os
import tkinter as tk
from tkinter import simpledialog, scrolledtext

# GUI to ask for the port key
def get_port_key():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    port_key = simpledialog.askstring("Port Key", "Enter your port key:")
    return port_key

# Obfuscation based on port key (XOR encryption)
def xor_obfuscate(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# Function to handle the obfuscation process
def obfuscate_code():
    code = code_text.get("1.0", tk.END).strip()  # Get the code from the text area
    if not code:
        tk.messagebox.showerror("Input Error", "Please paste your code in the text area.")
        return
    
    port_key = get_port_key()  # Get the port key from the user

    # Obfuscate the code
    obfuscated_code = xor_obfuscate(code, port_key)
    encoded_obfuscated_code = base64.b64encode(obfuscated_code.encode()).decode()

    # Define the output path for the obfuscated script
    output_path = "C:\\Users\\aavig\\Downloads\\ReduceMemory\\obfuscated_script.py"

    # Save obfuscated code to a file
    with open(output_path, "w") as f:
        f.write(f"""
import base64
import os
import tkinter as tk
from tkinter import simpledialog

def xor_deobfuscate(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# Encoded and obfuscated code
encoded_obfuscated_code = "{encoded_obfuscated_code}"

# GUI to ask for the port key
def get_port_key():
    root = tk.Tk()
    root.withdraw()
    port_key = simpledialog.askstring("Port Key", "Enter your port key:")
    return port_key

# Get port key and decode the obfuscated code
port_key = get_port_key()
decoded_obfuscated_code = base64.b64decode(encoded_obfuscated_code).decode()
original_code = xor_deobfuscate(decoded_obfuscated_code, port_key)

# Create a folder to store the deobfuscated code
folder_name = "deobfuscated_code"
if not os.path.exists(folder_name):
    os.makedirs(folder_name)

# Define the file path for the deobfuscated script
file_path = os.path.join(folder_name, "deobfuscated_script.py")

# Write the deobfuscated code to a file
with open(file_path, "w") as f:
    f.write(original_code)

# Inform the user that the code has been saved
print(f"Deobfuscated code saved to {{file_path}}")
        """)

    tk.messagebox.showinfo("Success", f"Code obfuscated successfully! Check '{output_path}'.")

# Create the main window
main_window = tk.Tk()
main_window.title("Code Obfuscator")

# Create a text area for code input
code_text = scrolledtext.ScrolledText(main_window, wrap=tk.WORD, width=80, height=20)
code_text.pack(padx=10, pady=10)

# Create a button to obfuscate the code
obfuscate_button = tk.Button(main_window, text="Obfuscate Code", command=obfuscate_code)
obfuscate_button.pack(pady=10)

# Start the GUI loop
main_window.mainloop()

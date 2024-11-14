import requests
import hashlib
import nmap
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import sys

def check_password(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code == 200:
            hashes = (line.split(":") for line in response.text.splitlines())
            for hash, count in hashes:
                if hash == suffix:
                    return f"'{password}' was compromised {count} times."
            return f"Congrats! '{password}' was not compromised."
        else:
            return f"Error: Unable to fetch data from the API (Status Code: {response.status_code})."
    except requests.exceptions.RequestException as e:
        return f"Error: {e}. Check your internet connection or try again later."


def simple_nmap_scan(target, ports='1-1024'):
    """
    Performs a simple Nmap scan on a given target and returns the open ports.
    
    Parameters:
    target (str): The target IP or hostname to scan.
    ports (str): The port range to scan. Default is '1-1024'.
    
    Returns:
    str: A string containing the open ports or an error message if the scan fails.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(target, ports)

        if target not in nm.all_hosts():
            return f"Error: Host {target} not found."

        if 'tcp' not in nm[target]:
            return f"No 'tcp' ports found for {target}."

        open_ports = [port for port in nm[target]['tcp'] if nm[target]['tcp'][port]['state'] == 'open']

        if not open_ports:
            return f"No open ports found on {target}."

        return f"Open ports on {target}: {', '.join(map(str, open_ports))}"

    except nmap.nmap.PortScannerError as e:
        return f"Error: Could not scan {target}. {e}"
    except Exception as e:
        return f"Error: {e}"

# Fonction pour détecter les services d'un hôte avec Nmap
def detect_services(target, ports='1-1024'):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, ports, arguments="-sV")

        if target not in nm.all_hosts():
            return f"Error: Host {target} not found."

        if 'tcp' not in nm[target]:
            return f"No 'tcp' ports found for {target}."

        services = []
        for port in nm[target]['tcp']:
            name = nm[target]['tcp'][port]['name']
            product = nm[target]['tcp'][port].get('product', 'Unknown')
            version = nm[target]['tcp'][port].get('version', 'Unknown')
            services.append(f"Port {port}: {name} - Product: {product}, Version: {version}")

        if not services:
            return f"No services detected on {target}."

        return "\n".join(services)

    except Exception as e:
        return f"Error: Could not detect services on {target}. {e}"

# Fonction pour détecter l'OS d'un hôte avec Nmap
def detect_os(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-O')

        if target not in nm.all_hosts():
            return f"Error: Host {target} not found."

        if 'osclass' in nm[target]:
            os_info = "\n".join([f"OS: {os['osfamily']} {os['osgen']} - Accuracy: {os['accuracy']}%" for os in nm[target]['osclass']])
            return f"Detected OS:\n{os_info}"
        return "OS detection not available."

    except Exception as e:
        return f"Error: Could not detect OS for {target}. {e}"

# Fonction pour détecter les vulnérabilités avec Nmap
def detect_vuln(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='--script vuln')
        vulnerabilities = []
        for host in nm.all_hosts():
            for vuln, output in nm[host].get('script', {}).items():
                vulnerabilities.append(f"{host}: {vuln} - {output}")
        if not vulnerabilities:
            return f"No vulnerabilities detected on {target}."
        return "\n".join(vulnerabilities)
    except Exception as e:
        return f"Error: Could not detect vulnerabilities on {target}. {e}"

# Fonction pour gérer l'interface CLI
def cli_mode():
    print("Welcome to the CLI version of Vulneye Scanner!")
    print("Select an option:")
    print("1. Check Password")
    print("2. Scan Ports")
    print("3. Detect OS")
    print("4. Detect Services")
    print("5. Detect Vulnerabilities")

    choice = input("Enter the number of your choice: ")

    if choice == '1':
        password = input("Enter the password to check: ")
        result = check_password(password)
        print(result)

    elif choice == '2':
        target = input("Enter the target IP or hostname: ")
        result = simple_nmap_scan(target)
        print(result)

    elif choice == '3':
        target = input("Enter the target IP or hostname: ")
        result = detect_os(target)
        print(result)

    elif choice == '4':
        target = input("Enter the target IP or hostname: ")
        result = detect_services(target)
        print(result)

    elif choice == '5':
        target = input("Enter the target IP or hostname: ")
        result = detect_vuln(target)
        print(result)

    else:
        print("Invalid option selected.")

def gui_mode(root):
    clear_window(root)

    label = tk.Label(root, text="Select an option:")
    label.pack(pady=20)

    password_button = tk.Button(root, text="Check Password", command=lambda: check_password_gui(root))
    password_button.pack(pady=5)

    nmap_button = tk.Button(root, text="Use Nmap", command=lambda: nmap_gui(root))
    nmap_button.pack(pady=5)


def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()

# Fonction pour démarrer l'interface en mode GUI
def check_password_gui(root):
    clear_window(root)

    label1 = tk.Label(root, text="Enter password to check:")
    label1.pack(pady=5)
    password_entry = tk.Entry(root, width=30)
    password_entry.pack(pady=5)

    check_password_button = tk.Button(root, text="Check Password", command=lambda: check_password_action(root, password_entry))
    check_password_button.pack(pady=5)

    result_text = scrolledtext.ScrolledText(root, width=80, height=10)
    result_text.pack(pady=5)

# Fonction pour exécuter le check du mot de passe dans l'interface GUI
def check_password_action(root, password_entry):
    password = password_entry.get()
    result = check_password(password)
    result_text = scrolledtext.ScrolledText(root, width=80, height=10)
    result_text.pack(pady=5)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

# Fonction pour gérer l'interface Nmap dans le GUI
def nmap_gui(root):
    clear_window(root)

    label = tk.Label(root, text="Choose Nmap Option:")
    label.pack(pady=5)

    nmap_option = ttk.Combobox(root, values=["Scan Ports", "Detect OS", "Detect Services", "Detect Vulnerabilities"])
    nmap_option.pack(pady=5)
    nmap_option.set("Select Option")

    start_button = tk.Button(root, text="Start Nmap", command=lambda: run_nmap(root, nmap_option.get()))
    start_button.pack(pady=5)

    result_text = scrolledtext.ScrolledText(root, width=80, height=10)
    result_text.pack(pady=5)

# Fonction pour exécuter les scans Nmap dans l'interface GUI
def run_nmap(root, selected_option):
    target = "127.0.0.1"  # Can be updated to accept user input
    if selected_option == "Scan Ports":
        result = simple_nmap_scan(target)
    elif selected_option == "Detect OS":
        result = detect_os(target)
    elif selected_option == "Detect Services":
        result = detect_services(target)
    elif selected_option == "Detect Vulnerabilities":
        result = detect_vuln(target)
    else:
        result = "Invalid Option"

    result_text = scrolledtext.ScrolledText(root, width=80, height=10)
    result_text.pack(pady=5)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

# Fonction principale pour afficher l'interface GUI ou CLI selon l'argument
def main():
    if '--cli' in sys.argv:
        cli_mode()
    else:
        root = tk.Tk()
        root.title("Vulneye Scanner")
        gui_mode(root)
        root.mainloop()

if __name__ == "__main__":
    main()

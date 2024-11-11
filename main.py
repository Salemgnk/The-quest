import requests
import hashlib
import nmap
import tkinter as tk
from tkinter import messagebox, scrolledtext

class PasswordChecker:
    def __init__(self) -> None:
        pass

    def check_password(self, password):
        """
        Check if a password has been compromised according to the Have I Been Pwned API.

        Parameters
        ----------
        password : str
            The password to check.

        Returns
        -------
        str
            A message indicating whether or not the password was compromised, or
            an error message if the API call fails.
        """
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
                return f"'{password}' was not compromised."
            else:
                return f"Error: Unable to fetch data from the API (Status Code: {response.status_code})."
        except requests.exceptions.RequestException as e:
            return f"Error: {e}. Check your internet connection or try again later."

class NmapScanner:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
    
    def simple_nmap_scan(self, target, ports='1-1024'):
        """
        Scan a target for open ports.

        Parameters
        ----------
        target : str
            The target to scan.
        ports : str, optional
            The ports to scan, in the format 'x-y' where x and y are the
            start and end ports, respectively. Default is '1-1024'.

        Returns
        -------
        str
            A message indicating the result of the scan.
        """
        try:
            nm = nmap.PortScanner()
            nm.scan(target, ports)
            
            # Vérifie si l'hôte est trouvé dans les résultats
            if target not in nm.all_hosts():
                return f"Error: Host {target} not found."
            
            # Vérifie si l'hôte a des ports TCP ouverts
            if 'tcp' not in nm[target]:
                return f"No 'tcp' ports found for {target}."
            
            open_ports = [port for port in nm[target]['tcp'] if nm[target]['tcp'][port]['state'] == 'open']
            
            if not open_ports:
                return f"No open ports found on {target}. Ports might be closed or filtered by a firewall."
            
            return f"Open ports on {target}: {', '.join(map(str, open_ports))}"
        
        except nmap.nmap.PortScannerError as e:
            return f"Error: Could not scan {target}. {e}"
        except Exception as e:
            return f"Error: {e}"

    

    def detect_services(target, ports='1-1024'):
        """
        Identify the services running on a specified target.

        Parameters
        ----------
        target : str
            The hostname or IP address of the target machine.
        ports : str, optional
            The ports to scan, in the format 'x-y' where x and y are the
            start and end ports, respectively. Default is '1-1024'.

        Returns
        -------
        str
            A formatted string listing the services running on open ports.
        """
        nm = nmap.PortScanner()
        try:
            nm.scan(target, ports, arguments="-sV")
            
            # Vérifie si l'hôte est trouvé dans les résultats
            if target not in nm.all_hosts():
                return f"Error: Host {target} not found."
            
            # Vérifie si l'hôte a des ports TCP ouverts
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

    def detect_os(target):
        """
        Detect the operating system of a target.

        Parameters
        ----------
        target : str
            The target to detect the OS of.

        Returns
        -------
        str
            A formatted string with the OS details or an error message.
        """
        nm = nmap.PortScanner()
        try:
            nm.scan(target, arguments='-O')
            
            # Vérifie si l'hôte a des informations sur l'OS
            if target not in nm.all_hosts():
                return f"Error: Host {target} not found."
            
            if 'osclass' in nm[target]:
                os_info = "\n".join([f"OS: {os['osfamily']} {os['osgen']} - Accuracy: {os['accuracy']}%" for os in nm[target]['osclass']])
                return f"Detected OS:\n{os_info}"
            return "OS detection not available."
        
        except Exception as e:
            return f"Error: Could not detect OS for {target}. {e}"


    def detect_vuln(target):
        """
        Detect the vulnerabilities of a target.

        Parameters
        ----------
        target : str
            The target to detect vulnerabilities on.

        Returns
        -------
        str
            A formatted string listing detected vulnerabilities or an error message.
        """
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

class GuiApp:
    """
    A GUI application for using the password checker and Nmap scanner classes.
    """
    def __init__(self, root):
        """
        Initialize the GUI application.

        Parameters
        ----------
        root : tk.Tk
            The root window of the application.
        """
        self.root = root
        self.root.title("Vulneye Scanner")
        
        self.password_checker = PasswordChecker()
        self.nmap_scanner = NmapScanner()

        self.create_widgets()

    def create_widgets(self):
        """
        Create the GUI widgets for the application.
        """
        # Label and entry for password input
        self.label1 = tk.Label(self.root, text="Enter password to check:")
        self.label1.pack(pady=5)
        self.password_entry = tk.Entry(self.root, width=30)
        self.password_entry.pack(pady=5)

        # Button to check password
        self.check_password_button = tk.Button(self.root, text="Check Password", command=self.check_password_gui)
        self.check_password_button.pack(pady=5)

        # Label and entry for target IP input
        self.label2 = tk.Label(self.root, text="Enter target IP to scan:")
        self.label2.pack(pady=5)
        self.target_entry = tk.Entry(self.root, width=30)
        self.target_entry.pack(pady=5)

        # Label and entry for port range input
        self.label3 = tk.Label(self.root, text="Enter Port Range (Optional, Default is 1-1024):")
        self.label3.pack(pady=5)
        self.port_range_entry = tk.Entry(self.root, width=30)
        self.port_range_entry.pack(pady=5)

        # Button to initiate port scan
        self.nmap_button = tk.Button(self.root, text="Scan Ports", command=self.scan_ports_gui)
        self.nmap_button.pack(pady=5)

        # Text area to display results
        self.result_text = scrolledtext.ScrolledText(self.root, width=80, height=10)
        self.result_text.pack(pady=5)

        # Button to exit the application
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=5)

    def check_password_gui(self):
        """
        Callback for the "Check Password" button.
        """
        password = self.password_entry.get()
        result = self.password_checker.check_password(password)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

    def scan_ports_gui(self):
        """
        Callback for the "Scan Ports" button.
        """
        target = self.target_entry.get()
        ports = self.port_range_entry.get() or '1-1024'
        result = self.nmap_scanner.simple_nmap_scan(target, ports)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = GuiApp(root)
    root.mainloop()
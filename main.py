import requests
import hashlib
import nmap
import tkinter as tk

def check_password(password):
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

def simple_nmap_scan(target, ports='1-1024'):
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

def get_ports():
    """
    Ask the user whether to use the default ports or specify their own range.
    
    Returns
    -------
    str
        The range of ports to scan.
    """
    ports = input("Would you like to use the default port range (1-1024)? (y/n): ")
    if ports.lower() == 'n':
        ports = input("Enter the port range (e.g., 80, 443, 1-1024): ")
    else:
        ports = '1-1024'
    return ports

def save_report(report, filename="report.txt"):
    """
    Save the results of a scan or analysis to a text file.

    Parameters
    ----------
    report : str
        The report to save.
    filename : str, optional
        The name of the file to save the report in. Default is 'report.txt'.
    """
    with open(filename, 'a') as f:
        f.write(report + "\n")
    print(f"Report saved to {filename}")

def main():
    """
    The main entry point of the program.

    This function displays a menu for the user to select from and then
    performs the selected action. The actions are:
    1. Check if a password has been compromised
    2. Scan a target for open ports
    3. Detect the services running on a target
    4. Detect the operating system of a target
    5. Detect the vulnerabilities of a target

    After performing the action, the function saves the result to a
    file named 'report.txt' and then loops back to the menu.
    """
    
    while True:
        try:
            print("Welcome to Vulneye. What do you want to do?")
            print("1. Check if a password has been compromised")
            print("2. Scan a target for open ports")
            print("3. Detect the services running on a target")
            print("4. Detect the operating system of a target")
            print("5. Detect the vulnerabilities of a target")
            print("6. Exit")
            choice = int(input("Enter your choice (1-6): "))
            if choice == 1:
                password = input("Enter the password to check: ")
                print(check_password(password))
            elif choice == 2:
                target = input("Enter the target to scan: ")
                ports = get_ports()
                result = simple_nmap_scan(target, ports)
                print(result)
                save_report(result)
            elif choice == 3:
                target = input("Enter the target to detect services on: ")
                ports = get_ports()
                result = detect_services(target, ports)
                print(result)
                save_report(result)
            elif choice == 4:
                target = input("Enter the target to detect the OS of: ")
                result = detect_os(target)
                print(result)
                save_report(result)
            elif choice == 5:
                target = input("Enter the target to detect the vulnerabilities of: ")
                result = detect_vuln(target)
                print(result)
                save_report(result)
            elif choice == 6:
                print("Goodbye!")
                break
            else:
                print("Invalid option, please try again.")
        except ValueError:
            print("Invalid input, please try again.")

if __name__ == "__main__":
    main()

import requests
import hashlib
import nmap

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
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    if response.status_code == 200:
        hashes = (line.split(":") for line in response.text.splitlines())
        for hash, count in hashes:
            if hash == suffix:
                print(f"{password} was compromised {count} times")
                return
        print(f"{password} was not compromised")
        return
    else:
        return("Error: " + str(response.status_code) + "\nCheck your internet connection")


def scan_open_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, "1-1024")
    open_ports = []
    for port in nm[target]['tcp']:
        if nm[target]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    return open_ports

def detect_services(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024', arguments="-sV")
    services = {}
    for port in nm[target]['tcp']:
        services[port] = {
            'name' : nm[target]['tcp'][port]['name'],
            'product' : nm[target]['tcp'][port].get('product', 'Unknown'),
            'version': nm[target]['tcp'][port].get('version', 'Unknown')
        }
    return services
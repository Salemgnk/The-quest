import requests
import hashlib

def check_password(password):
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


check_password("password")
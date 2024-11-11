# The Quest: Vulneye Scanner

## Description

Vulneye Scanner is a password generator and validator that integrates cybersecurity concepts. It helps users create secure passwords while educating them on the importance of password security. This project also offers network monitoring features to help detect potential targets using Nmap.

## Features

- **Password Validator**: Analyzes the strength of a password and checks if it has been compromised using public databases.
- **Network Monitoring (Nmap)**: Scans the network to detect potential targets and analyze open ports.
- **Password Generator**: Creates strong, randomly generated passwords based on custom criteria (length, complexity).
- **Service Detection**: Detects services running on open ports of a target server via Nmap.
- **Vulnerability Detection**: Identifies potential vulnerabilities on a target server or application using Nmap scripts.
- **Operating System Detection**: Detects the operating system of a target using Nmap.

## Prerequisites

- Python 3.x
- Tkinter (for the graphical user interface)
- Requests (to access external APIs)
- Nmap (must be installed locally to use network scanning features)

### Installing Nmap

If Nmap is not installed, you can follow the installation instructions based on your operating system:

- **Windows**: Download [Nmap for Windows](https://nmap.org/download.html).
- **Linux**: Run `sudo apt install nmap` (on Ubuntu/Debian).
- **macOS**: Run `brew install nmap` (if using Homebrew).

## Installation

1. Clone the repository:

   ```bash
   git clone git@github.com:Salemgnk/The-quest.git
   ```

2. Navigate to the project directory:

    ```bash
    cd The-quest
    ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Usage
    
    Run the application by executing the following command in the project directory:

    ```bash
    python3 main.py
    ```

## User Interface

    The application features a graphical user interface (GUI) based on Tkinter. It allows you to choose between the following features:

    - Password Checking: Enter a password to check its security and whether it has been compromised.
    - Network Scan: Enter a target IP address to perform an Nmap scan for open ports, running services, and potential vulnerabilities.
    - Password Generator: Generate strong random passwords based on custom criteria.
    - Go Back: You can go back to the main screen at any time.

## Issues and Limitations

Some Nmap features might not be available or may require elevated privileges (such as full scans or OS detection). If some options are inaccessible or errors occur during the scan, make sure Nmap is properly installed and that you have the necessary permissions.
    **Root/Admin Privilege:** Certain advanced Nmap features (like OS detection) may require you to run the application as an administrator (on Windows) or with sudo (on Linux/Mac).
    **Local Network:** Some network scanning features may only work if you are on the same local network or connected via a VPN.
    **Going Back** : Not implemented yet

## Future Features

    Email/SMS Alerts: Notify users via email or SMS if vulnerabilities are detected or if a password has been compromised.
    Real-Time Port Monitoring: Monitor ports on a target in real-time and get notifications if any changes are detected.
    Report Export: Allow exporting scan results or password check outcomes to text or PDF files for later review.

## Disclaimer

This project is for educational purposes only. Features like keylogging should only be used in an ethical and legal manner. Any use of this application to test the security of a network or service must be done with explicit authorization from the network or service owner.

## Contribution

Contributions are welcome! If you want to improve this project, feel free to submit a pull request and discuss the changes you would like to make.

## Contact

For any questions, feel free to contact me at:

    Professional Email: salem.gnandi@epitech.eu
    Personal Email: gnandisalem@gmail.com

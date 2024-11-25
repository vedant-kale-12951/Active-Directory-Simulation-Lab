# Active-Directory-Simulation-Lab

Overview
This repository demonstrates an Active Directory attack simulation leveraging LLMNR (Link-Local Multicast Name Resolution) poisoning to capture user credentials and escalate privileges. The scenario is based on a phishing-induced breach where credentials were compromised via insecure network protocols.

Attack Methodology
LLMNR Exploitation:

Configured the attacker environment using Responder to intercept LLMNR requests and capture user hashes.
Simulated UNC path requests on compromised machines to retrieve NTLM hashes.
Password Cracking:

Used Hashcat with NTLM hashes and a wordlist (rockyou.txt) to crack passwords and retrieve plaintext credentials.
Vulnerabilities Exploited
CVE-2021-21960: LLMNR-related vulnerability enabling unauthorized credential theft via MITM attacks.
Key Findings
Credentials of multiple users (e.g., Bob and Alice) were compromised without explicit input, exposing critical flaws in network security.
Mitigations
Disable LLMNR:
Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution.
Enforce Secure DNS:
Replace LLMNR with secure DNS-based name resolution.
Network Segmentation:
Isolate critical systems to limit the attack scope.
Why LLMNR is a Threat
LLMNR poisoning enables attackers to steal credentials, access critical systems, and launch further attacks with minimal effort, posing significant risks to network security.

References
For a detailed walkthrough of the procedure and outputs, refer to the accompanying documentation.

Feel free to contribute by submitting issues or pull requests.

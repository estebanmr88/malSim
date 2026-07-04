# Windows Behavioral Simulation (MalSim)

This repository contains a C++ implementation of a controlled simulation tool (`MalSim`) designed to model common post-compromise behaviors observed in Windows environments. It serves as an educational and testing resource for security analysts, EDR validation, and behavioral detection engineering.

### Capabilities

* **Anti-Analysis and Evasion:** Implements multiple layers of debugger detection to bypass active monitoring environments, utilizing APIs, token privilege validation, and active process scanning.
* **Persistence Mechanisms:** Ensures execution continuity by registering a startup key under `CurrentVersion\Run` within the user registry hive and generating an elevated scheduled task triggered upon user logon.
* **Targeted File Modification:** Simulates generic ransomware telemetry by enumerating the user's `Documents` directory, renaming existing files to random identifiers, overwriting payloads, or generating hidden sentinel files in empty directories.
* **Data Exfiltration:** Collects core host hardware specifications and establishes a socket connection via Winsock to securely transmit host info to a designated loopback/internal handler.

***Disclaimer:** This software is intended solely for authorized security simulation, behavioral analysis, and educational evaluation within controlled testing networks.*

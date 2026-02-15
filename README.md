# CVE CRITICALITY AND RISK SCORE EVALUATOR

A cybersecurity project focused on identifying, analyzing, and documenting **Common Vulnerabilities and Exposures (CVEs)**.  
This repository provides tools, research, or documentation to help understand security flaws and improve system security.


## 📌 What is CVE?

**CVE (Common Vulnerabilities and Exposures)** is a public system used to identify and catalog known security vulnerabilities in software and hardware products.  
Each vulnerability is assigned a unique CVE ID, making it easier for security professionals to track, discuss, and remediate issues.

---

## 🎯 Project Objectives

- Analyze known CVEs and their impact
- Provide proof-of-concept (PoC) or reproduction steps (when applicable)
- Document affected systems and versions
- Calculate EPSS Percentge and CVSS RISK Score based on internationally recognized statndards and acclaimed procedures
- RANK the Vulnerabilities and Sort it based on CVSS RISK Score, FIX Available and EPSS percentage
- Help the Engineers to decide project flow and sprint flow based on the criticality of the components

---


## 🚀 Features

- CVE research and analysis
- Clear and structured vulnerability documentation and Ranking
- Easy-to-understand explanations and Reason for the Vulnerabilities
- Input file an Excel sheet containing all the CVE IDS and Vulnerabilities description and Origin and Respective URLS
- Output file to be genrated as An excel sheet with CVSS_Score, CVSS RISK SCore, EPSS Percentage and CVSS Vector String

---

## ⚠️ Disclaimer

This project is intended **for educational and defensive security purposes only**.  
Do **not** use this information or tools to exploit systems you do not own or have explicit permission to test.

The author is **not responsible** for misuse of the information provided.

---

## 🛠 Requirements

Depending on the project scope, you may need:
- Linux / Windows
- Python / Bash / other scripting tools
- Vulnerable test environment (VM, lab setup)

Details will be provided per CVE or module.

---

## 📖 Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/souvikdas2613/CVE_CRITICALITY_AND_RISK_SCOREe.git

---


## 📦 Requirements & Prerequisites

This project requires **Python 3.9 or later**.

### 🔧 Python Dependencies

Install the required Python packages using `pip`:

bash
pip install pandas openpyxl requests python-dotenv

---

### 🔧 Imported Modules

This project uses the following Python modules:

**Standard Library**
```python
import sys
import os
import json
import time
import threading
from collections import defaultdict
from typing import Any
```

**Third Party Library**

```python
import pandas as pd
import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
```
---

## 📖 Contributing

Contributions are welcome!

Fork the repository

Create a new branch

Commit your changes

Open a pull request

Please ensure all contributions follow ethical security guidelines.

---

## 📖 License

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

---

## 📖 Author

- KIRAN KS AND SOUVIK DAS
- CLOUD INFRASTRUCTURE SPECIALIST


---

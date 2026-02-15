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

### 📦 Dependency Installation (YAML)

Create the environment using the provided `requirements.yaml` file:

```bash
conda env create -f requirements.yaml
conda activate cve-project-env
```
---

### 📦 Environment Setup

This project uses environment variables for sensitive configuration.

Create a file .env in your project directory and keep the below Details,

- GITHUB Token for your GITHUB Account
- nvd.nist.gov TOKEN NVD_API_KEY

```
cat .env

# GITHUB TOKEN
GITHUB_TOKEN=github_pat_XXXXXXXXXXXXXXXXXXXX

# NVD API Key (get free key at: https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXX

```

Load environment variables in the code:

```
## Already mention in the code. No need to explicitly define

load_dotenv()

```

---


### 📦 How to Run The Tool with MCP


1. Open CLAUDE Desktop or CURSOR Tool

2. Then GO to MCP TOOLD section inside .cursor/mcp.json file for integrating MCP Tool. Example code given in mcp.json file in this GitHub Repository. Main python file is "CVE_CRITICALITY_MCP_v3.py"

3. On your Local directory keep the Python file and INPUT EXEL sheet "cve.xlsx" together. Make sure Input file name does not differ.

4. Open the AI CHAT Panel in Cursor and Write : "Use the MCP Tool: TOOL NAME and Generate the Output CVE file for vulnaribilities"

5. After processing it will generate the Output file "llm_prioritized_vulnerabilities".

6. On the same direcotry it generates LOG file as well.

7. A sample INPUT EXCEL file to show How the Details in each column and should it be their nomenclature, Here in the repository we kep. File name : "cve.xlsx"

8. Sample output file also kept in this repository name : "llm_prioritized_vulnerabilities.xlsx" 

---


### 📦 How to Run The Tool without MCP

```bash
python CVE_CRITICALITY_WITHOUT_MCP_GRADIO.py

It will start GRADIO on Localhost

Open browser and Copy paste the link of GRADIO on port.

http://127.0.0.1:7860

Upload the Excel file containing the CVE details

Click on Button "ANALIZE CVEs"

It will run and Process the INPUT EXCEL file .

Once done it will create Output file "llm_prioritized_vulnerabilities".

Click on the DOWNLAODABLE link on Gradio UI and download the file in local machine

A sample INPUT EXCEL file to show How the Details in each column and should it be their nomenclature, Here in the repository we kep. File name : "cve.xlsx"

Sample output file also kept in this repository name : "llm_prioritized_vulnerabilities.xlsx" 

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

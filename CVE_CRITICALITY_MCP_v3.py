#   ==============      pip install pandas openpyxl requests openai  ==========  #
import sys
import pandas as pd
import requests
from openai import OpenAI
from dotenv import load_dotenv
import json
import os
#import gradio as gr
import threading
import time
from collections import defaultdict

from typing import Any
from mcp.server.fastmcp import FastMCP

log_script_dir = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(log_script_dir, "CVE_CRITICALITY_MCP.log")

def log (msg):
    with open(LOG_FILE, "a") as f:
        f.write("\n")
        #a=str(msg)
        f.write(str(msg))


# Initialize FastMCP server
mcp = FastMCP("cve-ranking-agent")

# ============ CACHE AND RATE LIMITING CONFIG ============
# Use absolute path for cache file based on script directory
_script_dir = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(_script_dir, "cvss_epss_cache.json")

# NVD Rate Limiting (VERY STRICT - can block IP if exceeded)
# Without API key: 5 requests per 30 seconds = 6 seconds minimum between requests
# With API key: 50 requests per 30 seconds = 0.6 seconds minimum
# Initial values (will be updated if API key is found)
NVD_DELAY = 6.5  # seconds between NVD requests (without API key)
NVD_REQUESTS_PER_30SEC = 5  # Maximum requests per 30-second window (without API key)
NVD_WINDOW_SECONDS = 30  # Time window for rate limiting

GITHUB_DELAY = 0.5  # seconds between GitHub requests
EPSS_DELAY = 0.3  # seconds between EPSS API requests

CACHE_DATA_ITERATION = 100

# Track last request times and request count for rate limiting (thread-safe)
last_nvd_request = threading.Lock()
last_github_request = threading.Lock()
last_epss_request = threading.Lock()
last_nvd_time = [0]
last_github_time = [0]
last_epss_time = [0]

# Track NVD requests in a sliding window
nvd_request_times = []  # List of timestamps of recent NVD requests
nvd_request_lock = threading.Lock()

# Check for NVD API key (if available, can make more requests)
# ⚠️  IMPORTANT: NVD will temporarily block your IP if you exceed limits!
# To get an NVD API key (free): https://nvd.nist.gov/developers/request-an-api-key
# Then set NVD_API_KEY in your .env file
load_dotenv(override=True)
NVD_API_KEY = os.getenv('NVD_API_KEY')
if NVD_API_KEY:
    NVD_REQUESTS_PER_30SEC = 50
    NVD_DELAY = 0.65  # 0.6 seconds is minimum, using 0.65 for safety (allows ~46 requests/30sec)


EXCEL_FILE = "/home/soudas/CVE_SCORE_AI/cve.xlsx"

# ============ CACHE MANAGEMENT ============
def load_cache():
    """Load CVSS scores and EPSS from cache file."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log(f"Warning: Could not load cache: {e}")
            return {}
    return {}


def save_cache(cache):
    """Save CVSS scores and EPSS to cache file."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log(f"Warning: Could not save cache: {e}")


# ============ NVD RATE LIMITING HELPER ============
def wait_for_nvd_rate_limit():
    """
    Wait if necessary to respect NVD rate limits.
    Tracks requests in a 30-second sliding window.
    """
    global nvd_request_times

    current_time = time.time()

    with nvd_request_lock:
        # Clean old requests outside the 30-second window
        nvd_request_times[:] = [t for t in nvd_request_times if current_time - t < NVD_WINDOW_SECONDS]

        # If we've hit the limit, wait until the oldest request expires
        if len(nvd_request_times) >= NVD_REQUESTS_PER_30SEC:
            oldest_request = min(nvd_request_times)
            wait_time = NVD_WINDOW_SECONDS - (current_time - oldest_request) + 1  # +1 second buffer
            if wait_time > 0:
                log(f"⚠️  NVD rate limit reached ({len(nvd_request_times)}/{NVD_REQUESTS_PER_30SEC} requests). "
                      f"Waiting {wait_time:.1f} seconds to avoid IP blocking...")
                time.sleep(wait_time)
                current_time = time.time()
                # Clean again after waiting
                nvd_request_times[:] = [t for t in nvd_request_times if current_time - t < NVD_WINDOW_SECONDS]

        # Ensure minimum delay between requests
        if nvd_request_times:
            time_since_last = current_time - max(nvd_request_times)
            if time_since_last < NVD_DELAY:
                time.sleep(NVD_DELAY - time_since_last)

        # Record this request
        nvd_request_times.append(time.time())

@mcp.tool()
async def getread_excel_sheet(EXCEL_FILE: str = ""):
    """Get The excel sheet about CVE. Name of the Excel sheet can be cve.xls.
        Rank CVEs by CVSS_RISK_SCORE and add RANK + reason

    Args:
        EXCEL_FILE: Path to the Excel file (optional, defaults to cve.xlsx in script directory)
        At the end it will give me output of excel file
    """
    # Redirect all logs to stderr to avoid interfering with MCP JSON protocol
    
    # ============ LOAD & FILTER ============   #

    #   Use PANDA ibrary - Open an Excel file and load it into Python as a table.

    # Use the provided EXCEL_FILE parameter, or default to cve.xlsx if not provided
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if not EXCEL_FILE or EXCEL_FILE == "":
        EXCEL_FILE = os.path.join(script_dir, "cve.xlsx")
    elif not os.path.isabs(EXCEL_FILE):
        # If relative path, make it absolute from the script's directory
        EXCEL_FILE = os.path.join(script_dir, EXCEL_FILE)

    # Normalize the path to handle any path issues
    EXCEL_FILE = os.path.normpath(EXCEL_FILE)

    if not os.path.exists(EXCEL_FILE):
        raise FileNotFoundError(f"Excel file not found: {EXCEL_FILE}")

    df = pd.read_excel(EXCEL_FILE)
    df["Fix"] = df["Fix"].fillna("None")

    #critical_rows = df[df["Severity"].str.upper().isin(["CRITICAL", "MEDIUM","LOW"])]
    critical_rows = df[df["Severity"].str.upper().isin(["CRITICAL", "MEDIUM", "LOW", "UNKNOWN", "NEGLIGIBLE"])]
    log(f"\n\nFound {len(critical_rows)} CRITICAL vulnerabilities\n\n")

    # ============ BUILD DATA FOR LLM ============
    # Load cache

    cvss_cache = load_cache()
    log(f"Loaded {len(cvss_cache)} cached entries\n")

    # Strategy: Deduplicate CVEs first, fetch scores, then map back to all rows
    log("Deduplicating CVEs to minimize API calls...")
    unique_cves = {}
    for _, row in critical_rows.iterrows():
        cve = row["CVE ID"]
        url = row["URL"]
        severity = row["Severity"]

        cache_key = f"{cve}_{url}"
        if cache_key not in unique_cves:
            unique_cves[cache_key] = {
                "cve": cve,
                "url": url,
                "severity": severity
            }

    log(f"Found {len(unique_cves)} unique CVE/URL combinations (out of {len(critical_rows)} total rows)\n")

    # Fetch CVSS scores and EPSS for unique CVEs
    total_unique = len(unique_cves)

    # Don't log large data structures to avoid issues
    # log(unique_cves)

    # Estimate processing time
    # Assume: 30% GitHub (faster), 70% NVD (slower with rate limiting)
    # Average delay per request
    avg_delay = (0.3 * GITHUB_DELAY) + (0.7 * NVD_DELAY)
    estimated_seconds = total_unique * avg_delay
    estimated_minutes = estimated_seconds / 60

    # log to stderr to avoid interfering with MCP JSON protocol
    log(f"Fetching CVSS scores and EPSS...")
    log(f"📊 Estimated time: ~{estimated_minutes:.1f} minutes for {total_unique} unique CVEs")
    log(f"   (Actual time will be less due to caching and parallel processing)\n")

    processed = 0
    cached_count = 0

    for cache_key, cve_info in unique_cves.items():
        processed += 1
        cve = cve_info["cve"]
        url = cve_info["url"]
        severity = cve_info["severity"]

        # Check if already in cache
        was_cached = cache_key in cvss_cache

        epss, cvss, CVSS_vectorString, CVSS_RISK_SCORE, Rejected_Reason = get_cvss_score(cve, url, severity, cache=cvss_cache)

        if was_cached:
            cached_count += 1
            log("cached_count          :" + str(cached_count))

        # Save cache every 100 requests to prevent data loss
        if processed % CACHE_DATA_ITERATION == 0:
            save_cache(cvss_cache)
            log("cache saved 3")
            log(f"Progress: {processed}/{total_unique} ({processed*100//total_unique}%) | "
                  f"Cached: {cached_count} | API calls: {processed - cached_count}")

        # Store result
        unique_cves[cache_key]["epss"] = epss
        unique_cves[cache_key]["cvss"] = cvss
        unique_cves[cache_key]["CVSS_vectorString"] = CVSS_vectorString
        unique_cves[cache_key]["CVSS_RISK_SCORE"] = CVSS_RISK_SCORE
        unique_cves[cache_key]["Rejected_Reason"] = Rejected_Reason

    # Final cache save
    save_cache(cvss_cache)
    log("cache saved 4")
    log(f"\nCompleted! Used {cached_count} cached scores, made {total_unique - cached_count} API calls\n")

    # Now map back to all rows
    log("Building vulnerability data for LLM...")
    vuln_data = []

    for _, row in critical_rows.iterrows():
        cve = row["CVE ID"]
        url = row["URL"]
        cache_key = f"{cve}_{url}"

        cve_data = unique_cves.get(cache_key, {})
        if cve_data:
            log("\nalready cached data exists for :     " + str(cache_key))
        epss = cve_data.get("epss", 0)
        cvss = cve_data.get("cvss", None)
        CVSS_vectorString = cve_data.get("CVSS_vectorString", None)
        CVSS_RISK_SCORE = cve_data.get("CVSS_RISK_SCORE", 0)
        severity = row["Severity"]
        Fix = row["Fix"]
        rejected_reason = cve_data.get("Rejected_Reason", None)

        vuln_data.append({
            "image": row["Component"],
            "cve": cve,
            "package": row["Package"],
            "cvss_score": cvss,
            "EPSS Percentage": epss,
            "severity": severity,
            "CVSS_RISK_SCORE": CVSS_RISK_SCORE,
            "url": url,
            "Fix": Fix,
            "CVSS_vectorString": CVSS_vectorString,
            "Rejected_Reason": rejected_reason
        })

    log(f"\nBuilt {len(vuln_data)} vulnerability records\n")

    # Don't log large data structures to avoid issues
    # log(vuln_data)

    result = log_LLM_JSON_result_in_Excel_Sheet(vuln_data)

    # Return success message with output file path
    output_file = os.path.join(script_dir, "llm_prioritized_vulnerabilities.xlsx")
    
    # Ensure output is flushed before returning
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Return immediately after file generation
    # Use plain text without emoji to avoid JSON parsing issues
    if result and isinstance(result, str) and "Failed" in result:
        return result
    else:
        success_msg = f"Successfully processed {len(vuln_data)} vulnerabilities. Output saved to: {output_file}"
        return success_msg


def get_CVSS_RISK_SCORE(score, epss, severity):

    # Risk = (CVSS × 6) + (EPSS × 0.4) + Severity Bonus + Attack Vector Bonus

    severity_bonus = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 0
    }

    CVSS_RISK_SCORE = (score * 6) + (epss * 0.4) + severity_bonus.get(severity.upper(), 0)
    log("\ninside get_CVSS_RISK_SCORE   :    " + str(CVSS_RISK_SCORE))
    return CVSS_RISK_SCORE


def get_cvss_score(cve_or_ghsa, url, severity, cache=None):

    """
    Fetch CVSS score, EPSS, and vector string from GitHub or NVD API for a CVE/GHSA ID.
    Uses caching to avoid duplicate API calls.

    Returns:
        tuple: (epss, score, CVSS_vectorString)
    """
    global last_nvd_time, last_github_time, last_epss_time

    # API Base URLs
    GITHUB_URL = "https://api.github.com/advisories"
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Check cache first
    cache_key = f"{cve_or_ghsa}_{url}"
    if cache and cache_key in cache:
        cached_data = cache[cache_key]
        return (
            cached_data.get("epss", 0),
            cached_data.get("cvss", None),
            cached_data.get("CVSS_vectorString", None),
            cached_data.get("CVSS_RISK_SCORE", 0),
            cached_data.get("Rejected_Reason", None)
        )

    load_dotenv(override=True)
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    epss = 0
    score = 0
    CVSS_vectorString = None
    CVSS_RISK_SCORE = 0.0
    Rejected_Reason = None

    # --- Step 1: Try GitHub first ---
    if ("github" in url.lower()):
        # Rate limiting for GitHub
        with last_github_request:
            current_time = time.time()
            time_since_last = current_time - last_github_time[0]
            if time_since_last < GITHUB_DELAY:
                time.sleep(GITHUB_DELAY - time_since_last)
            last_github_time[0] = time.time()

        api_url = f"{GITHUB_URL}/{cve_or_ghsa}"
        try:
            resp = requests.get(api_url, headers=HEADERS, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            log("\n\n" + str(api_url) + "\n\n")
            log(data)

            cvss_v4 = float(data['cvss_severities']['cvss_v3']['score'])
            cvss_v3 = float(data['cvss_severities']['cvss_v4']['score'])

            if cvss_v4:
                score = cvss_v4
            else:
                score = cvss_v3

            CVSS_vectorString_v4 = data['cvss_severities']['cvss_v4']['vector_string']
            CVSS_vectorString_v3 = data['cvss_severities']['cvss_v3']['vector_string']

            if CVSS_vectorString_v4:
                CVSS_vectorString = CVSS_vectorString_v4
            else:
                CVSS_vectorString = CVSS_vectorString_v3

            # Get EPSS from GitHub response if available
            if 'epss' in data and 'percentage' in data['epss']:
                epss = float(data['epss']['percentage'])

        except Exception as e:
            log(f"Error fetching GHSA {cve_or_ghsa}: {e}")

    else:   # --- Step 2: Fallback to NVD API ---
        # Wait for rate limit before making request
        wait_for_nvd_rate_limit()

        # Make the request with retry logic
        max_retries = 3
        retry_delay = 5  # Start with 5 seconds
        for attempt in range(max_retries):
            try:
                # Build request URL with API key if available
                url = f"{NVD_BASE_URL}?cveId={cve_or_ghsa}"
                headers = {}
                if NVD_API_KEY:
                    # NVD API key can be passed as header or query param - using header
                    headers["apiKey"] = NVD_API_KEY

                nvd_resp = requests.get(url, headers=headers, timeout=15)

                # Check for rate limit errors
                if nvd_resp.status_code == 429:  # Too Many Requests
                    wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                    log(f"⚠️  NVD rate limit error (429). Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                    continue
                elif nvd_resp.status_code == 403:  # Forbidden (IP blocked)
                    log(f"❌ NVD returned 403 Forbidden - IP may be temporarily blocked. Skipping {cve_or_ghsa}")
                    log("   Consider using an NVD API key or waiting longer between requests.")
                    break
                
                nvd_resp.raise_for_status()
                log("\n\n" + str(url) + "\n\n")
                log(nvd_resp.json())

                vulns = nvd_resp.json().get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0]["cve"].get("metrics", {})
                    # Try CVSS v4 first (newer), then v3
                    if "cvssMetricV40" in metrics:
                        score = float(metrics["cvssMetricV40"][0]["cvssData"]["baseScore"])
                        CVSS_vectorString = metrics["cvssMetricV40"][0]["cvssData"].get("vectorString")
                    elif "cvssMetricV31" in metrics:
                        score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
                        CVSS_vectorString = metrics["cvssMetricV31"][0]["cvssData"].get("vectorString")
            
                    else:
                        pass

                    #### If REJECTED REASON there..

                    if (vulns[0]["cve"]["vulnStatus"]).upper() == "REJECTED":
                        reason = next(
                            d["value"]
                            for d in vulns[0]["cve"]["descriptions"]
                            if d["lang"] == "en"
                        )
                        Rejected_Reason = reason

                break  # Success, exit retry loop

            except requests.exceptions.HTTPError as e:
                if e.response.status_code in [429, 403]:
                    wait_time = retry_delay * (2 ** attempt)
                    log(f"⚠️  NVD HTTP error {e.response.status_code}. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    if attempt == max_retries - 1:
                        log(f"❌ Failed to fetch {cve_or_ghsa} after {max_retries} attempts")
                else:
                    log(f"NVD fetch error for {cve_or_ghsa}: {e}")
                    break
            except Exception as e:
                log(f"NVD fetch error for {cve_or_ghsa}: {e}")
                break

    # --- Step 3: Fetch EPSS from FIRST.org API ---
    if not epss:  # Only fetch if not already got from GitHub and for NVD alsways we need to go to FAST API
        
        # Rate limiting for EPSS API
        with last_epss_request:
            current_time = time.time()
            time_since_last = current_time - last_epss_time[0]
            if time_since_last < EPSS_DELAY:
                time.sleep(EPSS_DELAY - time_since_last)
            last_epss_time[0] = time.time()
    
        try:
            epss_url = f"https://api.first.org/data/v1/epss?cve={cve_or_ghsa}"
            epss_resp = requests.get(epss_url, timeout=10)
            epss_resp.raise_for_status()
            epss_data = epss_resp.json()
            if epss_data.get("data") and len(epss_data["data"]) > 0:
                epss = float(epss_data["data"][0]["epss"])
        except Exception as e:
            log(f"EPSS API fetch error for {cve_or_ghsa}: {e}")


    CVSS_RISK_SCORE = get_CVSS_RISK_SCORE(score, epss, severity)

    # Save to cache
    if cache is not None:
        cache[cache_key] = {
            "epss": epss,
            "cvss": score,
            "CVSS_vectorString": CVSS_vectorString,
            "CVSS_RISK_SCORE": CVSS_RISK_SCORE,
            "Rejected_Reason": Rejected_Reason

        }

    # --- Step 4: Return results ---
    return epss, score, CVSS_vectorString, CVSS_RISK_SCORE, Rejected_Reason


def log_LLM_JSON_result_in_Excel_Sheet(vuln_data):

    ranked = []
    for data in vuln_data:
        ranked.append(data)

    ranked.sort(
        key=lambda x: (
            -float(x["CVSS_RISK_SCORE"]),   # 1. Highest CVSS first
            x["Fix"],                       # 2. If FIX there
            -float(x["EPSS Percentage"])   # 3. Highest EPSS first
        )
    )

    # ==========================
    # SAVE LLM OUTPUT TO EXCEL
    # ==========================

    try:

        # Convert list → DataFrame
        df = pd.DataFrame(ranked)
        df = df.sort_values(by="CVSS_RISK_SCORE", ascending=False)

        # Save to Excel
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = os.path.join(script_dir, "llm_prioritized_vulnerabilities.xlsx")

        # Remove old file if it exists to ensure fresh generation each time
        if os.path.exists(output_file):
            os.remove(output_file)
            log(f"Removed existing output file: {output_file}")

        df.to_excel(output_file, index=False)
        
        df = pd.read_excel(output_file)
        """
        # Move 'rank' column to the first position
        cols = df.columns.tolist()
        cols.insert(0, cols.pop(cols.index('RANK')))  # remove 'rank' and insert at index 0
        df = df[cols]
        """
        df["Fix"] = df["Fix"].fillna("None")

        # Save back to Excel
        df.to_excel(output_file, index=False)
        

        log(f"\n✅ Excel report saved as: {output_file}")
        return output_file

    except Exception as e:
        log("\n❌ Failed to save Excel output:", e)
        return "Failed to save Excel output"



def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()

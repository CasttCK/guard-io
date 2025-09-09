import requests
from flask import Flask, render_template, request, jsonify, send_from_directory
from dotenv import load_dotenv

import pandas as pd
import tldextract
import validators
import os
import re


# ================================ Functions ================================
def load_tranco_whitelist(csv_path, search_limit):
    spreadsheet_data = pd.read_csv(csv_path, header=None, names=["rank", "domain"])
    domains = spreadsheet_data["domain"].head(search_limit).str.lower().tolist()
    return set(domains)


# ================================ Variables ================================
load_dotenv()
app = Flask(__name__)
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
WHITELIST = load_tranco_whitelist("tranco_list.csv", 100000)


# ================================ Routes ================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(os.getcwd(), "assets"), filename)


@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.json.get("url")
    score = 0
    issues = []

    if url.startswith("https://"):
        score += 20
    else:
        issues.append("URL sem HTTPS")

    if not validators.url(url):
        return jsonify({"url": url, "domain": url, "score": 0, "status": "invalid", "issues": issues})

    extracted_domain_from_url = tldextract.extract(url)
    domain = f"{extracted_domain_from_url.domain}.{extracted_domain_from_url.suffix}"

    if domain in WHITELIST:
        score += 30
    else:
        issues.append("O domínio não consta na lista de confiabilidade")

    if len(url) < 100:
        score += 10
    else:
        issues.append("A URL é muito longa")

    if "-" in domain:
        issues.append("O domínio contém hífen (suspeito)")

    if re.search(r"[^\x00-\x7F]", url):
        issues.append("O domínio contém caracteres não ASCII (pode ser homográfico)")

    try:
        headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
        data = {"url": url}

        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        analysis_id = response.json()["data"]["id"]

        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()

        stats = result["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            issues.append(f"VirusTotal detectou {malicious} arquivo(s) malicioso(s), "
                          f"{suspicious} arquivo(s) suspeito(s)")
            score = 0
        else:
            score += 40

    except Exception as e:
        issues.append(f"Erro ao consultar VirusTotal: {str(e)}")

    if score >= 80 and not issues:
        status = "reliable"
    elif score >= 60 and len(issues) < 2:
        status = "acceptable"
    else:
        status = "suspect"

    return jsonify({
        "url": url,
        "domain": domain,
        "score": score,
        "status": status,
        "issues": issues
    })


if __name__ == "__main__":
    app.run(debug=True)

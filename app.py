import requests
from flask import Flask, render_template, request, jsonify, send_from_directory
from dotenv import load_dotenv

import pandas as pd
import tldextract
import validators
import os
import re


# ================================ Variables ================================
load_dotenv()
app = Flask(__name__)
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")


def load_tranco_whitelist(csv_path, search_limit):
    spreadsheet_data = pd.read_csv(csv_path, header=None, names=["rank", "domain"])
    domains = spreadsheet_data["domain"].head(search_limit).str.lower().tolist()
    return set(domains)


WHITELIST = load_tranco_whitelist("tranco_list.csv", 100000)


# ================================ Functions ================================
def extract_domain_from_url_and_validate(url, state):
    extracted_domain_from_url = tldextract.extract(url)
    domain = f"{extracted_domain_from_url.domain}.{extracted_domain_from_url.suffix}"

    if "-" in domain:
        state["issues"].append("O domínio contém hífen (suspeito)")

    if re.search(r"[^\x00-\x7F]", url):
        state["issues"].append("O domínio contém caracteres não ASCII (pode ser homográfico)")

    return domain


def validate_https(url, state):
    if url.startswith("https://"):
        state["score"] += 20
    else:
        state["issues"].append("URL sem HTTPS")


def validate_domain_in_whitelist(domain, state):
    if domain in WHITELIST:
        state["score"] += 30
    else:
        state["issues"].append("O domínio não consta na lista de confiabilidade")


def validate_url_length(url, state):
    if len(url) < 100:
        state["score"] += 10
    else:
        state["issues"].append("A URL é muito longa")


def check_url_on_virustotal(url, state):
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
            state["issues"].append(f"VirusTotal detectou {malicious} arquivo(s) malicioso(s), "
                          f"{suspicious} arquivo(s) suspeito(s)")
            state["score"] = 0
        else:
            state["score"] += 40

    except Exception as e:
        state["issues"].append(f"Erro ao consultar VirusTotal: {str(e)}")


def check_score_and_set_status(state):
    if state["score"] >= 80 and not state["issues"]:
        state["status"] = "reliable"
    elif state["score"] >= 60 and len(state["issues"]) < 2:
        state["status"] = "acceptable"
    else:
        state["status"] = "suspect"


def perform_necessary_checks(url):
    if not validators.url(url):
        return jsonify({"url": url, "domain": "", "score": 0, "status": "invalid", "issues": []})

    state = {"status": "", "score": 0, "issues": []}
    domain = extract_domain_from_url_and_validate(url, state)

    validate_https(url, state)
    validate_domain_in_whitelist(domain, state)
    validate_url_length(url, state)
    check_url_on_virustotal(url, state)
    check_score_and_set_status(state)

    return jsonify({
        "url": url,
        "domain": domain,
        "status": state["status"],
        "score": state["score"],
        "issues": state["issues"]
    })


# ================================ Routes ================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(os.getcwd(), "assets"), filename)


@app.route("/check_url", methods=["POST"])
def check_url():
    url = str.lower(request.json.get("url"))
    return perform_necessary_checks(url)


if __name__ == "__main__":
    app.run(debug=True)

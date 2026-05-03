# 🔐 Email Header Analyzer

## 🚀 Overview

Email Header Analyzer is a cybersecurity-focused API that inspects email headers to detect spoofing, phishing attempts, and authentication failures using SPF, DKIM, and DMARC analysis.

Built for security analysts and SOC environments to quickly validate email authenticity and assess risk.

---

## ⚡ Features

* SPF validation (Sender Policy Framework)
* DKIM signature verification
* DMARC policy enforcement check
* Header parsing & anomaly detection
* Heuristic-based phishing detection
* Risk scoring engine (Low / Medium / High)

---

## 🛠️ Tech Stack

* Python
* FastAPI
* AsyncIO
* DNS Resolution
* Email Security Protocols (SPF, DKIM, DMARC)

---

## 📂 Project Structure

```
email-header-analyzer/
│── app/
│   ├── auth_checks.py
│   ├── config.py
│   ├── heuristics.py
│   ├── intel.py
│   ├── main.py
│   ├── models.py
│   ├── scoring.py
│
│── run.py
│── requirements.txt
│── README.md
│── .gitignore
```

---

## ▶️ Run Locally

### 1. Clone the repository

```
git clone https://github.com/your-username/email-header-analyzer.git
cd email-header-analyzer
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Start the server

```
python run.py
```

---

## 🔌 API Usage

### Endpoint

```
POST /analyze
```

### Sample Request

```json
{
  "header": "Received: from mail.example.com ... (full email header here)"
}
```

### Sample Response

```json
{
  "spf": "pass",
  "dkim": "pass",
  "dmarc": "fail",
  "risk_score": 75,
  "risk_level": "High",
  "issues": [
    "DMARC policy failed",
    "Suspicious sending domain"
  ]
}
```

---

## 🧪 What It Detects

* Spoofed sender domains
* SPF/DKIM/DMARC failures
* Suspicious routing paths
* Phishing indicators in headers

---

## 📸 Demo

<img width="1338" height="637" alt="image" src="https://github.com/user-attachments/assets/ea7cc21b-9539-47a0-9614-ebb6d9ad6c52" />





---

## 🎯 Use Cases

* SOC analysis of suspicious emails
* Phishing investigation
* Email authentication validation
* Security research & learning

---

## 🚧 Future Enhancements

* Web UI dashboard
* Threat intelligence integration (VirusTotal, AbuseIPDB)
* Real-time email monitoring
* SIEM integration (Splunk)

---

## 👨‍💻 Author

Sukhesh A

---

## ⭐ If you found this useful

Give it a star ⭐ on GitHub — helps visibility and credibility.

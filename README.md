# 🛡️ PhishVault

**PhishVault** is a phishing detection web app that analyzes URLs to detect malicious or suspicious behavior using multiple techniques including:

- SSL Certificate validation
- Domain age analysis
- Keyword inspection
- Redirect chain checks
- Threat intelligence from Google Safe Browsing and PhishTank
- IP reputation via AbuseIPDB
- DNS record inspection

## 🚀 Features

- 🔐 Login/logout system with Flask-Login
- 📬 Forgot password flow (Mailtrap + Flask-Mail)
- 🌐 URL scanning through a multi-step phishing detection pipeline
- 📊 Dashboard for users to track scans
- 🧠 Community reports placeholder for future crowdsourced data

## 🧰 Built With

- Python + Flask
- SQLite
- Flask-Login, Flask-Mail
- Requests, Whois, DNSPython
- Google Safe Browsing API, PhishTank (manual JSON), AbuseIPDB

## 📁 Project Structure

```
PhishVault/
│
├── templates/              # HTML templates
├── static/                 # CSS, JS, images
├── models.py               # SQLAlchemy models
├── auth_routes.py          # Auth logic (login, signup, forgot password)
├── phishing_routes.py      # URL scanning routes and logic
├── dashboard_routes.py     # Dashboard logic (optional/coming soon)
├── app.py                  # App setup and blueprint registration
├── .env                    # Environment variables (not committed)
└── phishtank_data.json     # Manually downloaded threat data
```

## 📦 Setup Instructions

1. **Clone the repo**
   ```bash
   git clone https://github.com/chinmay161/PhishVault.git
   cd PhishVault
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create `.env` file** and add your Mailtrap, API keys, and secret key.

4. **Run the app**
   ```bash
   flask run
   ```

## 📧 Contact

Feel free to reach out via [GitHub Issues](https://github.com/chinmay161/PhishVault/issues) or fork the project if you'd like to contribute!

---

**Status:** 🎓 College Project | 🛠️ Still in development

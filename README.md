# 🛡️ **PhishVault**

## 📌 Overview

**PhishVault** is a phishing detection and URL analysis platform built using Flask. It helps users detect and assess potentially malicious websites by performing various security checks including SSL verification, domain age analysis, keyword scans, redirect tracing, and threat intelligence lookups (e.g., Google Safe Browsing, PhishTank, AbuseIPDB).

---

## 📂 Project Structure

```
PhishVault/
│
├── app.py                   # Main application file
├── models.py                # SQLAlchemy database models
├── auth_routes.py           # Authentication logic
├── phishing_routes.py       # URL scanning and analysis
├── dashboard_routes.py      # User dashboard functionality
├── admin_routes.py          # Admin panel logic
├── csrf_protection.py       # CSRF protection utility
├── extensions.py            # Socket.IO setup
├── static/                  # Static assets (CSS, JS, icons)
├── templates/               # Jinja2 templates
├── requirements.txt         # Python dependencies
└── README.md                # Project readme
```

---

## 🛠️ Setup & Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/chinmay161/PhishVault.git
   cd PhishVault
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   Create a `.env` file with:

   ```
   FLASK_SECRET_KEY=your_secret_key
   DATABASE_URL=sqlite:///phishvault.db
   MAIL_SERVER=smtp.mailtrap.io
   MAIL_PORT=2525
   MAIL_USERNAME=your_mailtrap_username
   MAIL_PASSWORD=your_mailtrap_password
   MAIL_DEFAULT_SENDER=noreply@phishvault.com
   GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   ```

5. **Run the application**

   ```bash
   python app.py
   ```

---

## 🔐 Authentication Flow

* **Signup**: Creates a new user account and sends a verification email.
* **Login**: Authenticates user after email verification.
* **Forgot Password**: Sends a reset link with a secure token.
* **Reset Password**: Resets user password after token validation.

**Token models:**

* `Token`: For email verification.
* `PasswordResetToken`: For password resets.

---

## 🌐 URL Scanning Features

Each scan includes:

1. **SSL Certificate Check**
2. **Domain Age Analysis**
3. **Suspicious Keywords**
4. **Redirect Chain Analysis**
5. **Threat Database Lookup** (Google Safe Browsing, PhishTank)
6. **IP Reputation** (AbuseIPDB)
7. **DNS Record Details**

**Risk Score Calculation**: Weighted based on severity of detected issues.

---

## 📊 Dashboard

### For Users:

* View total scans, safe/malicious stats.
* Paginated recent scan history.
* Export scan report as CSV.
* Visual risk trends over the last 6 months.

### For Admins:

* View total users, scans, malicious counts.
* Manage social/partner links.
* Edit policy documents (TOS, Privacy).
* View and export user data.
* Enable/disable link visibility.

---

## 🧩 Models Summary

### `User`

* Fields: `email`, `password_hash`, `role`, `is_active`, etc.
* Relations: tokens, password reset tokens, scan results.

### `ScanResult`

* Stores result data for each URL scan.

### `Token` / `PasswordResetToken`

* Handles verification and reset logic.

### `Link`

* Stores social and partner links for frontend.

### `PolicyDocument`

* Editable legal documents via the admin panel.

---

## 🔧 **Admin Panel**

**URL:** `/admin/dashboard`
**Access:** Only for users with `role='admin'`

### 📊 Features of the Admin Panel:

* **Dashboard Overview**

  * Total users
  * Total scans
  * Malicious scan count
  * Basic charts for visual summary

* **User Management**

  * View all registered users
  * Export user list as CSV

* **Policy Editor**

  * Edit and update Terms of Service and Privacy Policy
  * Changes are reflected in `/terms` and `/privacy`

* **Link Management**

  * Add/edit/delete social and partner links
  * Toggle visibility of each link

* **Chart Data API**

  * Endpoint: `/admin/chart-data`
  * Used by frontend to populate admin charts

---

## 🔒 Security Features

* CSRF protection via `@csrf_protect` decorator
* Session protection: Secure, HttpOnly cookies
* Token-based email verification
* Rate-limiting and error handling (WIP recommended)

---

## 📤 Export & Reporting

* **CSV Reports**:

  * Scan history for users (`/dashboard/export/report.csv`)
  * All users for admins (`/admin/export/users.csv`)

---

## 📡 WebSocket Integration

* Real-time scan progress updates via Flask-SocketIO.
* Emits `scan_progress` events to frontend for UX feedback.

---

## 📄 License & Contribution

This is a college-level project and open for educational collaboration. You can raise issues or PRs via GitHub.

---

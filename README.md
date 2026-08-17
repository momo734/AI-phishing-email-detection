# MailShield

Web based AI phishing email detection project using React, Node.js, Express, and XAMPP MySQL.

## Features

- React frontend scanner.
- Node.js backend API.
- XAMPP MySQL database for users and registered scan history.
- User-selected AI model: Logistic Regression or Naive Bayes.
- TF-IDF prediction score with top weighted terms.
- Guests receive 5 free scans in the browser.
- Users must register after 5 guest scans.
- Registered users can scan without the guest limit and view scan history.

## Database Setup

1. Start Apache and MySQL in XAMPP.
2. Open phpMyAdmin.
3. Import `database.sql`, or create a database named `phishing_detector`.
4. If your MySQL port is not `3307`, update `DB_PORT` in `server.js` or start the server with an environment variable.

Default backend database settings:

```txt
host: 127.0.0.1
port: 3307
user: root
password: empty
database: phishing_detector
```

## Run Project

Install dependencies if needed:

```bash
npm install
```

Start the backend:

```bash
npm run server
```

Start the React frontend in another terminal:

```bash
npm run dev
```

Open the Vite URL, usually:

```txt
http://localhost:5173
```

## Dataset Setup

Put your phishing email dataset here:

```txt
https://1024terabox.com/s/1rm4Mc8udtyqiqcn1hrEPGw```

The CSV needs these columns:

```csv
text,label
"email body here",phishing
"normal email body here",legitimate
```

Accepted text column names:

```txt
text, email, email_text, body, message
```

Accepted label column names:

```txt
label, class, category, target
```

Accepted phishing labels:

```txt
1, phishing, phish, malicious, spam
```

Accepted legitimate labels:

```txt
0, legitimate, legit, ham, safe, benign
```

Restart the backend after replacing the CSV so the AI model trains from your dataset.

## Build Check

```bash
npm run build
```

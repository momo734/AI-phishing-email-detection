# MailShield: AI-Powered Phishing Email Detection System

**Assignment Documentation (Final Version — Model Cache v15)**

---

**Student name:** *[Your name]*  
**Student ID:** *[Your ID]*  
**Module / Course:** *[Module name]*  
**Institution:** *[Your institution]*  
**Submission date:** *[Date]*  

---

## Abstract

MailShield is a full-stack web application that classifies email text as **phishing** or **legitimate** using classical machine learning. The system implements **TF-IDF** feature extraction, **Logistic Regression**, and **Multinomial Naive Bayes** entirely in Node.js, without external ML libraries. Users paste or upload email content, choose a model (“Standard check” or “Second opinion”), and receive a verdict with **explainability** features including highlighted phrases, sentiment indicators, and safety recommendations.

The model is trained on **155,859** labelled emails merged from seven public CSV corpora. On a held-out test set of **31,171** emails, Logistic Regression achieves **97.46% accuracy** (416 false positives, 377 false negatives) and Naive Bayes achieves **95.47% accuracy** (418 false positives, 994 false negatives). A separate eleven-sample diverse validation set shows that legitimate **banking** notifications remain a documented false-positive challenge, while **newsletter** and **password-change** emails improved after statistically principled feature-selection refinements in v15.

The application uses a **React** frontend, **Express** backend, **MySQL** for user accounts and scan history, **JWT** authentication with bcrypt password hashing, and **JSON model caching** for fast startup. Verdicts are driven solely by **raw ML probability** compared to validation-tuned thresholds; heuristic rules support explainability only and do not override the classifier.

**Keywords:** phishing detection, TF-IDF, Logistic Regression, Naive Bayes, explainability, full-stack web application, email security.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Literature Review](#2-literature-review)
3. [System Design and Implementation](#3-system-design-and-implementation)
4. [Results and Evaluation](#4-results-and-evaluation)
5. [Discussion and Limitations](#5-discussion-and-limitations)
6. [Conclusion](#6-conclusion)
7. [References](#7-references)
8. [Appendices](#8-appendices)

---

## 1. Introduction

### 1.1 Background

Phishing is a social-engineering attack in which criminals impersonate trusted organisations to steal credentials, money, or data. Email remains the primary delivery channel. Technical controls such as SPF/DKIM/DMARC and spam gateways are necessary but insufficient: many phishing messages pass infrastructure checks because their **wording** resembles legitimate notifications from banks, retailers, or employers.

Machine learning offers a content-based approach. **TF-IDF** converts text into numerical features; **Logistic Regression** and **Naive Bayes** are well-established classifiers that balance accuracy, speed, and interpretability on modest hardware—making them suitable for educational and small-scale deployments.

### 1.2 Problem Statement

Users need a tool that:

1. Analyses suspicious email text quickly without enterprise mail-gateway access.
2. Explains *why* a message was flagged in understandable language.
3. Compares two classical ML models side by side.
4. Stores scan history for registered users while allowing limited guest trials.

### 1.3 Aim and Objectives

**Aim:** Design, implement, and evaluate MailShield—a web-based phishing email detection system with dual ML models and explainability.

| # | Objective | Status |
|---|-----------|--------|
| 1 | Merge multiple public datasets into one training corpus | Achieved (7 CSV files, 155,859 unique emails) |
| 2 | Implement TF-IDF, feature selection, LR, and NB in Node.js | Achieved |
| 3 | Evaluate on held-out test data (accuracy, precision, recall, F1, ROC-AUC) | Achieved |
| 4 | Provide explainability (highlights, sentiment, recommendations) | Achieved |
| 5 | Implement guest scans, JWT auth, MySQL history | Achieved |
| 6 | Critically report limitations (e.g. banking false positives) | Achieved |

### 1.4 Scope

**In scope:** Text-based email body analysis; LR and NB; React UI; Express API; MySQL; model caching; explainability.

**Out of scope:** Live IMAP/Outlook integration; attachment analysis; deep learning (BERT/LSTM); production HTTPS deployment; external URL reputation APIs.

---

## 2. Literature Review

### 2.1 Phishing and Email Threats

Phishing exploits urgency, fear, and familiarity. Legitimate transactional emails (statements, shipping updates, password resets) share vocabulary with phishing templates (“account,” “verify,” “payment”), creating a fundamental challenge for bag-of-words classifiers: **intent is hard to infer from words alone**.

### 2.2 Traditional vs ML Approaches

| Approach | Strength | Weakness |
|----------|----------|----------|
| Keyword / rule filters | Fast, interpretable | Brittle; high false positives on legitimate mail |
| Blacklists | Effective on known threats | Miss novel campaigns |
| SPF/DKIM/DMARC | Reduces spoofing | No content analysis |
| TF-IDF + LR/NB | Strong on text; efficient | Domain shift; vocabulary overlap |

### 2.3 Selected Algorithms

**Logistic Regression** models log-odds of phishing as a linear combination of TF-IDF features. Training uses stochastic gradient descent with L2 regularisation.

**Multinomial Naive Bayes** estimates class-conditional token probabilities with Laplace smoothing (α = 0.5). Priors are computed from training data.

**TF-IDF** emphasises terms frequent in a document but rare across the corpus. MailShield uses sublinear term frequency, document-length normalisation, and IDF computed on the training set only.

---

## 3. System Design and Implementation

### 3.1 Architecture

```
┌─────────────────┐     REST API      ┌──────────────────────────────┐
│  React Frontend │ ◄──────────────► │  Node.js / Express (server.js)│
│  (Vite, App.jsx)│                   │  • /api/analyze               │
└─────────────────┘                   │  • /api/auth/*               │
                                      │  • /api/history               │
                                      │  • classifyEmail()            │
                                      └───────────┬──────────────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    ▼                             ▼                             ▼
            ┌──────────────┐           ┌─────────────────┐           ┌──────────────┐
            │ MySQL        │           │ Model cache     │           │ CSV datasets │
            │ users        │           │ .model-cache    │           │ data/*.csv   │
            │ history      │           │ (v15)           │           │              │
            └──────────────┘           └─────────────────┘           └──────────────┘
```

### 3.2 Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite 8, CSS |
| Backend | Node.js, Express 5 |
| Database | MySQL (XAMPP, port 3307 default) |
| Authentication | JWT (8h expiry), bcrypt (12 rounds) |
| ML | Pure JavaScript (no scikit-learn / TensorFlow) |

### 3.3 Dataset

| Source file | Approx. rows | Notes |
|-------------|--------------|-------|
| CEAS_08.csv | 39,154 | Mixed |
| Enron.csv | 29,767 | Mixed |
| phishing_email.csv | 82,485 | Mixed |
| SpamAssasin.csv | 5,809 | Mixed |
| Ling.csv | 2,859 | Mixed |
| Nazario.csv | 1,565 | Phishing only |
| Nigerian_Fraud.csv | 3,332 | Phishing only |

**After deduplication:** 155,859 unique emails (76,625 legitimate, 79,234 phishing).  
**Duplicates removed:** 9,112.

### 3.4 Data Split (No Test Leakage)

| Split | Rows | Purpose |
|-------|------|---------|
| Core training | 105,985 | Vocabulary, TF-IDF IDF, LR/NB training |
| Validation (15% of train pool) | 18,703 | **Threshold tuning only** |
| Holdout test (20% of all data) | 31,171 | **Final metrics only** — never used for training or threshold selection |

Procedure: `dedupeRows()` → seeded shuffle → 80/20 train/test split → 15% validation carved from training portion.

### 3.5 ML Pipeline

#### 3.5.1 Preprocessing (`tokenizeClean`)

1. Lowercase; strip URLs and email addresses.
2. Tokenise alphanumeric words; remove stop words and noise.
3. Append contextual **bigrams** (e.g. `account__statement`).
4. Preserve token **frequency** within each document (not deduplicated).

#### 3.5.2 Feature Selection (`selectDiscriminativeFeatures`)

Up to **8,000** terms selected by:

1. Chi-square statistic per class.
2. Balanced selection (~50% phishing-associated, ~50% legitimate-associated).
3. **Bigram guard:** ≥15 documents per class.
4. **Ambiguous filter:** exclude phishing-skewed terms with class balance ≥25%.
5. **Minority-ratio filter (v15):** phishing-skewed bigrams need ≥20% legit docs; unigrams need ≥6% — statistically reduces sparse-legit skew without keyword lists.

#### 3.5.3 TF-IDF (`buildTfIdfVector`)

- Sublinear TF: `1 + log(count)`
- IDF: `log((N+1)/(df+1)) + 1` from core training documents
- Length normalisation: divide by `sqrt(total_tokens)`

#### 3.5.4 Logistic Regression (`trainLogisticRegression`)

| Parameter | Value |
|-----------|-------|
| Epochs | 20 |
| Learning rate | 0.05 |
| L2 regularisation | 0.01 |
| Class weight | 1.0 (balanced) |
| Bias initialisation | Log-odds of class prior |
| Bias cap (v15) | ±0.75 (prevents intercept drift) |
| Weight cap | ±2.0 |

#### 3.5.5 Naive Bayes (`trainNaiveBayes`)

- Multinomial NB, α = 0.5
- Data-driven priors (~50.8% phishing, ~49.2% legitimate)
- Sublinear inference weighting: `1 + log(count)`

#### 3.5.6 Prediction and Verdict

1. Compute raw LR or NB phishing probability.
2. Compare to **validation-tuned threshold** (stored in model cache).
3. **Verdict = raw ML probability ≥ threshold** — no keyword override.
4. Heuristic layer (`calibrateProbability`, sentiment, URL checks) produces a **contextual score for explainability only** (±0.04 max adjustment, does not change verdict).

**Cached thresholds (v15):** LR = **0.46**, NB = **0.32**

#### 3.5.7 Model Caching

- File: `data/.model-cache.json`
- Version: **15**
- Fingerprint: cache version + CSV file sizes/mtimes + random seed
- Startup: load cache in ~2–5 s; full retrain ~8 min if cache invalid

### 3.6 Explainability

| Feature | Description |
|---------|-------------|
| Verdict badge | “Looks like a scam” / “Looks safe” (plain language) |
| Confidence | From raw ML probability |
| Why we flagged this | Summary from indicators |
| What to do | Prioritised recommendations |
| Pressure tactics | Urgency and fear scores |
| Words that stood out | Top TF-IDF terms |
| Flagged text view | Inline highlights (suspicious link, risky word, etc.) |

### 3.7 Security (Implementation)

| Control | Implementation |
|---------|----------------|
| JWT secret | Required in production (≥32 chars); ephemeral dev secret otherwise |
| Passwords | 8–128 characters; bcrypt 12 rounds |
| Rate limiting | Auth: 20 req/15 min/IP; Analyze: 30 req/min/IP |
| Input validation | Email format, text length (≤100,000 chars), model type whitelist |
| History authorisation | All queries scoped by `user_id`; JWT payload validated |
| Error messages | Generic client messages; details logged server-side only |
| Debug traces | Only when `DEBUG_ANALYSIS=true` |

### 3.8 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Backend and ML status |
| POST | `/api/analyze` | Optional | Scan email (guest or logged-in) |
| POST | `/api/auth/register` | No | Create account |
| POST | `/api/auth/login` | No | Obtain JWT |
| GET | `/api/history` | JWT | List user’s scans |
| DELETE | `/api/history/:id` | JWT | Delete one scan |
| DELETE | `/api/history` | JWT | Delete all scans |

---

## 4. Results and Evaluation

*All metrics below are from `training-log-v15.txt` — holdout test set, raw ML probabilities, validation-tuned thresholds. No manual adjustment.*

### 4.1 Training Configuration (v15)

| Setting | Value |
|---------|-------|
| Model cache version | 15 |
| Core training rows | 105,985 |
| Validation rows | 18,703 |
| Holdout test rows | 31,171 |
| Vocabulary size | 8,000 |
| LR intercept (bias) | 0.7301 |
| LR validation threshold | 0.46 |
| NB validation threshold | 0.32 |
| Training duration | 495.9 s (~8 min) |

### 4.2 Holdout Test Results — Logistic Regression

| Metric | Value |
|--------|-------|
| **Accuracy** | **97.46%** |
| **Precision** | **97.39%** |
| **Recall** | **97.63%** |
| **F1-score** | **97.51%** |
| **ROC-AUC** | 0.9954 |
| **False positives** | **416** |
| **False negatives** | **377** |

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------|-------------------|
| **Actual Legitimate** | TN = 14,878 | FP = 416 |
| **Actual Phishing** | FN = 377 | TP = 15,500 |

### 4.3 Holdout Test Results — Naive Bayes

| Metric | Value |
|--------|-------|
| **Accuracy** | **95.47%** |
| **Precision** | **97.27%** |
| **Recall** | **93.74%** |
| **F1-score** | **95.47%** |
| **ROC-AUC** | 0.9895 |
| **False positives** | **418** |
| **False negatives** | **994** |

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------|-------------------|
| **Actual Legitimate** | TN = 14,876 | FP = 418 |
| **Actual Phishing** | FN = 994 | TP = 14,883 |

### 4.4 Model Comparison Summary

| Criterion | Logistic Regression | Naive Bayes |
|-----------|---------------------|-------------|
| Holdout accuracy | **97.46%** | 95.47% |
| Recall (catch phishing) | **97.63%** | 93.74% |
| False negatives | **377** | 994 |
| False positives | 416 | 418 |
| Diverse validation (11 samples) | 7/11 (63.6%) | **9/11 (81.8%)** |
| Interpretability | Feature weights | Token likelihoods |

**Recommendation:** Use **Logistic Regression** as the default (“Standard check”) when minimising missed phishing is priority. Use **Naive Bayes** (“Second opinion”) as a complementary view—stronger on some edge cases (e.g. fake invoice in diverse set) but misses more phishing on holdout.

### 4.5 Diverse Domain Validation (11 handcrafted emails)

| Category | Expected | LR (raw prob) | LR correct? | NB (raw prob) | NB correct? |
|----------|----------|---------------|-------------|---------------|-------------|
| Banking statement | Legitimate | 97.2% | ✗ | 99.99% | ✗ |
| Shopping order | Legitimate | 2.5% | ✓ | 2.1% | ✓ |
| University registration | Legitimate | 1.9% | ✓ | 0% | ✓ |
| HR benefits | Legitimate | 83.3% | ✗ | 99.7% | ✗ |
| Shipping notification | Legitimate | 67.2% | ✗ | 29.5% | ✓ |
| Meeting invitation | Legitimate | 23.2% | ✓ | 0.1% | ✓ |
| Password change | Legitimate | 6.9% | ✓ | 13.2% | ✓ |
| Newsletter | Legitimate | 1.2% | ✓ | 28.1% | ✓ |
| Urgent credential phishing | Phishing | 97.7% | ✓ | 97.0% | ✓ |
| Fake invoice | Phishing | 41.3% | ✗ | 39.0% | ✓ |
| Credential theft URL | Phishing | 98.3% | ✓ | 69.8% | ✓ |

### 4.6 Pipeline Test Results (`evaluate-pipeline.mjs`)

| Sample | LR verdict | NB verdict |
|--------|------------|------------|
| Community newsletter (legitimate) | Legitimate (6%) | Borderline* |
| Meeting (legitimate) | Legitimate | Legitimate |
| Urgent phishing | Phishing | Phishing |

*NB newsletter sample in evaluate-pipeline scored 40% (just above NB threshold 0.32) — borderline case.

### 4.7 False Positive Themes (Holdout)

- System quarantine / antivirus update emails.
- Internal congratulations or HR messages.
- Automated notifications sharing financial vocabulary with phishing templates.

### 4.8 False Negative Themes (Holdout)

- Obfuscated or low-signal phishing.
- Subtle account-themed messages below threshold.
- Non-standard English (Nigerian-fraud style fragments).

---

## 5. Discussion and Limitations

### 5.1 Key Findings

1. **High holdout accuracy** (97%+ LR) demonstrates TF-IDF + classical ML remains effective on merged public corpora.
2. **Strong metrics do not guarantee all real-world genres** — banking statements still false-positive at ~97% LR probability.
3. **v15 feature-selection improvements** fixed newsletter false positives (from ~81% LR down to ~6% on pipeline test) without hard-coded keyword rules.
4. **Verdict integrity:** Raw ML drives classification; heuristics support transparency only.
5. **No test leakage:** Thresholds tuned on validation; holdout used once for reporting.

### 5.2 Limitations

| Limitation | Impact |
|------------|--------|
| Bag-of-words features | Cannot capture intent or sender context |
| Banking / HR false positives | Legitimate mail flagged; user must read explainability |
| NB lower recall | 994 FN vs 377 for LR on holdout |
| Dataset bias | Some CSVs contain no legitimate class |
| Text-only | Headers, attachments, URLs not fully forensically analysed |
| Rate limiting | Rapid automated testing may receive HTTP 429 |

### 5.3 Future Work

- Add more legitimate transactional emails to training data.
- Explore character n-grams or transformer models for comparison.
- Integrate header authentication signals (SPF/DKIM results).
- Conduct formal usability testing with non-technical users.

---

## 6. Conclusion

MailShield successfully implements a complete phishing detection pipeline—dataset merging, TF-IDF feature extraction, chi-square feature selection with contextual bigrams, Logistic Regression and Naive Bayes classifiers, validation-based threshold tuning, model caching, and a React web interface with explainability and JWT-secured scan history.

On 31,171 holdout emails, Logistic Regression achieves **97.46% accuracy** with **416 false positives** and **377 false negatives**; Naive Bayes achieves **95.47% accuracy** with **418 false positives** and **994 false negatives**. The project honestly documents remaining challenges, particularly legitimate banking notifications, illustrating the limits of vocabulary-based classification when phishing and legitimate messages share the same words.

The system is suitable as an educational reference implementation and a local tool for checking suspicious email text, with transparent explanations that help users make informed decisions even when the classifier errs.

---

## 7. References

Include in your final submission (format per your institution, e.g. Harvard/IEEE):

1. Anti-Phishing Working Group (APWG). *Phishing Activity Trends Report.* [Online]. Available: https://apwg.org/
2. F. Pedregosa et al., “Scikit-learn: Machine Learning in Python,” *Journal of Machine Research*, 2011. *(Conceptual reference for LR/NB; MailShield implements algorithms directly in JavaScript.)*
3. T. Joachims, “Text Categorization with Support Vector Machines: Learning with Many Relevant Features,” *ECML*, 1998. *(TF-IDF text classification context.)*
4. I. Fette, N. Sadeh, and A. Tomasic, “Learning to Detect Phishing Emails,” *WWW*, 2007.
5. Verizon. *Data Breach Investigations Report.* [Online]. Available: https://www.verizon.com/business/resources/reports/dbir/
6. Node.js Foundation. *Node.js Documentation.* https://nodejs.org/docs/
7. React Team. *React Documentation.* https://react.dev/
8. Express.js. *Express Web Framework.* https://expressjs.com/

*Add any course textbooks, lecture notes, or dataset source citations your module requires.*

---

## 8. Appendices

### Appendix A — How to Run the Project

**Prerequisites:** Node.js 18+, XAMPP (MySQL on port 3307), dataset CSVs in `data/`.

```bash
cd "Phishing Detection"
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Wait for backend log: “Loaded trained ML model from cache” or training completion.

**Production:**

```bash
set NODE_ENV=production
set JWT_SECRET=your-random-secret-at-least-32-characters-long
node server.js
```

### Appendix B — Verification Commands

```bash
node --check server.js
npm run lint
node scripts/evaluate-pipeline.mjs
node scripts/diverse-evaluation.mjs
```

Set `EVAL_PORT=5001` (or your backend port) if not using default.

### Appendix C — Files to Submit With This Document

| Item | Location |
|------|----------|
| Source code | Full project folder or GitHub link |
| This report | `docs/ASSIGNMENT_DOCUMENTATION.md` |
| Extended technical report | `docs/PROJECT_DOCUMENTATION.md` (optional, more detail) |
| Architecture diagrams | `docs/diagrams/*.png` |
| Training log (v15) | `training-log-v15.txt` |
| Screenshots | Scanner UI, phishing result, banking false positive, explainability panel |
| Database schema | `database.sql` |

### Appendix D — Screenshot Checklist for Assignment

Capture and label these in your submission:

1. **Features page** — plain-language feature cards.
2. **Scanner — legitimate meeting email** — verdict “Looks safe,” low confidence score.
3. **Scanner — obvious phishing** — verdict “Looks like a scam,” highlights visible.
4. **Scanner — banking email (failure case)** — show false positive with explainability so marker sees critical analysis.
5. **Model comparison** — same email scanned with Standard check vs Second opinion.
6. **Scan history** — logged-in user view (requires MySQL running).

### Appendix E — Glossary

| Term | Definition |
|------|------------|
| TF-IDF | Term Frequency–Inverse Document Frequency; numerical text representation |
| Logistic Regression | Linear classifier with sigmoid output giving class probability |
| Naive Bayes | Probabilistic classifier assuming conditional independence of features |
| Holdout set | 20% of data never used for training or threshold tuning |
| False positive | Legitimate email classified as phishing |
| False negative | Phishing email classified as legitimate |
| ROC-AUC | Area under ROC curve; measures ranking quality across thresholds |

---

*End of Assignment Documentation — MailShield v15*

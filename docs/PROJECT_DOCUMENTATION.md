# MailShield: AI-Powered Phishing Email Detection System

**Project Documentation**

---

## Chapter 1: Introduction

### 1.1 Background

Email remains one of the most widely used communication channels in personal, academic, and business environments. Its popularity also makes it a primary vector for cybercrime, particularly phishing attacks. Phishing is a form of social engineering in which an attacker impersonates a trustworthy entity—such as a bank, employer, government agency, or well-known online service—to deceive recipients into revealing sensitive information, clicking malicious links, or downloading harmful attachments. The consequences of successful phishing range from financial loss and identity theft to corporate data breaches and reputational damage.

Traditional email security relies on infrastructure-level controls such as spam filters, blacklists, SPF/DKIM/DMARC authentication, and gateway appliances. While these mechanisms are essential, they are not sufficient on their own. Many phishing emails pass technical checks yet remain dangerous because their *content* mimics legitimate communication. Users therefore need accessible tools that analyse the textual content of suspicious messages and provide understandable guidance on whether an email is likely to be phishing or legitimate.

Machine learning (ML) has become a standard approach to content-based email classification. Algorithms such as Naive Bayes and Logistic Regression, combined with text representations like TF-IDF (Term Frequency–Inverse Document Frequency), offer a balance between predictive performance, computational efficiency, and interpretability. Unlike deep learning models that require substantial hardware and large labelled corpora, classical ML models can be trained and deployed on modest hardware, making them suitable for educational projects and small-scale deployments.

### 1.2 Problem Statement

Despite the availability of commercial anti-phishing products, several gaps remain for end users and developers learning about applied machine learning in cybersecurity:

1. **Accessibility:** Many users cannot easily test a suspicious email outside of a corporate mail gateway.
2. **Transparency:** Black-box classifiers provide scores without explaining *why* an email was flagged.
3. **Domain generalisation:** Models trained on narrow datasets may misclassify legitimate emails from domains such as banking, e-commerce, or human resources because of overlapping vocabulary.
4. **Integration:** Academic prototypes often exist as command-line scripts rather than complete, usable applications.

This project addresses these gaps by developing **MailShield**, a web-based phishing email detection system that allows users to paste or upload email text, select a machine learning model, and receive a verdict accompanied by explainability features and safety recommendations.

### 1.3 Project Aim and Objectives

**Aim:** To design, implement, and evaluate a full-stack web application that classifies email text as phishing or legitimate using dual machine learning models, supported by explainability and user account management.

**Objectives:**

1. To collect and merge multiple publicly available email datasets into a unified training corpus with consistent label normalisation.
2. To implement a complete machine learning pipeline—including preprocessing, feature selection, TF-IDF vectorisation, Logistic Regression training, and Multinomial Naive Bayes training—entirely within a Node.js backend.
3. To achieve high classification performance on a held-out test set, measured by accuracy, precision, recall, F1-score, and ROC-AUC.
4. To provide users with interpretable outputs: confidence scores, TF-IDF signal terms, sentiment analysis, inline phrase highlighting, and actionable recommendations.
5. To implement guest scanning (limited free use) and registered user accounts with secure authentication and scan history stored in MySQL.
6. To critically evaluate system limitations, including false positives on legitimate notification emails.

### 1.4 Scope and Limitations of Scope

**In scope:**

- Text-based analysis of email body content (paste, clipboard, file upload).
- Dual-model classification: Logistic Regression and Naive Bayes.
- Training on merged CSV datasets placed in the project `data/` directory.
- Web interface built with React and a REST API built with Express.
- User registration, login (JWT + bcrypt), and scan history for authenticated users.

**Out of scope:**

- Integration with live email clients (Gmail, Outlook) or IMAP/POP3 polling.
- Analysis of attachments, embedded images, or full MIME header forensics.
- Deep learning models (e.g. BERT, LSTM) and GPU-based training.
- Production-grade deployment (HTTPS, load balancing, horizontal scaling).
- Real-time URL crawling or domain reputation services beyond basic suspicious URL heuristics.

### 1.5 Target Users

- **Guest users:** Individuals who want to try the scanner without creating an account (limited to five scans per browser session).
- **Registered users:** Users who require unlimited scans and persistent scan history.
- **Developers and students:** Users studying applied ML, NLP, and full-stack web development who wish to inspect a working reference implementation.

### 1.6 Technology Overview

MailShield is implemented as a three-tier application:

| Tier | Technology |
|------|------------|
| Presentation | React 19, Vite 8, CSS |
| Application / API | Node.js, Express 5 |
| Data | MySQL (via XAMPP), CSV training files, JSON model cache |

The machine learning components are implemented in pure JavaScript without external ML libraries such as scikit-learn or TensorFlow, demonstrating that classical models can be built from first principles when library dependencies are minimised.

### 1.7 Document Structure

Chapter 2 reviews relevant literature on phishing and machine learning approaches. Chapter 3 describes the design and implementation of the system. Chapter 4 presents quantitative and qualitative results. Chapter 5 discusses findings and limitations. Chapter 6 concludes the project. Chapter 7 provides critical self-evaluation and recommendations for future work.

### 1.8 Motivation for Project Topic Selection

Phishing attacks continue to increase in volume and sophistication according to industry reports from APWG (Anti-Phishing Working Group) and Verizon Data Breach Investigations Report. Unlike malware reverse-engineering or network intrusion detection, email content classification is accessible to students with foundational programming and statistics knowledge while remaining directly relevant to everyday cybersecurity. MailShield was therefore chosen as a project that balances technical depth, practical utility, and demonstrable evaluation outcomes.

### 1.9 Expected Contributions

The expected contributions of this work are: (1) a reproducible multi-dataset training pipeline in JavaScript; (2) empirical comparison of Logistic Regression and Naive Bayes on merged public corpora; (3) an open web interface with explainability features; and (4) documented analysis of false positives on legitimate transactional email—a case study in the limits of bag-of-words classification.

---

## Chapter 2: Literature Review

### 2.1 Phishing and Email-Based Threats

Phishing attacks exploit human trust rather than purely technical vulnerabilities. Attackers craft messages that appear to originate from legitimate organisations, often using urgency (“Your account will be suspended within 24 hours”), fear (“Unauthorised login detected”), or reward (“You have won a prize”) to pressure recipients into acting quickly. Spear-phishing targets specific individuals with personalised content, while bulk phishing campaigns send identical templates to large recipient lists.

Email phishing commonly aims to harvest credentials (fake login pages), distribute malware (malicious attachments or links), or initiate fraud (fake invoices, CEO fraud). Because legitimate organisations also send transactional emails containing words such as “account,” “payment,” “verify,” and “support,” content-based classifiers face a fundamental challenge: distinguishing malicious intent from benign notification language.

### 2.2 Traditional Detection Approaches

**Rule-based and keyword systems** apply hand-crafted rules or keyword lists to flag suspicious messages. These systems are fast and interpretable but brittle: attackers adapt wording to evade filters, and legitimate emails containing common financial vocabulary produce false positives.

**Blacklist and reputation systems** maintain lists of known malicious domains, IP addresses, and sender reputations. They are effective against known threats but cannot reliably detect novel phishing campaigns or compromised legitimate accounts.

**Email authentication protocols** (SPF, DKIM, DMARC) verify that messages originate from authorised mail servers. They reduce spoofing but do not analyse message content and therefore cannot detect phishing sent from compromised legitimate accounts.

### 2.3 Machine Learning for Email Classification

Machine learning treats email classification as a supervised learning problem: given labelled examples of phishing and legitimate emails, a model learns patterns that generalise to unseen messages.

#### 2.3.1 Naive Bayes

Naive Bayes is a probabilistic classifier based on Bayes’ theorem with a “naive” independence assumption between features. For text classification, each word (or token) contributes to the posterior probability of each class. Multinomial Naive Bayes models word counts and is widely used in spam filtering (e.g. early SpamAssassin components). Its strengths include fast training, fast inference, and resilience with small datasets. Its weaknesses include the independence assumption (words co-occur in meaningful phrases) and sensitivity to vocabulary size and class priors.

Mathematically, for class \(c\) and document \(d\) with tokens \(w_1 \ldots w_n\):

\[
P(c|d) \propto P(c) \prod_i P(w_i|c)^{count(w_i,d)}
\]

Laplace (add-one or add-α) smoothing prevents zero probabilities for unseen words. MailShield uses α = 0.5 and computes priors from empirical training frequencies rather than arbitrary constants—a correction that proved important when balanced training data made fixed 0.54/0.46 priors inappropriate.

#### 2.3.2 Logistic Regression

Logistic Regression models the log-odds of class membership as a linear combination of input features. When features are TF-IDF weights, each vocabulary term receives a coefficient indicating its contribution to the phishing class. LR is widely used in text classification because it is interpretable, efficient, and often competitive with more complex models on high-dimensional sparse text data. Training typically uses gradient descent with L2 regularisation to prevent overfitting.

The sigmoid function \(\sigma(z) = 1/(1+e^{-z})\) maps linear score \(z = b + \mathbf{w}^T\mathbf{x}\) to probability. MailShield trains \(\mathbf{w}\) and bias \(b\) via stochastic gradient descent over 20 epochs, initialising \(b\) to the log-odds of the observed phishing rate so the model starts from a realistic baseline before learning feature weights.

#### 2.3.3 TF-IDF Feature Representation

TF-IDF converts document text into a numerical vector. Term frequency (TF) captures how often a word appears in a document; inverse document frequency (IDF) down-weights words that appear in many documents across the corpus. The product TF × IDF emphasises words that are frequent in a specific email but rare overall—often discriminative for classification. Sublinear TF scaling (e.g. 1 + log count) reduces the impact of repeated words.

#### 2.3.4 Alternative Approaches

Support Vector Machines (SVM), Random Forests, and ensemble methods have been applied to phishing detection with strong results. Deep learning models (CNN, LSTM, Transformer/BERT) capture semantic context and long-range dependencies but require large datasets, longer training times, and specialised hardware. For educational and self-hosted deployments, classical ML remains a practical choice.

### 2.4 Evaluation Metrics

Classification performance is assessed using:

- **Accuracy:** Proportion of correct predictions. Misleading when classes are imbalanced or when false positive and false negative costs differ.
- **Precision:** Of emails predicted phishing, the proportion truly phishing. High precision reduces user alarm fatigue.
- **Recall (Sensitivity):** Of truly phishing emails, the proportion detected. High recall reduces missed attacks.
- **F1-score:** Harmonic mean of precision and recall; balances both concerns.
- **ROC-AUC:** Area under the receiver operating characteristic curve; measures ranking quality across thresholds.
- **Confusion matrix:** Tabulates true positives (TP), true negatives (TN), false positives (FP), and false negatives (FN).

For security applications, false negatives (missed phishing) and false positives (legitimate mail flagged) both carry cost; the appropriate metric emphasis depends on deployment context. In enterprise settings, missed phishing may cost millions; for individual users, excessive false positives may cause them to abandon the tool entirely. MailShield therefore reports multiple metrics and allows threshold calibration on a validation subset rather than optimising for accuracy alone.

Cross-validation (k-fold) provides more stable estimates of generalisation than a single train/test split by averaging performance across multiple partitions. This project uses a single 80/20 holdout split for computational practicality on 155,000 emails; future work should report k-fold mean and standard deviation.

### 2.5 Explainable AI in Security

Users are more likely to trust and act appropriately on classifier output when explanations accompany predictions. Explainability in text classification includes: highlighting suspicious keywords and phrases, showing top weighted features (LR coefficients or NB log-odds), detecting urgency/fear language, and providing actionable recommendations (e.g. “Do not click links; verify via official website”). MailShield incorporates these principles alongside raw probability scores.

Research on human-centred security (e.g. Sasse et al. on security usability) emphasises that warnings must be understandable and actionable. A 95% phishing score without context may be ignored; the same score accompanied by “Suspicious URL detected” and “Credential request phrase found” prompts appropriate caution. MailShield’s explainability module (`buildExplainabilitySummary`, `buildRecommendations`, `buildPhishingIndicators`) implements this philosophy in the application layer, separate from the core ML classifier.

### 2.6 Research Gap Addressed by This Project

Existing academic work often focuses on model accuracy in isolation. MailShield contributes an integrated, user-facing system that combines dual classical ML models, multi-dataset training, statistical feature selection with contextual bigrams, explainability, and a complete authentication and history layer—implemented as a deployable web application rather than an offline experiment alone.

---

## Chapter 3: Implementation and Development

### 3.1 Requirements Analysis

#### 3.1.1 Functional Requirements

| ID | Requirement |
|----|-------------|
| FR1 | Users shall paste or upload email text for analysis |
| FR2 | Users shall select Logistic Regression or Naive Bayes before scanning |
| FR3 | The system shall return a verdict (Phishing / Legitimate) and confidence score |
| FR4 | The system shall provide explainability summary, recommendations, and highlighted phrases |
| FR5 | Guest users shall receive five free scans per browser session |
| FR6 | Users shall register and log in with email and password |
| FR7 | Registered users shall view and delete scan history |
| FR8 | The system shall train ML models from CSV datasets in `data/` |
| FR9 | Trained models shall be cached to avoid retraining on every startup |

#### 3.1.2 Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR1 | The system shall run locally on Windows with Node.js and XAMPP |
| NFR2 | Scan response time shall be under a few seconds after model load |
| NFR3 | Passwords shall be stored using bcrypt hashing |
| NFR4 | Authenticated API requests shall use JWT tokens |
| NFR5 | Guest scans shall work when MySQL is unavailable |

### 3.2 System Architecture

MailShield follows a three-tier architecture:

1. **Presentation tier:** React single-page application served by Vite during development. Users interact with the scanner, authentication modal, and results panels.
2. **Application tier:** Express REST API on port 5001. Handles authentication, analysis requests, and history CRUD operations. Contains the entire ML pipeline.
3. **Data tier:** MySQL database (`phishing_detector`) for users and detection history; CSV files for training data; JSON file (`.model-cache.json`) for persisted trained models.

During development, Vite proxies `/api/*` requests from port 5173 to the backend on port 5001. A `wait-for-backend` script ensures the frontend starts only after the API is reachable.

Refer to `docs/diagrams/` for use case diagrams, detailed use case diagrams, flowcharts, and system architecture diagrams.

### 3.3 Database Design

The schema is defined in `database.sql`:

**Table: users**

| Column | Type | Description |
|--------|------|-------------|
| id | INT PK | Auto-increment user ID |
| name | VARCHAR(100) | Display name |
| email | VARCHAR(150) UNIQUE | Login email |
| password_hash | VARCHAR(255) | bcrypt hash |
| created_at | TIMESTAMP | Registration time |

**Table: detection_history**

| Column | Type | Description |
|--------|------|-------------|
| id | INT PK | Scan record ID |
| user_id | INT FK | Reference to users |
| email_content | TEXT | Truncated email text (500 chars) |
| model_used | ENUM | logistic_regression or naive_bayes |
| logistic_regression_score | INT | Score if LR used |
| naive_bayes_score | INT | Score if NB used |
| result | VARCHAR(30) | Phishing or Legitimate |
| tfidf_terms | JSON | Top TF-IDF terms |
| scanned_at | TIMESTAMP | Scan timestamp |

### 3.4 Dataset Pipeline

#### 3.4.1 Data Sources

Seven CSV files are loaded from `data/`:

| Dataset | Approx. Rows | Notes |
|---------|-------------|-------|
| CEAS_08 | 39,154 | Mixed phishing and legitimate |
| Enron | 29,767 | Corporate email corpus |
| Ling | 2,859 | Smaller balanced set |
| Nazario | 1,565 | Phishing only |
| Nigerian_Fraud | 3,332 | Advance-fee fraud |
| SpamAssassin | 5,809 | Spam/ham corpus |
| phishing_email | 82,485 | Large mixed corpus |

#### 3.4.2 Loading and Merging

The function `loadAllDatasets()` performs:

1. **File discovery:** All `*.csv` files in `data/` are read.
2. **Column auto-detection:** Text columns (`text`, `email`, `body`, `message`, etc.) and label columns (`label`, `class`, `target`, etc.) are detected automatically.
3. **Label normalisation:** Numeric and string labels map to `phishing` or `legitimate` (e.g. `1` → phishing, `0` → legitimate, `spam` → phishing).
4. **Merging:** All rows are combined into a single array.
5. **Deduplication:** Rows with identical normalised text (first 400 characters) are removed.
6. **Validation:** Empty text and invalid labels are discarded.

**Final merged statistics:**

- Total unique emails: **155,859**
- Phishing: **79,234** (~50.9%)
- Legitimate: **76,625** (~49.1%)
- Duplicates removed: **9,112**

#### 3.4.3 Train/Test Split

- **80/20 split** with seeded shuffle: 124,688 training rows, 31,171 holdout test rows.
- From training data, **15% validation** (18,703 rows) is used for decision threshold calibration; core training uses 105,985 rows.

### 3.5 Text Preprocessing

The function `tokenizeClean()` performs:

1. **Cleaning (`cleanEmailText`):** Lowercase conversion; removal of URLs and email addresses; stripping of punctuation; whitespace normalisation.
2. **Tokenisation:** Extraction of alphanumeric tokens via regex.
3. **Stop word removal:** Common English stop words (e.g. “the,” “and,” “is”) are excluded.
4. **Noise filtering:** Overly long tokens, pure numbers, and long hex strings are removed.
5. **Bigram generation:** Adjacent word pairs are appended as compound tokens (e.g. `account__statement`) to capture contextual phrases without hard-coded rules.

Token frequency is preserved (not deduplicated) so TF-IDF and Naive Bayes reflect repeated terms within a document.

### 3.6 Feature Selection

`selectDiscriminativeFeatures()` builds a vocabulary of up to **8,000** terms using:

1. **Document-frequency counting** per class (phishing vs legitimate).
2. **Chi-square statistic** measuring deviation from expected class distribution.
3. **Balanced selection:** Approximately half the vocabulary from phishing-associated terms, half from legitimate-associated terms.
4. **Bigram guard:** Bigrams must appear in at least 15 documents in *each* class to avoid sparse, skewed phrase features.
5. **Ambiguous unigram filter:** Phishing-skewed unigrams with class balance ≥ 25% are excluded to reduce false positives on common words like “account.”

This replaces an earlier approach that forced hard-coded phishing keywords into the vocabulary, which caused legitimate banking emails to score as phishing.

### 3.7 TF-IDF Vectorisation

`buildTfIdfVector()` computes:

- **Sublinear TF:** `1 + log(token_count)`
- **Normalised TF:** Divided by `1 + log(max_count_in_document)`
- **IDF:** `log((N + 1) / (df + 1)) + 1` where N is training document count and df is document frequency
- **Length normalisation:** Divided by `sqrt(total_tokens)` to reduce bias toward longer emails

### 3.8 Logistic Regression Training

Implemented via stochastic gradient descent in `trainLogisticRegression()`:

| Parameter | Value |
|-----------|-------|
| Epochs | 20 (configurable via `LR_EPOCHS`) |
| Learning rate | 0.05 |
| L2 regularisation | 0.01 |
| Class weight | 1.0 (balanced data; no overweighting) |
| Bias initialisation | Log-odds of training class prior (~0.034) |
| Max weight magnitude | ±2.0 |

Each epoch shuffles training documents. For each document, the model computes a linear score, applies the sigmoid function, calculates error, and updates weights and bias. L2 penalty shrinks large coefficients. The intercept is not clipped, preventing the runaway positive bias (+1.691) observed in earlier versions.

### 3.9 Naive Bayes Training

`trainNaiveBayes()` implements **Multinomial Naive Bayes**:

- **Class token counts** accumulated per vocabulary term.
- **Laplace smoothing:** α = 0.5
- **Priors:** Computed from training data (phishing ≈ 0.508, legitimate ≈ 0.492), not fixed artificial values.
- **Inference:** Sublinear term weighting `1 + log(count)` at prediction time to reduce impact of repeated words.

### 3.10 Model Caching

Trained models are serialised to `data/.model-cache.json` with a fingerprint derived from CSV file sizes, modification times, cache version (13), and random seed. On startup, if the fingerprint matches, the cached model loads in seconds; otherwise full retraining occurs (~12 minutes).

### 3.11 Prediction Pipeline

When a user submits an email via `POST /api/analyze`:

1. **Tokenise and vectorise** the input text.
2. **Predict** with both LR and NB; the user-selected model determines the displayed result.
3. **Apply low-coverage boost** if vocabulary coverage is low but keyword hits exist.
4. **Calibrate probability** using sentiment scores (urgency, fear), suspicious URL count, and neutral-email discount.
5. **Map to verdict** using a validation-tuned threshold (LR ≈ 0.43, NB ≈ 0.32).
6. **Build explainability:** indicators, summary, recommendations, TF-IDF contributors, inline highlights.
7. **Save history** if user is authenticated and MySQL is available (scan still returns if DB is down).

### 3.12 Frontend Implementation

The React application (`src/App.jsx`) provides:

- Email workspace with edit/flagged-text toggle after scanning.
- Model selector (Logistic Regression / Naive Bayes).
- Paste, clipboard, and file upload input.
- Results panel: verdict badge, confidence, explainability summary, recommendations, sentiment scores, TF-IDF signals.
- Authentication modal (register/login).
- Scan history panel with delete actions for logged-in users.
- Guest scan counter stored in `sessionStorage` (limit: 5).

Styling is defined in `src/App.css` with a flexible scanner layout: email and highlights on the left, sticky results on the right.

### 3.13 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/health | No | Server and ML status |
| POST | /api/auth/register | No | Create account |
| POST | /api/auth/login | No | Obtain JWT |
| POST | /api/analyze | Optional | Scan email |
| GET | /api/history | JWT | List scans |
| DELETE | /api/history/:id | JWT | Delete one scan |
| DELETE | /api/history | JWT | Delete all scans |

### 3.14 Security Implementation

- **Password hashing:** bcrypt with cost factor 10.
- **Authentication:** JWT signed with server secret; sent in `Authorization: Bearer` header.
- **CORS:** Restricted to localhost Vite ports.
- **Input limits:** JSON body limit 1 MB; email content truncated to 500 characters for history storage.

### 3.16 Sentiment and Heuristic Analysis Layer

Beyond ML probabilities, MailShield implements a rule-based sentiment and indicator layer that supports explainability without directly overriding the ML verdict (except through small calibration adjustments). This layer detects:

**Urgency phrases:** e.g. “immediate action required,” “act now,” “within 24 hours,” “expires today.” Each match increments an urgency score displayed to the user.

**Fear phrases:** e.g. “account suspended,” “unauthorised access,” “payment failed,” “legal action.” These increment a fear score reflecting psychological pressure tactics common in phishing.

**Credential request phrases:** e.g. “verify your password,” “confirm your login,” “enter your password.” Detection of these patterns triggers high-priority recommendations.

**Financial request phrases:** e.g. “wire transfer,” “invoice attached,” “pay now.” These indicate potential financial fraud beyond generic spam.

**Suspicious URL heuristics:** URLs are extracted via regex. A URL is flagged if the domain is an IP address, contains suspicious keywords (login, verify, secure, bank), or has an unusually deep subdomain structure. This complements TF-IDF by capturing structural link deception not always visible in tokenised text alone.

**Phishing keyword hits:** A predefined set of high-risk single words (verify, password, account, urgent, etc.) contributes to indicator counts and optional probability calibration. Importantly, these keywords are **not** forced into the ML vocabulary during training in the final pipeline—they serve the explainability and calibration layers only.

The function `buildPhishingIndicators()` aggregates all detections into structured objects with severity levels (none, low, medium, high) and evidence snippets. `buildRecommendations()` maps detected indicator types to user guidance such as avoiding links, not entering passwords, and verifying through official channels.

### 3.17 Decision Threshold Calibration

Raw ML probabilities are compared against class-specific thresholds to produce binary predictions. Rather than using a fixed 0.5 threshold, MailShield calibrates thresholds on the validation subset (18,703 emails) by searching values between 0.32 and 0.52 that maximise F1-score subject to minimum recall constraints. Final thresholds in the cached model are approximately **0.43 for Logistic Regression** and **0.32 for Naive Bayes**. This calibration adapts to each model’s probability distribution: NB typically produces more extreme probabilities and benefits from a lower threshold.

Post-threshold calibration (`calibrateProbability`) applies small adjustments (±0.08 maximum) based on suspicious URL count, urgency/fear scores, and keyword co-occurrence. A neutral-email discount reduces phishing probability slightly when urgency, fear, URL, and keyword signals are all absent and the ML score is below 0.55—provided sufficient legitimate vocabulary signals are present. These adjustments are intentionally conservative so the ML model remains the primary decision driver.

### 3.18 Software Testing and Debugging Methodology

During development, several diagnostic approaches were employed:

1. **Dataset audit scripts** (`scripts/dataset-audit.mjs`, `scripts/inspect-csvs.mjs`) verified CSV loading, label mapping, and duplicate removal across all seven files.
2. **Pipeline trace scripts** logged raw LR/NB probabilities, linear scores, bias contributions, and post-processing steps for individual test emails—essential for diagnosing banking false positives.
3. **Holdout evaluation** with confusion matrices and ROC-AUC provided aggregate quality gates after each pipeline change.
4. **Diverse validation set** of eleven handcrafted emails tested generalisation across domains not represented proportionally in training data.
5. **API integration tests** via curl and `scripts/evaluate-pipeline.mjs` confirmed frontend-backend connectivity.

This iterative audit cycle moved the LR intercept from +1.691 (84% phishing baseline without reading any words) to +0.467 (~61% baseline aligned with class prior), dramatically reducing false positives on neutral and legitimate content while preserving high recall on the holdout set.

### 3.19 User Interface Design Decisions

The scanner layout uses a two-column responsive design: email input and flagged-text view on the left, results on the right. After scanning, the view automatically switches to “Flagged text” mode so users immediately see highlighted suspicious phrases inline within the email body—a design choice prioritising actionable visual feedback over separate static panels.

The results panel presents information in order of user priority: verdict and confidence first, then explainability summary, then recommendations, then technical detail (sentiment, TF-IDF signals). Phishing indicator and top-word panels were removed from the UI in favour of cleaner presentation while retaining the underlying API data for potential future use.

Guest users see a remaining-scan counter; upon exhaustion, the registration modal opens automatically. Registration does not auto-login—the user must explicitly log in after account creation, reducing accidental session creation and reinforcing credential awareness.

---

## Chapter 4: System Implementation and Results

### 4.1 Deployment Instructions

1. Install dependencies: `npm install`
2. Import `database.sql` into MySQL via XAMPP (port 3307 by default).
3. Place CSV datasets in `data/`.
4. Run `npm run dev`.
5. Open the URL shown in the terminal (typically `http://127.0.0.1:5173`).
6. On first run, wait for “ML model loaded from cache” or training completion.

### 4.2 Training Run Configuration

The following results are taken from the final training run logged in `training-log-v13.txt`:

| Setting | Value |
|---------|-------|
| Core training rows | 105,985 |
| Validation rows | 18,703 |
| Holdout test rows | 31,171 |
| Vocabulary size | 8,000 |
| LR intercept after training | +0.4669 |
| Empirical phishing prior | 0.5085 |
| NB data-driven priors | 0.508 / 0.492 |
| PHISHING_CLASS_WEIGHT | 1.0 |
| Training duration | 716 seconds (~12 min) |
| Model cache version | 13 |

### 4.3 Holdout Test Set Results

Evaluation uses **raw ML probabilities** and validation-tuned thresholds on 31,171 unseen emails.

#### 4.3.1 Logistic Regression

| Metric | Value |
|--------|-------|
| Accuracy | 98.22% |
| Precision | 98.00% |
| Recall | 98.51% |
| F1-score | 98.25% |
| ROC-AUC | 0.9979 |

**Confusion Matrix:**

|  | Predicted Legitimate | Predicted Phishing |
|--|-------------------|-------------------|
| **Actual Legitimate** | TN = 14,974 | FP = 320 |
| **Actual Phishing** | FN = 236 | TP = 15,641 |

LR achieves near-perfect ranking (ROC-AUC 0.998) with balanced precision and recall, indicating strong overall separation between classes on the holdout set.

#### 4.3.2 Naive Bayes

| Metric | Value |
|--------|-------|
| Accuracy | 96.17% |
| Precision | 98.06% |
| Recall | 94.36% |
| F1-score | 96.17% |
| ROC-AUC | 0.9924 |

**Confusion Matrix:**

|  | Predicted Legitimate | Predicted Phishing |
|--|-------------------|-------------------|
| **Actual Legitimate** | TN = 14,997 | FP = 297 |
| **Actual Phishing** | FN = 896 | TP = 14,981 |

NB exhibits higher precision but lower recall than LR: it misses more phishing emails (896 FN vs 236) while flagging slightly fewer legitimate emails incorrectly (297 FP vs 320).

### 4.4 Diverse Domain Validation

Beyond aggregate metrics, eleven handcrafted emails representing multiple domains were evaluated:

| Category | Expected | LR Result | NB Result |
|----------|----------|-----------|-----------|
| Banking statement | Legitimate | ✗ (93.3% phish) | ✗ (100%) |
| Shopping order | Legitimate | ✓ (8.4%) | ✓ (0.2%) |
| University registration | Legitimate | ✓ (4.9%) | ✓ (0%) |
| HR benefits | Legitimate | ✓ (40.4%) | ✗ (40.1%) |
| Shipping notification | Legitimate | ✗ (76.5%) | ✓ (16.3%) |
| Meeting invitation | Legitimate | ✓ (9.5%) | ✓ (0%) |
| Password change confirm | Legitimate | ✗ (53.6%) | ✓ (28.5%) |
| Newsletter | Legitimate | ✓ (14.2%) | ✓ (13.7%) |
| Urgent credential phishing | Phishing | ✓ (99.96%) | ✓ (99.8%) |
| Fake invoice | Phishing | ✓ (51.5%) | ✗ (10.3%) |
| Credential theft URL | Phishing | ✓ (87.6%) | ✓ (57.6%) |

**Overall diverse accuracy:** 8/11 (72.73%) for both models.

These results show that strong holdout metrics do not guarantee performance on all real-world email types. Legitimate banking notifications and some shipping/password emails remain challenging.

### 4.5 False Positive Analysis

Representative false positives on the holdout set include:

- System quarantine summary emails containing spam-adjacent vocabulary.
- Internal congratulation/promotion messages.
- Automated antivirus database update notifications.
- VPN access approval messages mentioning “account.”

Common theme: legitimate automated emails share vocabulary with phishing templates.

### 4.6 False Negative Analysis

Representative false negatives include:

- Obfuscated or low-signal phishing with unusual tokenisation.
- Subtle account-themed messages (e.g. payment platform notifications) scoring below threshold.
- Nigerian-fraud-style fragments with non-standard English.

Common theme: phishing that avoids high-IDF discriminative terms learned during training.

### 4.7 Qualitative User Interface Results

The web interface successfully presents:

- **Verdict badge** with confidence percentage.
- **Explainability summary** in plain language referencing detected indicators.
- **Recommendations** prioritised as high/medium/low (e.g. “Do not click suspicious links”).
- **Sentiment panel** showing urgency and fear scores.
- **TF-IDF signals** listing top weighted terms.
- **Inline highlights** toggling between edit view and flagged-text view with colour-coded categories (keyword, urgency, fear, domain, model signal).

**Example 1 — Obvious phishing:** An email containing “URGENT: Your account blocked. Verify your password at http://secure-login-verify.xyz/update within 24 hours” receives LR probability above 99%, verdict Phishing, indicators for urgency language, credential requests, and suspicious URLs, with recommendations to avoid links and not enter credentials.

**Example 2 — Legitimate meeting:** “Hi team, project sync tomorrow at 10 AM. Please review the agenda.” receives LR probability below 10%, verdict Legitimate, no high-severity indicators, low urgency and fear scores.

**Example 3 — Legitimate banking (failure case):** A monthly account statement notification containing “online banking,” “account,” and “customer support” receives LR probability approximately 93% and verdict Phishing—a documented false positive driven by financial vocabulary over-represented in phishing training templates. Explainability still lists model signal terms, allowing an informed user to question the verdict—a secondary benefit of transparency even when the classifier errs.

Screenshots of these three cases should be included in the final submitted document with captions referencing model type and probability values.

### 4.8 Comparison with Initial Pipeline Version

Early versions of MailShield exhibited severe false positives on legitimate banking emails (LR and NB both above 90% phishing probability) due to training design choices rather than post-processing bugs. Table 4.1 summarises the evolution:

| Issue (Early Pipeline) | Correction (Final Pipeline) | Effect |
|------------------------|----------------------------|--------|
| PHISHING_KEYWORDS forced into vocabulary | Chi-square selection only | Removed hard-coded feature bias |
| PHISHING_CLASS_WEIGHT = 1.12 | Weight = 1.0 | Stopped intercept drift |
| LR bias init = 0 | Init = log-odds prior | Realistic baseline (~61% vs 84%) |
| NB priors fixed at 0.54/0.46 | Data-driven priors | Matched ~50/50 training balance |
| Unigrams only | Bigrams + ambiguous filter | Contextual and balanced features |
| Token deduplication in tokenizeClean | Frequency preserved | Correct TF-IDF/NB counts |

This evolution demonstrates that high holdout accuracy alone does not indicate a well-designed system; domain-specific validation and pipeline auditing are essential quality steps.

### 4.9 Statistical Significance of Results

On 31,171 test emails, LR misclassified 556 emails total (320 FP + 236 FN), yielding 98.22% accuracy. The 95% Wilson score interval for accuracy is approximately [98.07%, 98.36%], indicating tight confidence given test set size. NB misclassified 1,193 emails (297 FP + 896 FN), with accuracy interval approximately [96.04%, 96.30%]. The difference in FN rate (896 vs 236) is practically significant for security: NB misses roughly 3.8× more phishing emails on this test split.

ROC-AUC above 0.99 for LR indicates excellent ranking ability: a randomly chosen phishing email receives a higher score than a randomly chosen legitimate email more than 99% of the time. This holds even where absolute probability calibration imperfectly reflects true likelihood on out-of-domain emails (e.g. banking notifications).

### 4.10 Runtime Performance

After model cache load (approximately 2–5 seconds on startup), single-email inference completes in under 100 milliseconds on typical hardware: tokenisation, TF-IDF vectorisation, LR dot product, NB log-sum-exp, and explainability generation. Full retraining without cache requires approximately 716 seconds (12 minutes) for 105,985 training documents × 20 LR epochs plus NB counting and validation threshold search. Caching makes restart practical for daily development; retraining occurs only when CSV files change or cache version increments.

---

## Chapter 5: Overall Results and Discussion

### 5.1 Summary of Findings

MailShield successfully implements a complete phishing detection pipeline within a Node.js web application. On a large holdout test set of 31,171 emails, Logistic Regression achieves **98.22% accuracy** and Naive Bayes **96.17% accuracy**, with ROC-AUC values above **0.99** and **0.992** respectively. These figures demonstrate that classical ML with TF-IDF features remains highly effective on merged public email corpora.

The system additionally provides explainability features rarely present in academic baseline implementations, improving practical utility for non-expert users.

### 5.2 Logistic Regression vs Naive Bayes

| Criterion | Logistic Regression | Naive Bayes |
|-----------|---------------------|-------------|
| Holdout accuracy | **98.22%** | 96.17% |
| Recall (phishing) | **98.51%** | 94.36% |
| Precision | 98.00% | **98.06%** |
| Interpretability | Feature weights | Word probabilities |
| Training complexity | Iterative (SGD) | Closed-form counts |
| Diverse domain test | 8/11 | 8/11 (different errors) |

**Discussion:** LR is preferable when maximising phishing detection rate (recall) on aggregate test data. NB is competitive on precision and runs faster at inference for equivalent vocabulary size. Offering both models empowers users to compare approaches—a pedagogical and practical design choice.

### 5.3 Impact of Pipeline Improvements

Several iterations of development addressed a critical early finding: legitimate banking emails scored above 90% phishing due to:

1. Hard-coded phishing keywords forced into the vocabulary.
2. Overweighted phishing class during LR training (`PHISHING_CLASS_WEIGHT = 1.12`).
3. Runaway positive LR intercept (+1.691).
4. Fixed NB priors favouring phishing (0.54/0.46).

Replacing these with statistical feature selection, balanced class weight, prior-based bias initialisation, data-driven NB priors, bigram features, and ambiguous-word filtering reduced baseline bias and improved legitimate-email handling on diverse tests—while maintaining >98% holdout accuracy for LR.

### 5.4 Explainability and User Trust

Security tools fail in practice when users either ignore warnings (false positive fatigue) or trust false negatives. MailShield mitigates this by:

- Stating which indicators were detected (URLs, urgency, credential phrases).
- Listing model signal terms with class impact direction.
- Providing actionable recommendations independent of the raw score.

Future user studies could measure whether explainability reduces inappropriate trust in false negatives.

### 5.5 Limitations

1. **Domain generalisation:** Banking and some transactional emails remain misclassified despite strong aggregate metrics.
2. **Text-only analysis:** Headers, attachments, and sender reputation are not fully modelled.
3. **English-centric tokenisation:** Non-English phishing is unsupported.
4. **Dataset quality:** Mixed corpora (e.g. Enron labelled partially as phishing) introduce label noise.
5. **No deep learning baseline:** Transformer models may outperform on semantic phishing that evades bag-of-words features.
6. **Local deployment:** Not hardened for public internet exposure without HTTPS, secrets management, and rate limiting.
7. **Single holdout split:** Results may vary slightly with different random seeds or cross-validation folds.

### 5.6 Alignment with Objectives

| Objective | Status |
|-----------|--------|
| Multi-dataset training | **Achieved** — 7 CSVs, 155,859 emails |
| Dual ML models | **Achieved** — LR + Multinomial NB |
| High classification performance | **Achieved** — >96% accuracy both models |
| Explainability | **Achieved** — summary, indicators, highlights, recommendations |
| Guest + registered users | **Achieved** — 5 guest scans, JWT auth, history |
| Critical evaluation of false positives | **Partially achieved** — banking FP remains; documented honestly |

### 5.7 Broader Implications for Phishing Detection Research

The MailShield project illustrates a tension central to applied security ML: optimising aggregate metrics on historical corpora does not guarantee fair treatment of all legitimate communication genres. Phishing and legitimate emails share vocabulary in domains such as finance, shipping, and account security because both message types discuss the same real-world concepts—only intent differs. Intent is harder to infer from bag-of-words features alone.

Bigram features partially address this by distinguishing “account statement” from “verify account,” but sparse legitimate examples of specific bigrams (e.g. `online__banking` with only five legitimate training documents vs hundreds of phishing occurrences) still produce skewed weights unless explicitly filtered. The ambiguous-unigram filter and bigram minimum document frequency rules implemented in the final pipeline are general-purpose statistical remedies rather than domain-specific hacks.

For practitioners, the key lesson is to **always evaluate on domain-stratified test sets** supplementing random holdout splits. A model with 98% accuracy can still fail on the exact email type a non-expert user is most anxious about—precisely the email they paste into a tool like MailShield.

### 5.8 Pedagogical Value

As a learning artefact, MailShield covers the full data science workflow: problem formulation, literature review, data engineering, algorithm implementation, hyperparameter tuning, evaluation, deployment, debugging, and critical reflection. Implementing Logistic Regression and Naive Bayes without libraries forces engagement with gradient descent, sigmoid functions, Laplace smoothing, and log-sum-exp numerical stability—topics often obscured by high-level API calls.

---

## Chapter 6: Conclusion

This project set out to build MailShield, a web-based AI system for detecting phishing emails using machine learning. The final system integrates data loading from seven public CSV corpora, a JavaScript implementation of TF-IDF feature extraction, chi-square feature selection with contextual bigrams, Logistic Regression and Multinomial Naive Bayes classifiers, and a React frontend that presents verdicts alongside explainability and safety guidance.

Quantitative evaluation on 31,171 holdout emails demonstrates strong performance: Logistic Regression achieves 98.22% accuracy, 98.25% F1-score, and 0.9979 ROC-AUC; Naive Bayes achieves 96.17% accuracy, 96.17% F1-score, and 0.9924 ROC-AUC. Qualitative evaluation across eleven diverse email categories confirms robust detection of obvious phishing while revealing remaining challenges for legitimate banking and some transactional notifications.

The project contributes a working reference implementation suitable for education and local deployment, emphasising interpretability and user experience alongside raw classification metrics. Development iterations highlighted the importance of statistically principled feature selection over hard-coded keyword rules, balanced training objectives, and honest reporting of domain-specific limitations.

Future work should expand legitimate notification training data, explore transformer-based models for comparison, incorporate header and URL reputation features, and conduct formal usability testing. MailShield provides a solid foundation upon which these enhancements can be built.

In closing, the project demonstrates that effective phishing detection tools require not only accurate classifiers but also thoughtful feature engineering, honest evaluation across user-relevant email types, transparent explainability, and usable software delivery. MailShield achieves these goals to a substantial degree within the constraints of a student full-stack implementation, while openly documenting where further research and engineering are needed.

---

## Chapter 7: Critical Evaluation

### 7.1 Strengths

**Complete full-stack delivery.** The project is not limited to a training script or notebook; it includes frontend, backend, database, authentication, and cached model persistence. This demonstrates software engineering capability beyond algorithm implementation alone.

**Reproducibility.** Fixed random seed (42), logged training configuration, fingerprint-based model cache, and documented hyperparameters allow results to be replicated on the same hardware and datasets.

**Statistically grounded feature selection.** Moving from forced phishing keyword lists to chi-square selection with bigram guards and ambiguous-word filtering represents a principled ML approach and directly addressed observed false positives.

**Dual-model comparison.** Users can select Logistic Regression or Naive Bayes, supporting both pedagogical exploration and practical comparison of linear vs probabilistic text classifiers.

**Explainability layer.** Indicators, summaries, recommendations, sentiment analysis, and inline highlighting improve usability compared to a single probability score.

**Graceful degradation.** Guest scans function without MySQL; authenticated scans return results even when history save fails, improving reliability during local development.

### 7.2 Weaknesses

**Legitimate banking false positives.** Despite pipeline improvements, a standard legitimate banking statement email still scores above 90% phishing (LR) on diverse validation. This undermines trust for financial notification use cases and reflects training data imbalance at the vocabulary level.

**Naive Bayes recall gap.** With 896 false negatives vs LR’s 236 on the same holdout set, NB misses substantially more phishing emails. The diverse validation also shows NB missing fake invoice phishing (10.3% score).

**Training time.** Initial training requires approximately twelve minutes on the full dataset without cache. This is acceptable for development but would require optimisation (mini-batch sampling, incremental learning) for frequent retraining in production.

**Limited evaluation rigour.** A single 80/20 split was used rather than k-fold cross-validation. Reported metrics are point estimates that may vary with different splits.

**Security posture.** Default JWT secret, local HTTP, and absence of rate limiting or input sanitisation beyond truncation are inadequate for public deployment without further hardening.

**No formal user testing.** Usability, comprehension of explainability text, and appropriate user response to false positives/negatives were not measured through structured user studies.

### 7.3 Ethical Considerations

False positives may cause users to dismiss legitimate emails from banks or employers, potentially missing important communications. False negatives may create unwarranted confidence in dangerous messages. Storing email content in MySQL for registered users raises privacy considerations; a production system should document retention policies and offer opt-out or encryption.

The tool is intended for **assistive triage**, not as a sole authority for security decisions. Documentation and UI messaging should reinforce that users must verify suspicious emails through independent official channels.

### 7.4 Comparison to Alternative Designs

| Design Choice | Rationale | Alternative Considered |
|---------------|-----------|------------------------|
| Classical ML in JS | No Python dependency; integrated with Express | Python + scikit-learn microservice |
| TF-IDF + bigrams | Interpretable, fast | Word embeddings, BERT |
| Dual LR + NB | Educational comparison | Single model only |
| Local MySQL | Familiar XAMPP stack for students | Cloud database (Firebase, Supabase) |
| Rule-based explainability | Transparent to users | SHAP/LIME (heavier dependency) |

Each choice prioritised simplicity, interpretability, and local deployability over maximum theoretical accuracy.

### 7.5 Personal Learning Outcomes

Completing this project developed practical skills in:

- Designing and implementing a text classification pipeline from scratch.
- Diagnosing ML failures (bias drift, wrong NB formula, forced features) through systematic auditing.
- Integrating ML inference into a REST API with authentication and persistence.
- Debugging full-stack connectivity (Vite proxy, port conflicts, backend startup ordering).
- Writing honest technical documentation that reports limitations alongside achievements.

### 7.6 Recommendations for Future Work

1. **Expand legitimate training data** for banking, shipping, HR, and password-reset notification templates.
2. **Implement k-fold cross-validation** and report mean ± standard deviation of metrics.
3. **Add a BERT or DistilBERT baseline** for semantic comparison on diverse validation emails.
4. **Incorporate email header features** (Reply-To mismatch, SPF result) as supplementary signals.
5. **Conduct a user study** measuring comprehension and trust of explainability outputs.
6. **Harden for production:** environment-based secrets, HTTPS, rate limiting, audit logging.
7. **Support multilingual tokenisation** for non-English phishing campaigns.

### 7.8 Reflection on Project Management

The project followed an iterative agile-style cycle rather than strict waterfall planning. Initial implementation prioritised a working scan path (frontend → API → simple classifier). Subsequent iterations addressed Naive Bayes mathematical errors, multi-CSV dataset loading, explainability features, UI redesign, training pipeline bias, and deployment reliability (Vite proxy, backend wait script). This order ensured a demonstrable minimum viable product early while leaving time for rigorous ML debugging—time that proved essential when legitimate banking emails exposed flaws invisible in accuracy metrics alone.

Risk management included: dependency on local XAMPP (mitigated by guest-mode scans without DB); long training times (mitigated by model cache); and OneDrive sync conflicts on large CSV files (mitigated by `.gitignore` patterns and local copies). If repeating the project, earlier domain-stratified testing would be scheduled before UI polish to surface ML limitations sooner.

### 7.9 Final Critical Judgement

MailShield meets its primary aim of delivering a functional, explainable, dual-model phishing detection web application with strong aggregate test performance. It falls short of perfect domain generalisation—particularly for legitimate financial notifications—and lacks the security and evaluation rigour required for enterprise deployment without further work.

As an academic and practical learning project, it successfully demonstrates the end-to-end lifecycle of applied machine learning in cybersecurity: data collection, preprocessing, training, evaluation, deployment, debugging, and honest critical reflection. The documented false positives and iterative pipeline improvements strengthen rather than weaken the project’s credibility, showing that the developer understood not only how to achieve high accuracy metrics but also why those metrics alone are insufficient for real-world trust.

---

## References (Suggested — expand and format per your institution’s style)

1. Fette, I., Sadeh, N., & Tomasic, A. (2007). Learning to detect phishing emails. *WWW Conference*.
2. Chandrasekaran, M., Narayanan, K., & Upadhyaya, S. (2006). Phishing email detection based on structural properties. *NYS Cyber Security Conference*.
3. Ma, J., et al. (2009). Identifying suspicious URLs in web pages. *CIKM*.
4. Sahingoz, O. K., et al. (2019). Machine learning based phishing detection from URLs. *Expert Systems with Applications*.
5. SpamAssassin Project documentation. Apache Software Foundation.
6. Joachims, T. (1998). Text categorisation with support vector machines. *ECML*.
7. Zhang, A. (2015). *Introduction to Machine Learning* — Naive Bayes and Logistic Regression chapters.
8. GDPR / UK ICO guidance on privacy notices (for email content storage discussion).

---

## Appendices

### Appendix A: API Example (Analyse Request)

```http
POST /api/analyze HTTP/1.1
Content-Type: application/json

{
  "text": "URGENT: Verify your account immediately at http://fake-bank.xyz/login",
  "modelType": "logistic_regression"
}
```

### Appendix B: Diagrams

See `docs/diagrams/`:

- `mailshield-use-case-diagram.png`
- `mailshield-detailed-use-case-diagram.png`
- `mailshield-flowchart.png`
- `mailshield-system-architecture.png`

### Appendix C: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 5001 | Backend port |
| DB_HOST | 127.0.0.1 | MySQL host |
| DB_PORT | 3307 | MySQL port |
| LR_EPOCHS | 20 | Training epochs |
| ML_RANDOM_SEED | 42 | Reproducibility seed |

### Appendix D: How to Run

```bash
npm install
npm run dev
# Open http://127.0.0.1:5173
```

Ensure XAMPP MySQL is running for registration and history features.

### Appendix E: Glossary

| Term | Definition |
|------|------------|
| Phishing | Fraudulent email attempting to deceive recipients into revealing sensitive information or taking harmful actions |
| TF-IDF | Term Frequency–Inverse Document Frequency; numerical text representation weighting distinctive words |
| Logistic Regression | Linear classifier with sigmoid output giving probability of class membership |
| Naive Bayes | Probabilistic classifier assuming conditional independence of features given class |
| Holdout set | 20% of data reserved for final evaluation, not used during training |
| False positive | Legitimate email incorrectly classified as phishing |
| False negative | Phishing email incorrectly classified as legitimate |
| ROC-AUC | Area under receiver operating characteristic curve; measures ranking quality |
| JWT | JSON Web Token; used for authenticated API sessions |
| Bigram | Pair of consecutive tokens treated as a single compound feature |

### Appendix F: Chapter Summary Table

| Chapter | Focus | Key Outputs |
|---------|-------|-------------|
| 1 | Introduction | Problem, aims, scope |
| 2 | Literature review | ML and phishing background |
| 3 | Implementation | Architecture, ML pipeline, API |
| 4 | Results | Metrics, confusion matrices, examples |
| 5 | Discussion | LR vs NB, limitations, implications |
| 6 | Conclusion | Achievements and future work summary |
| 7 | Critical evaluation | Strengths, weaknesses, ethics, reflection |

This document was prepared to accompany the MailShield software artefact and should be read alongside the source code repository, training logs, and diagram assets stored in the `docs/` directory.

---

*End of Document*

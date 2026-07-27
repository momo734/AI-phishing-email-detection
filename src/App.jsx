import { useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';

const API_BASE_URL = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_URL || 'http://127.0.0.1:5001');
const FREE_SCAN_LIMIT = 5;
const GUEST_SCANS_KEY = 'mailshieldGuestScans';
const modelLabels = {
  logistic_regression: 'Logistic Regression',
  naive_bayes: 'Naive Bayes',
};

const features = [
  {
    title: 'Dual AI models',
    description: 'Choose Logistic Regression or Naive Bayes before each scan and compare how each model scores the same email.',
    tag: 'ML',
  },
  {
    title: 'TF-IDF scoring',
    description: 'Every scan returns a phishing probability plus the top weighted terms that influenced the verdict.',
    tag: 'Analysis',
  },
  {
    title: 'AI explainability',
    description: 'See a clear summary of why each email was flagged, plus actionable safety recommendations after every scan.',
    tag: 'Explainability',
  },
  {
    title: 'Safety recommendations',
    description: 'After every scan, get actionable guidance such as avoiding suspicious links, verifying through official sites, and deleting risky emails.',
    tag: 'Guidance',
  },
  {
    title: 'Trigger highlighting',
    description: 'After a scan, switch to Flagged text in the email box to see suspicious keywords and phrases highlighted inline.',
    tag: 'Visual',
  },
  {
    title: 'Sentiment analysis',
    description: 'Detects psychological pressure such as urgency and fear, with scores for tactics like "Account blocked" or "Immediate action required".',
    tag: 'Psychology',
  },
  {
    title: 'Paste or upload',
    description: 'Drop email text directly into the console or upload .txt, .eml, and .csv files for quick testing.',
    tag: 'Input',
  },
  {
    title: 'Guest scanning',
    description: 'Try MailShield without an account. Guests receive 5 free scans stored locally in the browser.',
    tag: 'Access',
  },
  {
    title: 'User accounts',
    description: 'Register to remove the guest scan limit and keep using the detector for ongoing email checks.',
    tag: 'Auth',
  },
  {
    title: 'Scan history',
    description: 'Logged-in users automatically save each scan to MySQL with verdict, score, model, and timestamp.',
    tag: 'History',
  },
  {
    title: 'Dataset training',
    description: 'The backend trains from your phishing email CSV so vocabulary and scores reflect your dataset.',
    tag: 'Backend',
  },
  {
    title: 'Secure sessions',
    description: 'Registration and login use bcrypt password hashing and JWT tokens for authenticated API requests.',
    tag: 'Security',
  },
];

const howItWorks = [
  {
    step: '01',
    title: 'Paste or upload email text',
    description: 'Add suspicious message content to the scanner or upload a supported text file.',
  },
  {
    step: '02',
    title: 'Pick a detection model',
    description: 'Select Logistic Regression or Naive Bayes depending on the scoring approach you want.',
  },
  {
    step: '03',
    title: 'Review the verdict',
    description: 'See the phishing score, highlighted trigger phrases, sentiment signals, and TF-IDF terms that drove the result.',
  },
];

const highlightLegend = [
  { category: 'domain', label: 'Suspicious domain or link mismatch' },
  { category: 'keyword', label: 'Suspicious phishing keyword' },
  { category: 'urgency', label: 'Urgency language' },
  { category: 'fear', label: 'Fear or pressure language' },
  { category: 'tfidf', label: 'Model signal term' },
];

const recommendationPriorityClass = {
  high: 'recommendation-high',
  medium: 'recommendation-medium',
  low: 'recommendation-low',
};

function buildHighlightedSegments(text, highlights = []) {
  if (!text) return [];
  if (!highlights.length) return [{ text, category: null }];

  const segments = [];
  let cursor = 0;

  // Ensure highlights are sorted by start index to avoid broken rendering
  const sortedHighlights = [...highlights].sort((a, b) => a.start - b.start);

  sortedHighlights.forEach((highlight) => {
    if (highlight.start > cursor) {
      segments.push({ text: text.slice(cursor, highlight.start), category: null });
    }
    segments.push({
      text: text.slice(highlight.start, highlight.end),
      category: highlight.category,
      reason: highlight.reason,
    });
    cursor = highlight.end;
  });

  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), category: null });
  }

  return segments;
}

function App() {
  const [view, setView] = useState('scanner');
  const [emailText, setEmailText] = useState('');
  const [selectedModel, setSelectedModel] = useState('logistic_regression');
  const [analysis, setAnalysis] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [authMode, setAuthMode] = useState('login');
  const [showAuth, setShowAuth] = useState(false);
  const [emailView, setEmailView] = useState('edit');
  const [authForm, setAuthForm] = useState({ name: '', email: '', password: '' });
  const [session, setSession] = useState(() => {
    const saved = localStorage.getItem('mailshieldSession');
    return saved ? JSON.parse(saved) : null;
  });
  const [guestScansUsed, setGuestScansUsed] = useState(() => {
    localStorage.removeItem('mailshieldGuestScans');
    localStorage.removeItem('phishguardGuestScans');

    if (import.meta.env.DEV) {
      return 0;
    }

    return Number(sessionStorage.getItem(GUEST_SCANS_KEY) || 0);
  });

  const freeScansLeft = useMemo(
    () => Math.max(0, FREE_SCAN_LIMIT - guestScansUsed),
    [guestScansUsed],
  );

  useEffect(() => {
    if (import.meta.env.DEV) {
      return;
    }

    sessionStorage.setItem(GUEST_SCANS_KEY, String(guestScansUsed));
  }, [guestScansUsed]);

  useEffect(() => {
    if (session) {
      localStorage.setItem('mailshieldSession', JSON.stringify(session));
    } else {
      localStorage.removeItem('mailshieldSession');
    }
  }, [session]);

  const request = useCallback(async (path, options = {}) => {
    let response;

    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(session?.token ? { Authorization: `Bearer ${session.token}` } : {}),
          ...(options.headers || {}),
        },
      });
    } catch {
      throw new Error('Cannot reach the backend. Run npm run dev from the PhishingDetection folder and wait for "MailShield backend running" in the terminal.');
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(
        data.error
        || (response.status === 502 || response.status === 504
          ? 'Cannot reach the backend. Run npm run dev from the PhishingDetection folder and wait for "MailShield backend running".'
          : `Request failed (${response.status}).`),
      );
    }
    return data;
  }, [session]);

  const loadHistory = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    try {
      const rows = await request('/api/history');
      setHistory(rows);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }, [request, session]);

  const deleteHistoryItem = async (id) => {
    setMessage('');
    try {
      await request(`/api/history/${id}`, { method: 'DELETE' });
      setHistory((rows) => rows.filter((row) => row.id !== id));
      setMessage('Scan deleted from history.');
    } catch (error) {
      setMessage(error.message);
    }
  };

  const deleteAllHistory = async () => {
    if (!window.confirm('Delete all scan history? This cannot be undone.')) return;

    setMessage('');
    try {
      await request('/api/history', { method: 'DELETE' });
      setHistory([]);
      setMessage('All scan history deleted.');
    } catch (error) {
      setMessage(error.message);
    }
  };

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (readerEvent) => {
      setEmailText(String(readerEvent.target?.result || ''));
      setAnalysis(null);
      setEmailView('edit');
    };
    reader.readAsText(file);
  };

  const handlePasteFromClipboard = async () => {
    setMessage('');

    if (!navigator.clipboard?.readText) {
      setMessage('Clipboard paste is not supported in this browser. Paste manually into the text box.');
      return;
    }

    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) {
        setMessage('Your clipboard is empty. Copy an email first, then try again.');
        return;
      }
      setEmailText(text);
      setAnalysis(null);
      setEmailView('edit');
    } catch {
      setMessage('Could not read the clipboard. Allow clipboard access or paste manually into the text box.');
    }
  };

  const executeScan = async () => {
    setMessage('');

    if (!emailText.trim()) {
      setMessage('Paste an email or upload a text file before scanning.');
      return;
    }

    if (!session && freeScansLeft <= 0) {
      setAuthMode('register');
      setShowAuth(true);
      setMessage('Your 5 free scans are finished. Register to continue and unlock scan history.');
      return;
    }

    setLoading(true);
    try {
      const result = await request('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ text: emailText, modelType: selectedModel }),
      });
      setAnalysis(result);
      setEmailView('highlights');
      if (result.historyWarning) {
        setMessage(result.historyWarning);
      }
      if (!session) {
        setGuestScansUsed((count) => count + 1);
      }
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  const submitAuth = async (event) => {
    event.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const endpoint = authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const payload = authMode === 'register'
        ? authForm
        : { email: authForm.email, password: authForm.password };
      const data = await request(endpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      if (authMode === 'register') {
        setShowAuth(true);
        setAuthMode('login');
        setAuthForm({ name: '', email: authForm.email, password: '' });
        setMessage(data.message || 'Registration successful. Please log in to continue.');
        return;
      }

      setSession({ token: data.token, user: data.user });
      setShowAuth(false);
      setAuthForm({ name: '', email: '', password: '' });
      setGuestScansUsed(0);
      setMessage('Login successful.');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setSession(null);
    setHistory([]);
    setGuestScansUsed(0);
    sessionStorage.removeItem(GUEST_SCANS_KEY);
    setView('scanner');
    setMessage('Logged out. Guest scans are available again.');
  };

  /* ==========================================
     🛠️ PARSING AND LOGIC NORMALIZATION LAYER
     ========================================== */

  // Use API verdict directly — do not re-derive from phishing probability alone.
  const verdictLabel = analysis?.verdict || '';
  const isPhishing = verdictLabel.toLowerCase() === 'phishing';

  const phishPercent = useMemo(() => {
    if (!analysis) return 0;
    const rawProba = analysis.predictProba?.phishing
      ?? analysis.phishingProbability
      ?? analysis.calibratedPhishingProbability
      ?? analysis.rawPhishingProbability
      ?? 0;
    return Math.round(rawProba <= 1 ? rawProba * 100 : rawProba);
  }, [analysis]);

  const legitPercent = useMemo(() => {
    if (!analysis) return 0;
    const rawProba = analysis.predictProba?.legitimate ?? analysis.legitimateProbability ?? (100 - phishPercent);
    return Math.round(rawProba <= 1 ? rawProba * 100 : rawProba);
  }, [analysis, phishPercent]);

  const confidencePercent = analysis?.confidenceScore ?? (isPhishing ? phishPercent : legitPercent);
  const scoreStyle = { width: `${confidencePercent}%` };

  const highlightedSegments = useMemo(
    () => buildHighlightedSegments(emailText, analysis?.highlights || []),
    [emailText, analysis],
  );

  const explainability = analysis?.explainability || analysis?.explanation || null;
  const recommendations = analysis?.recommendations || explainability?.recommendations || [];
  const explainabilitySummary = explainability?.summary || analysis?.explanation?.summary || '';
  const highlightCount = analysis?.highlights?.length || 0;
  const showHighlightView = Boolean(analysis && emailView === 'highlights' && emailText.trim());

  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="brand-button" onClick={() => setView('scanner')}>
          <span className="brand-mark">MS</span>
          <span>MailShield</span>
        </button>

        <nav className="nav-tabs" aria-label="Main navigation">
          <button className={view === 'scanner' ? 'active' : ''} onClick={() => setView('scanner')}>Scanner</button>
          <button className={view === 'features' ? 'active' : ''} onClick={() => setView('features')}>Features</button>
          <button
            className={view === 'history' ? 'active' : ''}
            onClick={() => {
              if (!session) {
                setShowAuth(true);
                return;
              }
              setView('history');
              loadHistory();
            }}
          >
            History
          </button>
        </nav>

        <div className="account-area">
          {!session && <span className="scan-pill">{freeScansLeft} free scans left</span>}
          {session ? (
            <>
              <span className="user-chip">{session.user.email}</span>
              <button className="ghost-button" onClick={logout}>Logout</button>
            </>
          ) : (
            <>
              <button className="ghost-button" onClick={() => { setAuthMode('login'); setShowAuth(true); }}>Login</button>
              <button className="solid-button" onClick={() => { setAuthMode('register'); setShowAuth(true); }}>Register</button>
            </>
          )}
        </div>
      </header>

      <main className="workspace">
        <section className="hero-band">
          <div>
            <p className="eyebrow">
              {view === 'features' ? 'What MailShield offers' : 'Web based AI phishing email detection'}
            </p>
            <h1>
              {view === 'features'
                ? 'Everything built into your phishing detection platform.'
                : view === 'history'
                  ? 'Review past scans and model results.'
                  : 'Detect phishing emails before you click.'}
            </h1>
          </div>
        </section>

        {message && <div className="notice">{message}</div>}

        {view === 'features' && (
          <section className="features-page">
            <div className="features-grid">
              {features.map((feature) => (
                <article className="feature-card" key={feature.title}>
                  <span className="feature-tag">{feature.tag}</span>
                  <h2>{feature.title}</h2>
                  <p>{feature.description}</p>
                </article>
              ))}
            </div>

            <div className="how-panel">
              <div className="panel-head">
                <div>
                  <p className="eyebrow">Workflow</p>
                  <h2>How it works</h2>
                </div>
              </div>

              <div className="steps-grid">
                {howItWorks.map((item) => (
                  <article className="step-card" key={item.step}>
                    <span className="step-number">{item.step}</span>
                    <h3>{item.title}</h3>
                    <p>{item.description}</p>
                  </article>
                ))}
              </div>

              <div className="features-cta">
                <p>Ready to test an email? Open the scanner and run your first check.</p>
                <button className="solid-button" type="button" onClick={() => setView('scanner')}>
                  Go to scanner
                </button>
              </div>
            </div>
          </section>
        )}

        {view === 'scanner' && (
          <section className="scanner-layout">
            <div className="scanner-main">
              <div className="scan-panel">
                <div className="panel-head">
                  <div>
                    <p className="eyebrow">Email input</p>
                    <h2>Detection console</h2>
                  </div>
                  <select value={selectedModel} onChange={(event) => setSelectedModel(event.target.value)}>
                    <option value="logistic_regression">Logistic Regression</option>
                    <option value="naive_bayes">Naive Bayes</option>
                  </select>
                </div>

                <div className="email-workspace">
                  {analysis && (
                    <div className="email-view-toggle" role="tablist" aria-label="Email view">
                      <button
                        type="button"
                        role="tab"
                        aria-selected={emailView === 'edit'}
                        className={emailView === 'edit' ? 'active' : ''}
                        onClick={() => setEmailView('edit')}
                      >
                        Edit email
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={emailView === 'highlights'}
                        className={emailView === 'highlights' ? 'active' : ''}
                        onClick={() => setEmailView('highlights')}
                      >
                        Flagged text
                        {highlightCount > 0 && <span className="flag-count">{highlightCount}</span>}
                      </button>
                    </div>
                  )}

                  {showHighlightView ? (
                    <div className="email-highlight-view">
                      <div className="highlight-key">
                        {highlightLegend.map((item) => (
                          <span className={`key-item key-${item.category}`} key={item.category}>
                            <span className="key-dot" aria-hidden="true" />
                            {item.label}
                          </span>
                        ))}
                      </div>
                      <div className="highlighted-email">
                        {highlightedSegments.map((segment, index) => (
                          segment.category ? (
                            <mark
                              className={`highlight-${segment.category}`}
                              key={`${segment.category}-${index}`}
                              title={segment.reason}
                            >
                              {segment.text}
                            </mark>
                          ) : (
                            <span key={`plain-${index}`}>{segment.text}</span>
                          )
                        ))}
                      </div>
                    </div>
                  ) : (
                    <textarea
                      value={emailText}
                      onChange={(event) => {
                        setEmailText(event.target.value);
                        setAnalysis(null);
                        setEmailView('edit');
                      }}
                      placeholder="Paste the full email body here..."
                    />
                  )}
                </div>

                <div className="input-actions">
                  <label className="file-button">
                    Upload .txt
                    <input type="file" accept=".txt,.eml,.csv,text/*" onChange={handleFileUpload} />
                  </label>
                  <button className="ghost-button" type="button" onClick={handlePasteFromClipboard}>
                    Paste
                  </button>
                  <button className="ghost-button" onClick={() => { setEmailText(''); setAnalysis(null); setEmailView('edit'); }}>Clear</button>
                  <button className="solid-button scan-button" disabled={loading} onClick={executeScan}>
                    {loading ? 'Scanning...' : 'Run scan'}
                  </button>
                </div>
              </div>
            </div>

            <aside className="result-panel">
              <p className="eyebrow">Prediction confidence</p>
              {analysis ? (
                <div className="analysis-stack">
                  <div className={`verdict ${isPhishing ? 'danger' : 'safe'}`}>
                    <span>{verdictLabel || (isPhishing ? 'Phishing' : 'Legitimate')}</span>
                    <strong>{confidencePercent}%</strong>
                  </div>
                  <div className="score-track">
                    <div className={isPhishing ? 'danger-fill' : 'safe-fill'} style={scoreStyle} />
                  </div>
                  <dl className="score-details">
                    <div>
                      <dt>Model</dt>
                      <dd>{modelLabels[analysis.modelUsed || analysis.model_used] || modelLabels[selectedModel]}</dd>
                    </div>
                    <div>
                      <dt>Confidence</dt>
                      <dd>{confidencePercent}% ({isPhishing ? 'Phishing' : 'Legitimate'})</dd>
                    </div>
                    <div>
                      <dt>Phishing probability</dt>
                      <dd>{phishPercent}%</dd>
                    </div>
                    <div>
                      <dt>Legitimate probability</dt>
                      <dd>{legitPercent}%</dd>
                    </div>
                    <div>
                      <dt>Matched TF-IDF terms</dt>
                      <dd>{analysis.tfidf?.matchedTerms ?? 0}</dd>
                    </div>
                  </dl>

                  {explainabilitySummary && (
                    <div className="analysis-card explain-panel">
                      <h3>AI explainability</h3>
                      <p className="explain-summary">{explainabilitySummary}</p>
                    </div>
                  )}

                  {recommendations.length > 0 && (
                    <div className="analysis-card recommendation-panel">
                      <h3>Safety recommendations</h3>
                      <ul className="recommendation-list">
                        {recommendations.map((item, idx) => (
                          <li
                            className={`recommendation-item ${recommendationPriorityClass[item.priority] || 'recommendation-medium'}`}
                            key={`${item.text}-${idx}`}
                          >
                            {item.text}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {analysis.sentiment && (
                    <div className="analysis-card sentiment-panel">
                      <h3>Sentiment analysis</h3>
                      <p className="sentiment-tone">
                        Overall tone: <strong>{analysis.sentiment.overallTone || analysis.sentiment.overall_tone || 'Neutral'}</strong>
                      </p>
                      <div className="sentiment-scores">
                        <div className="sentiment-score">
                          <span>Urgency</span>
                          <div className="score-track">
                            <div className="danger-fill" style={{ width: `${analysis.sentiment.urgencyScore ?? analysis.sentiment.urgency_score ?? 0}%` }} />
                          </div>
                          <b>{analysis.sentiment.urgencyScore ?? analysis.sentiment.urgency_score ?? 0}%</b>
                        </div>
                        <div className="sentiment-score">
                          <span>Fear</span>
                          <div className="score-track">
                            <div className="danger-fill" style={{ width: `${analysis.sentiment.fearScore ?? analysis.sentiment.fear_score ?? 0}%` }} />
                          </div>
                          <b>{analysis.sentiment.fearScore ?? analysis.sentiment.fear_score ?? 0}%</b>
                        </div>
                      </div>
                      {analysis.sentiment.triggers?.length ? (
                        <ul className="trigger-list">
                          {analysis.sentiment.triggers.map((trigger, idx) => (
                            <li key={`${trigger.category}-${trigger.phrase}-${idx}`}>
                              <span className={`trigger-badge trigger-${trigger.category}`}>{trigger.category}</span>
                              <span>{trigger.phrase}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="sentiment-empty">No strong urgency or fear triggers detected.</p>
                      )}
                    </div>
                  )}

                  <div className="analysis-card terms-list">
                    <h3>Top TF-IDF signals</h3>
                    {analysis.tfidf?.topTerms?.length || analysis.tfidf?.top_terms?.length ? (
                      (analysis.tfidf.topTerms || analysis.tfidf.top_terms).map((term, idx) => (
                        <div className="term-row" key={`${term.term}-${idx}`}>
                          <span>{term.term}</span>
                          <meter min="0" max="1" value={Math.min(term.value ?? 0, 1)} />
                          <b>{term.value ?? 0}</b>
                        </div>
                      ))
                    ) : (
                      <p>No dataset vocabulary terms were found in this email.</p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="empty-result">
                  Choose a model, paste an email, and run a scan to see the TF-IDF based score.
                </div>
              )}
            </aside>
          </section>
        )}

        {view === 'history' && session && (
          <section className="history-panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Registered users only</p>
                <h2>Scan history</h2>
              </div>
              <div className="history-actions">
                {history.length > 0 && (
                  <button className="ghost-button danger-button" type="button" onClick={deleteAllHistory}>
                    Delete all
                  </button>
                )}
                <button className="ghost-button" type="button" onClick={loadHistory} disabled={loading}>Refresh</button>
              </div>
            </div>

            {history.length === 0 ? (
              <div className="empty-result">No scans saved yet. Registered scans will appear here automatically.</div>
            ) : (
              <div className="history-list">
                {history.map((row) => {
                  // Uniformly handle history table data structures
                  const rowScore = row.score ?? row.probability ?? (row.model_used === 'naive_bayes' ? row.naive_bayes_score : row.logistic_regression_score) ?? 0;
                  const rowVerdict = String(row.result || row.verdict || '').toLowerCase() === 'phishing';

                  return (
                    <article className="history-row" key={row.id}>
                      <div>
                        <strong style={{ color: rowVerdict ? 'var(--danger-color, #dc3545)' : 'var(--success-color, #28a745)' }}>
                          {row.result || row.verdict}
                        </strong>
                        <p>{row.email_content || row.text}</p>
                        <span>{new Date(row.scanned_at || row.created_at).toLocaleString()}</span>
                      </div>
                      <div className="history-score">
                        <b>{rowScore}%</b>
                        <span>{modelLabels[row.model_used] || row.model_used}</span>
                        <button
                          className="ghost-button danger-button history-delete"
                          type="button"
                          onClick={() => deleteHistoryItem(row.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        )}
      </main>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <span className="brand-mark">MS</span>
            <div>
              <strong>MailShield</strong>
              <p>AI-powered phishing email detection using TF-IDF scoring.</p>
            </div>
          </div>

          <nav className="footer-links" aria-label="Footer navigation">
            <a href="#scanner" onClick={(event) => { event.preventDefault(); setView('scanner'); }}>Scanner</a>
            <a href="#features" onClick={(event) => { event.preventDefault(); setView('features'); }}>Features</a>
            <a href="#history" onClick={(event) => {
              event.preventDefault();
              if (!session) {
                setShowAuth(true);
                return;
              }
              setView('history');
              loadHistory();
            }}>History</a>
          </nav>

          <div className="footer-meta">
            <span>&copy; {new Date().getFullYear()} MailShield</span>
            <span>Logistic Regression &amp; Naive Bayes models</span>
          </div>
        </div>
      </footer>

      {showAuth && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <form className="auth-modal" onSubmit={submitAuth}>
            <button className="close-button" type="button" onClick={() => setShowAuth(false)}>x</button>
            <p className="eyebrow">{authMode === 'register' ? 'Create account' : 'Welcome back'}</p>
            <h2>{authMode === 'register' ? 'Register to continue scanning' : 'Login to your account'}</h2>

            {authMode === 'register' && (
              <label>
                Name
                <input value={authForm.name} onChange={(event) => setAuthForm({ ...authForm, name: event.target.value })} required />
              </label>
            )}

            <label>
              Email
              <input type="email" value={authForm.email} onChange={(event) => setAuthForm({ ...authForm, email: event.target.value })} required />
            </label>

            <label>
              Password
              <input type="password" value={authForm.password} onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })} required minLength={6} />
            </label>

            <button className="solid-button full-width" type="submit" disabled={loading}>
              {loading ? 'Please wait...' : authMode === 'register' ? 'Create account' : 'Login'}
            </button>

            <button
              className="link-button"
              type="button"
              onClick={() => setAuthMode(authMode === 'register' ? 'login' : 'register')}
            >
              {authMode === 'register' ? 'Already registered? Login' : 'Need an account? Register'}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

export default App;
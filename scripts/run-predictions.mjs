import { API_BASE } from './api-config.mjs';

const samples = [
  {
    label: 'legitimate',
    text: 'Hello team, the project meeting is scheduled for tomorrow at 10 AM. Please review the attached agenda. Thanks, Sarah',
  },
  {
    label: 'legitimate',
    text: 'Hi John, can we talk tomorrow about the quarterly report?',
  },
  {
    label: 'phishing',
    text: 'URGENT: Your account blocked. Immediate action required. Verify your password at http://secure-login-verify.xyz/update',
  },
  {
    label: 'phishing',
    text: 'Winner! Claim your free reward now. Click here to verify banking details immediately.',
  },
];

console.log(`Requires backend on ${API_BASE}\n`);

for (const sample of samples) {
  for (const modelType of ['logistic_regression', 'naive_bayes']) {
    const response = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: sample.text, modelType }),
    });
    const data = await response.json();

    console.log('='.repeat(72));
    console.log(`Expected: ${sample.label} | Model: ${modelType}`);
    console.log('Original email:', sample.text);
    console.log('Cleaned email:', data.cleanedText || '(not returned)');
    console.log('Raw phishing probability (predict_proba):', data.rawPhishingProbability);
    console.log('Calibrated phishing probability:', data.phishingProbability);
    console.log('Predicted class (prediction):', data.prediction, data.prediction === 1 ? '(Phishing)' : '(Legitimate)');
    console.log('Final displayed label (verdict):', data.verdict);
    console.log('Matched TF-IDF features:', data.tfidf?.matchedTerms);
  }
}

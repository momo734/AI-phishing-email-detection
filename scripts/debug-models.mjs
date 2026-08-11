import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { API_BASE } from './api-config.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

// Load server module pieces by evaluating - start server briefly via fetch after import
// Instead duplicate minimal dataset audit from CSV directly

function parseCsvRecords(content) {
  const records = [];
  let row = [];
  let current = '';
  let quoted = false;
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    const next = content[index + 1];
    if (char === '"' && quoted && next === '"') { current += '"'; index += 1; }
    else if (char === '"') quoted = !quoted;
    else if (char === ',' && !quoted) { row.push(current.trim()); current = ''; }
    else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && next === '\n') index += 1;
      row.push(current.trim());
      if (row.some((v) => v !== '')) records.push(row);
      row = []; current = '';
    } else current += char;
  }
  row.push(current.trim());
  if (row.some((v) => v !== '')) records.push(row);
  return records;
}

function normalizeLabel(value) {
  const label = String(value || '').trim().toLowerCase();
  if (['1', 'phishing', 'phish', 'phishing email', 'malicious', 'spam'].includes(label)) return 'phishing';
  if (['0', 'legitimate', 'legit', 'safe email', 'ham', 'safe', 'benign'].includes(label)) return 'legitimate';
  return null;
}

const datasetPath = join(root, 'data', 'Phishing_Email.csv');
const records = parseCsvRecords(readFileSync(datasetPath, 'utf8'));
const headers = records[0].map((h) => h.toLowerCase().replace(/[\s_-]/g, ''));
const textIndex = headers.findIndex((h) => ['text', 'email', 'emailtext', 'body', 'message'].includes(h));
const labelIndex = headers.findIndex((h) => ['label', 'class', 'category', 'target', 'emailtype', 'type'].includes(h));

const labelCounts = {};
const unknownLabels = new Map();
records.slice(1).forEach((cols) => {
  const raw = cols[labelIndex];
  const norm = normalizeLabel(raw);
  if (norm) labelCounts[norm] = (labelCounts[norm] || 0) + 1;
  else unknownLabels.set(raw, (unknownLabels.get(raw) || 0) + 1);
});

console.log('=== DATASET AUDIT ===');
console.log('Headers:', records[0]);
console.log('textIndex:', textIndex, 'labelIndex:', labelIndex);
console.log('Label counts:', labelCounts);
console.log('Unknown labels (top 10):', [...unknownLabels.entries()].slice(0, 10));

const tests = [
  { name: 'legitimate-meeting', text: 'Hello team, the project meeting is scheduled for tomorrow at 10 AM. Please review the attached agenda. Thanks, Sarah' },
  { name: 'phishing-urgent', text: 'URGENT: Your account blocked. Immediate action required. Verify your password at http://secure-login-verify.xyz/update' },
  { name: 'short-hi', text: 'Hi John, can we talk tomorrow?' },
];

console.log(`\n=== LIVE API TESTS (${API_BASE}) ===`);
for (const sample of tests) {
  for (const modelType of ['logistic_regression', 'naive_bayes']) {
    try {
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: sample.text, modelType }),
      });
      const data = await res.json();
      console.log(`${sample.name} | ${modelType}: rawProb=${data.phishingProbability} score=${data.score}% verdict=${data.verdict} features=${data.tfidf.matchedTerms}`);
    } catch (e) {
      console.log(`${sample.name} | ${modelType}: API unavailable (${e.message})`);
    }
  }
}

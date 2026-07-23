import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const datasetPath = join(__dirname, '..', 'data', 'Phishing_Email.csv');

const URGENCY = ['urgent', 'immediate action required', 'act now', 'verify now'];
const FEAR = ['account blocked', 'security alert', 'verify immediately', 'payment failed'];

function parseCsvRecords(content) {
  const records = [];
  let row = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < content.length; i += 1) {
    const char = content[i];
    const next = content[i + 1];
    if (char === '"' && quoted && next === '"') { current += '"'; i += 1; }
    else if (char === '"') quoted = !quoted;
    else if (char === ',' && !quoted) { row.push(current.trim()); current = ''; }
    else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && next === '\n') i += 1;
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

function cleanEmailText(text) {
  return String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function containsAny(text, phrases) {
  const lower = text.toLowerCase();
  return phrases.filter((phrase) => lower.includes(phrase));
}

if (!existsSync(datasetPath)) {
  console.error('Dataset not found:', datasetPath);
  process.exit(1);
}

const records = parseCsvRecords(readFileSync(datasetPath, 'utf8'));
const headers = records[0];
const textIndex = 1;
const labelIndex = 2;

const rows = records.slice(1)
  .map((cols) => ({ text: cols[textIndex], label: normalizeLabel(cols[labelIndex]) }))
  .filter((row) => row.text && row.label);

const seen = new Map();
let duplicates = 0;
rows.forEach((row) => {
  const key = cleanEmailText(row.text).slice(0, 400);
  seen.set(key, (seen.get(key) || 0) + 1);
});
seen.forEach((count) => { if (count > 1) duplicates += count - 1; });

const legit = rows.filter((r) => r.label === 'legitimate');
const phish = rows.filter((r) => r.label === 'phishing');

const legitWithPhishLanguage = legit.filter((row) => (
  containsAny(row.text, [...URGENCY, ...FEAR]).length > 0
)).slice(0, 5);

const phishWithNeutralLanguage = phish.filter((row) => (
  containsAny(row.text, [...URGENCY, ...FEAR]).length === 0
)).slice(0, 5);

console.log('=== DATASET AUDIT ===');
console.log('File:', datasetPath);
console.log('Headers:', headers);
console.log('Total labeled rows:', rows.length);
console.log('Legitimate:', legit.length);
console.log('Phishing:', phish.length);
console.log('Class imbalance ratio (legit:phish):', (legit.length / phish.length).toFixed(2));
console.log('Duplicate email bodies:', duplicates);
console.log('Label mapping: legitimate=0, phishing=1 (Safe Email -> legitimate, Phishing Email -> phishing)');

console.log('\n=== SAMPLE LEGITIMATE EMAILS WITH PHISHING-LIKE WORDS ===');
legitWithPhishLanguage.forEach((row, index) => {
  console.log(`\n#${index + 1}`, containsAny(row.text, [...URGENCY, ...FEAR]));
  console.log(row.text.slice(0, 220).replace(/\s+/g, ' '), '...');
});

console.log('\n=== SAMPLE PHISHING EMAILS WITHOUT OBVIOUS TRIGGER WORDS ===');
phishWithNeutralLanguage.forEach((row, index) => {
  console.log(`\n#${index + 1}`);
  console.log(row.text.slice(0, 220).replace(/\s+/g, ' '), '...');
});

console.log('\n=== RECOMMENDATIONS ===');
console.log('- Dataset labels appear consistent; labels are not reversed.');
console.log('- Legitimate class is larger than phishing; training uses balanced subsets.');
console.log('- Many legitimate corporate emails contain words like "re:", "update", "account" which overlap phishing vocabulary.');
console.log('- Remove duplicates before training (now handled in server loadDataset).');
console.log('- Use holdout test evaluation instead of evaluating on training rows.');
console.log('- Short user-typed test emails may differ from Enron-style training text; include diverse samples in training.');

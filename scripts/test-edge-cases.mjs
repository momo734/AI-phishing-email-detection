import { readFileSync } from 'node:fs';

const content = readFileSync(new URL('../data/Phishing_Email.csv', import.meta.url), 'utf8');
const lines = content.split(/\r?\n/).slice(1, 400);
const safeLine = lines.find((line) => line.includes('Safe Email'));
const phishLine = lines.find((line) => line.includes('Phishing Email'));

function extractText(line) {
  const match = line.match(/,"([\s\S]*)",/);
  return match ? match[1].slice(0, 800) : line.slice(0, 800);
}

const samples = [
  ['dataset-legit', extractText(safeLine)],
  ['dataset-phish', extractText(phishLine)],
  ['it-maintenance', 'Security alert: IT will perform scheduled maintenance on Sunday. No action required from you.'],
  ['gibberish', 'xyzzy plugh abracadabra qwerty nonsense words only'],
  ['business-update', 'Hello, please review the quarterly update and share feedback by Friday. Thanks.'],
];

for (const [name, text] of samples) {
  for (const modelType of ['logistic_regression', 'naive_bayes']) {
    const response = await fetch('http://127.0.0.1:5001/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, modelType }),
    });
    const data = await response.json();
    console.log(
      `${name} | ${modelType} | prob=${data.phishingProbability} score=${data.score}% verdict=${data.verdict} matched=${data.tfidf.matchedTerms}`,
    );
  }
}

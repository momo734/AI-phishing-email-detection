import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cachePath = join(root, 'data', '.model-cache.json');

if (!existsSync(cachePath)) {
  console.error('No model cache. Run: npm run server');
  process.exit(1);
}

const { model } = JSON.parse(readFileSync(cachePath, 'utf8'));

const email = process.argv[2] || 'URGENT: Your account suspended. Verify password and billing details within 24 hours. Click here to confirm login: http://secure-bank-login.xyz/update';

const cleaned = email
  .toLowerCase()
  .replace(/https?:\/\/\S+/gi, ' ')
  .replace(/[^a-z0-9\s]/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

const tokens = cleaned.match(/[a-z0-9]+/g)?.filter((t) => t.length > 1) || [];
const alpha = 0.5;
const V = model.vocabulary.length;

const termCounts = {};
tokens.forEach((token) => {
  if (!model.idf[token]) return;
  termCounts[token] = Math.min(3, (termCounts[token] || 0) + 1);
});

function scoreDocFrequency() {
  let logPhishing = Math.log(model.predictionPriors?.phishing ?? 0.54);
  let logLegitimate = Math.log(model.predictionPriors?.legitimate ?? 0.46);
  const terms = [];

  Object.entries(termCounts).forEach(([term, count]) => {
    const phishDocs = model.termDocCounts.phishing[term] || 0;
    const legitDocs = model.termDocCounts.legitimate[term] || 0;
    const phishProb = (phishDocs + alpha) / (model.classDocCounts.phishing + alpha * V);
    const legitProb = (legitDocs + alpha) / (model.classDocCounts.legitimate + alpha * V);
    logPhishing += count * Math.log(Math.max(phishProb, 1e-9));
    logLegitimate += count * Math.log(Math.max(legitProb, 1e-9));
    terms.push({
      term,
      count,
      phishDocs,
      legitDocs,
      phishProb: Number(phishProb.toFixed(6)),
      legitProb: Number(legitProb.toFixed(6)),
      logDelta: Number((Math.log(legitProb) - Math.log(phishProb)).toFixed(4)),
    });
  });

  const maxLog = Math.max(logPhishing, logLegitimate);
  const probability = Math.exp(logPhishing - maxLog) / (Math.exp(logPhishing - maxLog) + Math.exp(logLegitimate - maxLog));
  return { probability, logPhishing, logLegitimate, terms };
}

function scoreMultinomialTokens() {
  let logPhishing = Math.log(model.predictionPriors?.phishing ?? 0.54);
  let logLegitimate = Math.log(model.predictionPriors?.legitimate ?? 0.46);

  Object.entries(termCounts).forEach(([term, count]) => {
    const phishTokens = model.classTokenCounts.phishing[term] || 0;
    const legitTokens = model.classTokenCounts.legitimate[term] || 0;
    const phishProb = (phishTokens + alpha) / (model.totalClassTokens.phishing + alpha * V);
    const legitProb = (legitTokens + alpha) / (model.totalClassTokens.legitimate + alpha * V);
    logPhishing += count * Math.log(Math.max(phishProb, 1e-9));
    logLegitimate += count * Math.log(Math.max(legitProb, 1e-9));
  });

  const maxLog = Math.max(logPhishing, logLegitimate);
  const probability = Math.exp(logPhishing - maxLog) / (Math.exp(logPhishing - maxLog) + Math.exp(logLegitimate - maxLog));
  return { probability, logPhishing, logLegitimate };
}

const doc = scoreDocFrequency();
const multi = scoreMultinomialTokens();

console.log('Email preview:', email.slice(0, 120));
console.log('Tokens matched via idf gate:', Object.keys(termCounts).length, '/', tokens.length);
console.log('');
console.log('=== CURRENT predictNaiveBayes (doc-frequency, lines 679-686) ===');
console.log('Prior log P(phish):', Math.log(model.predictionPriors?.phishing ?? 0.54).toFixed(4));
console.log('Prior log P(legit):', Math.log(model.predictionPriors?.legitimate ?? 0.46).toFixed(4));
console.log('Final log P(phish):', doc.logPhishing.toFixed(4));
console.log('Final log P(legit):', doc.logLegitimate.toFixed(4));
console.log('P(phish):', doc.probability.toFixed(4), '->', doc.probability >= 0.42 ? 'Phishing' : 'Legitimate');
console.log('');
console.log('Terms hurting doc-frequency NB most (positive logDelta favors legitimate):');
doc.terms.sort((a, b) => b.logDelta - a.logDelta).slice(0, 10).forEach((t) => console.log(t));
console.log('');
console.log('=== CORRECT multinomial NB using classTokenCounts ===');
console.log('P(phish):', multi.probability.toFixed(4), '->', multi.probability >= 0.42 ? 'Phishing' : 'Legitimate');

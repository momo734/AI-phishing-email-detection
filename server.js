import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { existsSync, readFileSync, readdirSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const PORT = Number(process.env.PORT || 5001);
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_for_production';
const MAX_TRAINING_ROWS = Number(process.env.MAX_TRAINING_ROWS || 5000);
const ML_RANDOM_SEED = Number(process.env.ML_RANDOM_SEED || 42);
const LR_EPOCHS = Number(process.env.LR_EPOCHS || 20);
const LR_LEARNING_RATE = Number(process.env.LR_LEARNING_RATE || 0.05);
const LR_L2_REG = Number(process.env.LR_L2_REG || 0.01);
const MIN_TERM_DOC_FREQUENCY = Number(process.env.MIN_TERM_DF || 2);
const MIN_BIGRAM_CLASS_DOC_FREQUENCY = Number(process.env.MIN_BIGRAM_CLASS_DF || 15);
const MAX_WEIGHT_ABS = Number(process.env.MAX_WEIGHT_ABS || 2);
const PHISHING_CLASS_WEIGHT = Number(process.env.PHISHING_CLASS_WEIGHT || 1);
const __dirname = dirname(fileURLToPath(import.meta.url));

const PHISHING_KEYWORDS = new Set([
  'verify', 'password', 'account', 'login', 'urgent', 'click', 'security',
  'payment', 'suspended', 'bank', 'microsoft', 'paypal', 'invoice',
  'billing', 'confirm', 'update', 'hours',
]);

const PHISHING_PHRASE_TOKENS = [
  ['within 24 hours', 'within24hours'],
  ['24 hours', '24hours'],
  ['act now', 'actnow'],
  ['click here', 'clickhere'],
  ['verify your', 'verifyyour'],
  ['confirm your', 'confirmyour'],
  ['account suspended', 'accountsuspended'],
  ['security alert', 'securityalert'],
  ['payment failed', 'paymentfailed'],
];

const DEFAULT_DECISION_THRESHOLDS = {
  logistic_regression: 0.48,
  naive_bayes: 0.42,
};

let randomState = ML_RANDOM_SEED;

function seededRandom() {
  randomState = (randomState * 16807) % 2147483647;
  return (randomState - 1) / 2147483646;
}

function resetRandomSeed() {
  randomState = ML_RANDOM_SEED;
}

app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:5175',
    'http://127.0.0.1:5175',
    'http://localhost:5176',
    'http://127.0.0.1:5176',
  ],
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '1mb' }));

const db = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3307),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'phishing_detector',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
let databaseReady = false;

const fallbackDataset = [
  { label: 'phishing', text: 'urgent verify your account password click login bank suspend security update winner free' },
  { label: 'phishing', text: 'your account will be suspended verify password immediately click secure login' },
  { label: 'phishing', text: 'winner claim free reward urgent bank transfer confirm account' },
  { label: 'phishing', text: 'security alert update your login password now click this link' },
  { label: 'phishing', text: 'payment failed verify banking details account suspended urgent click confirm login within 24 hours' },
  { label: 'phishing', text: 'urgent billing update verify your password account security suspended click here confirm within 24 hours bank login' },
  { label: 'legitimate', text: 'team meeting schedule project update agenda attached tomorrow' },
  { label: 'legitimate', text: 'invoice received monthly report available for review' },
  { label: 'legitimate', text: 'hello please find the document from our discussion' },
  { label: 'legitimate', text: 'your order has shipped tracking number delivery update' },
  { label: 'legitimate', text: 'company newsletter training reminder office announcement' },
  { label: 'legitimate', text: 'hello community members we hope you find this monthly newsletter helpful this edition covers new community features upcoming events and helpful resources thank you for being part of our community best regards the team' },
  { label: 'legitimate', text: 'monthly newsletter update helpful tips community highlights new features and upcoming events for all members' },
  { label: 'legitimate', text: 'welcome to our community newsletter with helpful guides product features and event announcements' },
  { label: 'legitimate', text: 'your weekly digest helpful articles community news and feature updates from our team' },
  { label: 'legitimate', text: 'your chase statement is ready please review your account ending billing details automated notification from bank security team' },
  { label: 'legitimate', text: 'monthly statement available for review account summary billing information attached thank you for banking with us' },
  { label: 'legitimate', text: 'your account statement is ready to view please review your billing details and payment summary online' },
];

const tokenize = (text) => String(text || '').toLowerCase().match(/[a-z0-9]+/g) || [];

const STOP_WORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'as', 'by',
  'is', 'it', 'be', 'are', 'was', 'were', 'been', 'has', 'have', 'had', 'do', 'does', 'did',
  'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those',
  'i', 'you', 'he', 'she', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your',
  'from', 'with', 'about', 'into', 'through', 'during', 'before', 'after', 'above', 'below',
  're', 'fw', 'fwd', 'sent', 'subject', 'date',
]);

function cleanEmailText(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/[\w.-]+@[\w.-]+\.\w+/gi, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isNoisyToken(term) {
  if (term.length > 30) return true;
  if (/^\d+$/.test(term)) return true;
  if (/^[a-f0-9]{10,}$/.test(term)) return true;
  return false;
}

function extractPhraseTokens(cleanedText) {
  const phraseTokens = [];
  PHISHING_PHRASE_TOKENS.forEach(([phrase, token]) => {
    if (cleanedText.includes(phrase)) {
      phraseTokens.push(token);
    }
  });
  return phraseTokens;
}

function tokenizeClean(text) {
  const cleaned = cleanEmailText(text);
  const words = cleaned
    .match(/[a-z0-9]+/g)
    ?.filter((term) => term.length > 1 && !STOP_WORDS.has(term) && !isNoisyToken(term)) || [];

  const bigrams = [];
  for (let index = 0; index < words.length - 1; index += 1) {
    const bigram = `${words[index]}__${words[index + 1]}`;
    if (bigram.length <= 48) bigrams.push(bigram);
  }

  return [...words, ...bigrams];
}

function countPhishingKeywordHits(tokens) {
  let hits = 0;
  tokens.forEach((token) => {
    if (PHISHING_KEYWORDS.has(token)) hits += 1;
    if (token.includes('24hours') || token.includes('accountsuspended') || token.includes('securityalert')) {
      hits += 1;
    }
  });
  return hits;
}

function dedupeRows(rows) {
  const seen = new Set();
  return rows.filter((row) => {
    const key = cleanEmailText(row.text).slice(0, 400);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function splitTrainTest(rows, testRatio = 0.2) {
  const shuffled = shuffleArray(rows);
  const testSize = Math.max(100, Math.floor(shuffled.length * testRatio));
  return {
    test: shuffled.slice(0, testSize),
    train: shuffled.slice(testSize),
  };
}

function buildBalancedTrainingSet(rows, perClassLimit) {
  const phishingRows = shuffleArray(rows.filter((row) => row.label === 'phishing'));
  const legitimateRows = shuffleArray(rows.filter((row) => row.label === 'legitimate'));
  const limit = Math.min(perClassLimit, phishingRows.length, legitimateRows.length);

  const legitimateNewsletters = shuffleArray(
    legitimateRows.filter((row) => /\b(newsletter|community|helpful|features)\b/i.test(row.text)),
  ).slice(0, Math.min(300, limit));

  const legitimateNotifications = shuffleArray(
    legitimateRows.filter((row) => /\b(statement|billing|invoice|account|chase|bank)\b/i.test(row.text)),
  ).slice(0, Math.min(200, limit));

  return shuffleArray([
    ...phishingRows.slice(0, limit),
    ...legitimateRows.slice(0, limit),
    ...legitimateNewsletters,
    ...legitimateNotifications,
    ...fallbackDataset,
  ]);
}

function shuffleArray(items) {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(seededRandom() * (index + 1));
    [copy[index], copy[swapIndex]] = [copy[swapIndex], copy[index]];
  }
  return copy;
}

function selectDiscriminativeFeatures(docs, maxFeatures = 8000) {
  const phishingDocs = docs.filter((doc) => doc.label === 'phishing');
  const legitimateDocs = docs.filter((doc) => doc.label === 'legitimate');
  const phishRate = phishingDocs.length / docs.length;
  const legitRate = legitimateDocs.length / docs.length;
  const scores = new Map();

  docs.forEach((doc) => {
    new Set(doc.tokens).forEach((term) => {
      if (!scores.has(term)) {
        scores.set(term, { phishing: 0, legitimate: 0 });
      }
      scores.get(term)[doc.label] += 1;
    });
  });

  const entries = [...scores.entries()]
    .map(([term, counts]) => {
      const total = counts.phishing + counts.legitimate;
      const expectedPhishing = total * phishRate;
      const expectedLegitimate = total * legitRate;
      const chiSquare = expectedPhishing > 0 && expectedLegitimate > 0
        ? ((counts.phishing - expectedPhishing) ** 2 / expectedPhishing)
          + ((counts.legitimate - expectedLegitimate) ** 2 / expectedLegitimate)
        : 0;
      const phishAssoc = (counts.phishing / Math.max(total, 1)) - phishRate;
      return { term, counts, chiSquare, total, phishAssoc };
    })
    .filter(({ term, counts, total, phishAssoc }) => {
      if (term.includes('__')) {
        return counts.phishing >= MIN_BIGRAM_CLASS_DOC_FREQUENCY
          && counts.legitimate >= MIN_BIGRAM_CLASS_DOC_FREQUENCY;
      }
      if (total < MIN_TERM_DOC_FREQUENCY) return false;
      if (phishAssoc > 0) {
        const classBalance = Math.min(counts.phishing, counts.legitimate)
          / Math.max(counts.phishing, counts.legitimate);
        if (classBalance >= 0.25) return false;
      }
      return true;
    });

  const perSide = Math.floor(maxFeatures / 2);
  const phishingTerms = entries
    .filter(({ phishAssoc, chiSquare }) => phishAssoc > 0 && chiSquare > 0)
    .sort((a, b) => b.chiSquare - a.chiSquare)
    .slice(0, perSide)
    .map(({ term }) => term);

  const legitimateTerms = entries
    .filter(({ phishAssoc, chiSquare }) => phishAssoc < 0 && chiSquare > 0)
    .sort((a, b) => b.chiSquare - a.chiSquare)
    .slice(0, perSide)
    .map(({ term }) => term);

  const selected = new Set([...phishingTerms, ...legitimateTerms]);
  const remaining = entries
    .filter(({ term }) => !selected.has(term))
    .sort((a, b) => b.chiSquare - a.chiSquare)
    .slice(0, Math.max(0, maxFeatures - selected.size))
    .map(({ term }) => term);

  return [...selected, ...remaining].slice(0, maxFeatures);
}

const URGENCY_PHRASES = [
  'immediate action required',
  'act now',
  'urgent',
  'within 24 hours',
  'within 48 hours',
  'expires today',
  'time sensitive',
  'respond immediately',
  'do not delay',
  'as soon as possible',
  'limited time',
  'final notice',
  'last chance',
];

const FEAR_PHRASES = [
  'account blocked',
  'account suspended',
  'account locked',
  'verify immediately',
  'unauthorized access',
  'unusual activity',
  'security alert',
  'compromised',
  'payment failed',
  'legal action',
  'your account will be closed',
  'suspended permanently',
  'confirm your identity',
];

const CREDENTIAL_PHRASES = [
  'enter your password',
  'verify your password',
  'confirm your password',
  'verify your account',
  'confirm your login',
  'update your credentials',
  'provide your password',
  'reset your password',
  'verify password',
  'confirm password',
  'login now',
  'sign in to your account',
];

const FINANCIAL_PHRASES = [
  'payment failed',
  'billing details',
  'bank account',
  'credit card',
  'wire transfer',
  'invoice attached',
  'pay now',
  'refund pending',
  'update billing',
  'payment declined',
  'transaction failed',
];

const ACCOUNT_SUSPENSION_PHRASES = [
  'account suspended',
  'account blocked',
  'account locked',
  'account will be closed',
  'suspended permanently',
  'will be terminated',
  'access revoked',
  'unusual sign in',
];

const HIGHLIGHT_KEYWORDS = [
  'verify', 'login', 'password', 'account', 'payment', 'billing',
  'security', 'click', 'urgent', 'confirm', 'update',
];

const SUSPICIOUS_DOMAIN_KEYWORDS = [
  'login',
  'secure',
  'verify',
  'account',
  'bank',
  'paypal',
  'wallet',
  'signin',
  'update',
  'support',
  'amazon',
  'microsoft',
];

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractDomain(url) {
  try {
    const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`;
    return new URL(normalized).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function countPhraseHits(text, phrases) {
  const matches = findPhraseMatches(text, 'urgency', phrases, 'trigger');
  return matches.length;
}

function getSuspiciousUrls(text) {
  const urlPattern = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;
  const urls = text.match(urlPattern) || [];

  return urls.filter((url) => {
    const domain = extractDomain(url);
    if (!domain) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return true;
    if (SUSPICIOUS_DOMAIN_KEYWORDS.some((keyword) => domain.includes(keyword))) return true;
    return domain.split('.').length > 3;
  });
}

function countSuspiciousUrls(text) {
  return getSuspiciousUrls(text).length;
}

function findPhraseMatches(text, category, phrases, reason) {
  const matches = [];

  phrases.forEach((phrase) => {
    const regex = new RegExp(escapeRegex(phrase), 'gi');
    let match = regex.exec(text);

    while (match) {
      matches.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
        category,
        reason,
      });
      match = regex.exec(text);
    }
  });

  return matches;
}

function parseCsvRecords(content) {
  const records = [];
  let row = [];
  let current = '';
  let quoted = false;

  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    const next = content[index + 1];

    if (char === '"' && quoted && next === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === ',' && !quoted) {
      row.push(current.trim());
      current = '';
    } else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && next === '\n') {
        index += 1;
      }
      row.push(current.trim());
      if (row.some((value) => value !== '')) {
        records.push(row);
      }
      row = [];
      current = '';
    } else {
      current += char;
    }
  }

  row.push(current.trim());
  if (row.some((value) => value !== '')) {
    records.push(row);
  }

  return records;
}

const TEXT_COLUMN_ALIASES = new Set([
  'text', 'email', 'emailtext', 'body', 'message', 'content', 'textcombined',
]);
const LABEL_COLUMN_ALIASES = new Set([
  'label', 'class', 'category', 'target', 'emailtype', 'type',
]);

function normalizeCsvHeader(header) {
  return String(header || '').toLowerCase().replace(/[\s_-]/g, '');
}

function detectCsvColumns(headers) {
  const normalized = headers.map(normalizeCsvHeader);
  const labelIndex = normalized.findIndex((header) => LABEL_COLUMN_ALIASES.has(header));
  const subjectIndex = normalized.findIndex((header) => header === 'subject');
  const bodyIndex = normalized.findIndex((header) => TEXT_COLUMN_ALIASES.has(header) && header !== 'subject');

  return { normalized, labelIndex, subjectIndex, bodyIndex };
}

function extractEmailTextFromRow(columns, columnMap) {
  const parts = [];

  if (columnMap.subjectIndex >= 0 && columns[columnMap.subjectIndex]?.trim()) {
    parts.push(columns[columnMap.subjectIndex].trim());
  }

  if (columnMap.bodyIndex >= 0 && columns[columnMap.bodyIndex]?.trim()) {
    parts.push(columns[columnMap.bodyIndex].trim());
  }

  return parts.join(' ').trim();
}

function normalizeLabel(value) {
  const label = String(value || '').trim().toLowerCase();

  if (['1', 'true', 'yes', 'phishing', 'phish', 'phishing email', 'malicious', 'spam', 'fraud'].includes(label)) {
    return 'phishing';
  }

  if (['0', 'false', 'no', 'legitimate', 'legit', 'safe email', 'ham', 'safe', 'benign', 'normal'].includes(label)) {
    return 'legitimate';
  }

  return null;
}

function listDatasetCsvFiles() {
  const dataDir = join(__dirname, 'data');
  if (!existsSync(dataDir)) {
    return [];
  }

  return readdirSync(dataDir)
    .filter((name) => name.toLowerCase().endsWith('.csv'))
    .sort()
    .map((name) => join(dataDir, name));
}

function parseDatasetCsvFile(datasetPath) {
  const records = parseCsvRecords(readFileSync(datasetPath, 'utf8'));
  if (records.length < 2) {
    return { rows: [], skipped: { emptyFile: 1, missingColumns: 0, emptyText: 0, invalidLabel: 0 } };
  }

  const headers = records[0];
  const columnMap = detectCsvColumns(headers);

  if (columnMap.labelIndex === -1 || (columnMap.bodyIndex === -1 && columnMap.subjectIndex === -1)) {
    console.warn(`Skipping ${datasetPath}: could not detect text and label columns (${headers.join(', ')})`);
    return { rows: [], skipped: { emptyFile: 0, missingColumns: 1, emptyText: 0, invalidLabel: 0 } };
  }

  const rows = [];
  const skipped = { emptyFile: 0, missingColumns: 0, emptyText: 0, invalidLabel: 0 };

  records.slice(1).forEach((columns) => {
    const text = extractEmailTextFromRow(columns, columnMap);
    const label = normalizeLabel(columns[columnMap.labelIndex]);

    if (!text) {
      skipped.emptyText += 1;
      return;
    }

    if (!label) {
      skipped.invalidLabel += 1;
      return;
    }

    rows.push({ text, label, source: datasetPath });
  });

  return { rows, skipped };
}

function loadAllDatasets() {
  const datasetPaths = listDatasetCsvFiles();

  if (!datasetPaths.length) {
    console.log('No CSV files found in data/. Using the built-in small sample dataset.');
    const phishingRows = fallbackDataset.filter((row) => row.label === 'phishing');
    const legitimateRows = fallbackDataset.filter((row) => row.label === 'legitimate');
    return {
      rows: fallbackDataset,
      stats: {
        source: 'fallback',
        files: [],
        totalRows: fallbackDataset.length,
        legitimate: legitimateRows.length,
        phishing: phishingRows.length,
        duplicatesRemoved: 0,
        emptyEmailsRemoved: 0,
        invalidLabelsRemoved: 0,
        filesSkipped: 0,
      },
    };
  }

  const mergedRows = [];
  const fileStats = [];
  let emptyEmailsRemoved = 0;
  let invalidLabelsRemoved = 0;
  let filesSkipped = 0;

  datasetPaths.forEach((datasetPath) => {
    const { rows, skipped } = parseDatasetCsvFile(datasetPath);
    emptyEmailsRemoved += skipped.emptyText;
    invalidLabelsRemoved += skipped.invalidLabel;
    filesSkipped += skipped.missingColumns + skipped.emptyFile;

    if (!rows.length) {
      return;
    }

    mergedRows.push(...rows);
    fileStats.push({
      file: datasetPath.split(/[\\/]/).pop(),
      rows: rows.length,
      phishing: rows.filter((row) => row.label === 'phishing').length,
      legitimate: rows.filter((row) => row.label === 'legitimate').length,
    });
  });

  const rawCount = mergedRows.length;
  const rows = dedupeRows(mergedRows.map(({ text, label }) => ({ text, label })));
  const duplicateCount = rawCount - rows.length;
  const phishingRows = rows.filter((row) => row.label === 'phishing');
  const legitimateRows = rows.filter((row) => row.label === 'legitimate');
  const hasBothClasses = phishingRows.length > 0 && legitimateRows.length > 0;

  if (!rows.length || !hasBothClasses) {
    console.log('Combined dataset is empty or missing one class. Using the built-in sample dataset.');
    return {
      rows: fallbackDataset,
      stats: {
        source: 'fallback',
        files: fileStats,
        totalRows: fallbackDataset.length,
        legitimate: fallbackDataset.filter((row) => row.label === 'legitimate').length,
        phishing: fallbackDataset.filter((row) => row.label === 'phishing').length,
        duplicatesRemoved: duplicateCount,
        emptyEmailsRemoved,
        invalidLabelsRemoved,
        filesSkipped,
      },
    };
  }

  console.log(`Loaded ${rows.length} unique emails from ${fileStats.length} CSV file(s) in data/`);
  fileStats.forEach(({ file, rows: count, phishing, legitimate }) => {
    console.log(`  - ${file}: ${count} rows (phishing: ${phishing}, legitimate: ${legitimate})`);
  });
  console.log(`Combined class balance -> legitimate: ${legitimateRows.length}, phishing: ${phishingRows.length}`);
  console.log(`Removed -> duplicates: ${duplicateCount}, empty: ${emptyEmailsRemoved}, invalid labels: ${invalidLabelsRemoved}, skipped files: ${filesSkipped}`);

  return {
    rows,
    stats: {
      source: 'combined',
      files: fileStats,
      totalRows: rows.length,
      legitimate: legitimateRows.length,
      phishing: phishingRows.length,
      duplicatesRemoved: duplicateCount,
      emptyEmailsRemoved,
      invalidLabelsRemoved,
      filesSkipped,
    },
  };
}

function trainDatasetModel(trainRows, testRows = []) {
  resetRandomSeed();
  const trainingStartedAt = Date.now();
  const allDocs = trainRows.map((row) => ({ ...row, tokens: tokenizeClean(row.text) }));
  const shuffledTrainDocs = shuffleArray(allDocs);
  const valSize = Math.max(200, Math.floor(shuffledTrainDocs.length * 0.15));
  const validationDocs = shuffledTrainDocs.slice(0, valSize);
  const trainDocs = shuffledTrainDocs.slice(valSize);

  console.log(`Training split -> core train: ${trainDocs.length}, validation: ${validationDocs.length}, vocabulary source: training set only`);
  console.log('Selecting discriminative features and building TF-IDF vocabulary...');

  const selectedVocabulary = selectDiscriminativeFeatures(trainDocs);
  const vocabularySet = new Set(selectedVocabulary);
  const selectedWithKeywords = [...vocabularySet];

  const totalDocs = trainDocs.length;
  const documentFrequency = {};
  const idf = {};

  trainDocs.forEach((doc) => {
    new Set(doc.tokens.filter((term) => vocabularySet.has(term))).forEach((term) => {
      documentFrequency[term] = (documentFrequency[term] || 0) + 1;
    });
  });

  selectedWithKeywords.forEach((term) => {
    const df = documentFrequency[term] || 0;
    idf[term] = Math.log((totalDocs + 1) / (df + 1)) + 1;
  });

  console.log(`TF-IDF vocabulary size: ${selectedWithKeywords.length}`);

  const classDocs = {
    phishing: trainDocs.filter((doc) => doc.label === 'phishing'),
    legitimate: trainDocs.filter((doc) => doc.label === 'legitimate'),
  };

  console.log(`Empirical class priors -> phishing: ${(classDocs.phishing.length / totalDocs).toFixed(4)}, legitimate: ${(classDocs.legitimate.length / totalDocs).toFixed(4)}`);
  console.log('Training Logistic Regression...');

  const logisticModel = trainLogisticRegression(trainDocs, idf, vocabularySet);
  console.log(`Logistic Regression bias: ${logisticModel.bias.toFixed(4)} (prior log-odds: ${Math.log((classDocs.phishing.length / totalDocs) / (classDocs.legitimate.length / totalDocs)).toFixed(4)})`);
  console.log('Training Naive Bayes...');
  const naiveBayesModel = trainNaiveBayes(trainDocs, vocabularySet);

  const model = {
    vocabulary: selectedWithKeywords,
    idf,
    classPriors: {
      phishing: classDocs.phishing.length / totalDocs,
      legitimate: classDocs.legitimate.length / totalDocs,
    },
    predictionPriors: naiveBayesModel.predictionPriors,
    classTokenCounts: naiveBayesModel.classTokenCounts,
    termDocCounts: naiveBayesModel.termDocCounts,
    totalClassTokens: naiveBayesModel.totalClassTokens,
    classDocCounts: naiveBayesModel.classDocCounts,
    naiveBayes: naiveBayesModel.config,
    logisticWeights: logisticModel.weights,
    logisticBias: logisticModel.bias,
    logisticClassPrior: logisticModel.classPrior,
    trainingConfig: {
      epochs: LR_EPOCHS,
      learningRate: LR_LEARNING_RATE,
      l2Regularization: LR_L2_REG,
      randomSeed: ML_RANDOM_SEED,
      phishingClassWeight: PHISHING_CLASS_WEIGHT,
    },
  };

  model.decisionThresholds = calibrateDecisionThresholds(model, validationDocs);
  console.log('Validation decision thresholds:', model.decisionThresholds);

  const trainingTimeMs = Date.now() - trainingStartedAt;
  model.trainingMeta = {
    trainingRows: trainDocs.length,
    validationRows: validationDocs.length,
    testRows: testRows.length,
    vocabularySize: selectedWithKeywords.length,
    trainingTimeMs,
    trainingTimeSeconds: Number((trainingTimeMs / 1000).toFixed(2)),
  };

  return model;
}

function clipWeight(value) {
  return Math.max(-MAX_WEIGHT_ABS, Math.min(MAX_WEIGHT_ABS, value));
}

function trainLogisticRegression(
  docs,
  idf,
  vocabularySet,
  epochs = LR_EPOCHS,
  learningRate = LR_LEARNING_RATE,
  l2 = LR_L2_REG,
) {
  const weights = {};
  const phishingDocCount = docs.filter((doc) => doc.label === 'phishing').length;
  const classPrior = phishingDocCount / Math.max(docs.length, 1);
  let bias = Math.log(Math.max(classPrior, 1e-6) / Math.max(1 - classPrior, 1e-6));

  vocabularySet.forEach((term) => {
    weights[term] = (seededRandom() - 0.5) * 0.02;
  });

  for (let epoch = 0; epoch < epochs; epoch += 1) {
    shuffleArray(docs).forEach((doc) => {
      const vector = buildTfIdfVector(doc.tokens, idf, vocabularySet);
      const target = doc.label === 'phishing' ? 1 : 0;
      const classWeight = target === 1 ? PHISHING_CLASS_WEIGHT : 1;
      const linearScore = bias + Object.entries(vector).reduce(
        (sum, [term, value]) => sum + value * (weights[term] || 0),
        0,
      );
      const prediction = sigmoid(linearScore);
      const error = (prediction - target) * classWeight;

      bias -= learningRate * error;
      Object.entries(vector).forEach(([term, value]) => {
        if (weights[term] === undefined) weights[term] = 0;
        weights[term] = clipWeight(
          weights[term] - learningRate * (error * value + l2 * weights[term]),
        );
      });
    });

    if ((epoch + 1) % 10 === 0 || epoch + 1 === epochs) {
      console.log(`  LR epoch ${epoch + 1}/${epochs} — bias=${bias.toFixed(4)}`);
    }
  }

  return { weights, bias, classPrior: Number(classPrior.toFixed(4)) };
}

function buildTfIdfVector(tokens, idf, vocabularySet = null) {
  const filtered = [];
  tokens.forEach((token) => {
    if (vocabularySet && !vocabularySet.has(token)) return;
    filtered.push(token);
  });

  if (filtered.length === 0) return {};

  const counts = {};
  filtered.forEach((token) => {
    counts[token] = (counts[token] || 0) + 1;
  });

  const maxCount = Math.max(...Object.values(counts));
  const totalTokens = filtered.length;
  const lengthNorm = Math.sqrt(totalTokens) || 1;

  return Object.fromEntries(
    Object.entries(counts)
      .filter(([term]) => idf[term])
      .map(([term, count]) => {
        const sublinearTf = 1 + Math.log(count);
        const normalizedTf = sublinearTf / (1 + Math.log(maxCount));
        const tfidf = (normalizedTf * idf[term]) / lengthNorm;
        return [term, tfidf];
      }),
  );
}

function predictLogisticRegression(tokens, model) {
  const vector = buildTfIdfVector(tokens, model.idf, new Set(model.vocabulary));
  const linearScore = model.logisticBias + Object.entries(vector).reduce(
    (sum, [term, value]) => sum + value * (model.logisticWeights[term] || 0),
    0,
  );
  const probability = sigmoid(linearScore);
  return {
    probability,
    linearScore: Number(linearScore.toFixed(4)),
    vector,
  };
}

function trainNaiveBayes(trainDocs, vocabularySet) {
  const classTokenCounts = { phishing: {}, legitimate: {} };
  const termDocCounts = { phishing: {}, legitimate: {} };
  const totalClassTokens = { phishing: 0, legitimate: 0 };
  const classDocCounts = {
    phishing: trainDocs.filter((doc) => doc.label === 'phishing').length,
    legitimate: trainDocs.filter((doc) => doc.label === 'legitimate').length,
  };

  trainDocs.forEach((doc) => {
    const uniqueTerms = new Set(doc.tokens.filter((term) => vocabularySet.has(term)));
    uniqueTerms.forEach((term) => {
      termDocCounts[doc.label][term] = (termDocCounts[doc.label][term] || 0) + 1;
    });

    doc.tokens.forEach((token) => {
      if (!vocabularySet.has(token)) return;
      classTokenCounts[doc.label][token] = (classTokenCounts[doc.label][token] || 0) + 1;
      totalClassTokens[doc.label] += 1;
    });
  });

  const totalDocs = classDocCounts.phishing + classDocCounts.legitimate;
  const phishingPrior = classDocCounts.phishing / Math.max(totalDocs, 1);
  const legitimatePrior = classDocCounts.legitimate / Math.max(totalDocs, 1);

  return {
    classTokenCounts,
    termDocCounts,
    totalClassTokens,
    classDocCounts,
    predictionPriors: {
      phishing: Number(phishingPrior.toFixed(6)),
      legitimate: Number(legitimatePrior.toFixed(6)),
    },
    config: {
      alpha: 0.5,
      modelType: 'multinomial',
      inferenceTokenWeight: 'sublinear',
    },
  };
}

function predictNaiveBayes(tokens, model) {
  const vocabularySet = new Set(model.vocabulary);
  const termCounts = {};
  tokens.forEach((token) => {
    if (!vocabularySet.has(token)) return;
    termCounts[token] = (termCounts[token] || 0) + 1;
  });

  const vocabularySize = model.vocabulary.length;
  const alpha = model.naiveBayes?.alpha ?? 0.5;
  const phishPrior = model.predictionPriors?.phishing ?? model.classPriors.phishing;
  const legitPrior = model.predictionPriors?.legitimate ?? model.classPriors.legitimate;

  // Prior: log P(c)
  let logPhishing = Math.log(Math.max(phishPrior, 1e-6));
  let logLegitimate = Math.log(Math.max(legitPrior, 1e-6));

  // Multinomial NB with Laplace smoothing and sublinear term weighting at inference
  // so repeated benign words (e.g. "account" in a statement email) do not dominate.
  Object.entries(termCounts).forEach(([term, count]) => {
    const phishTokenCount = model.classTokenCounts.phishing[term] || 0;
    const legitTokenCount = model.classTokenCounts.legitimate[term] || 0;
    const phishConditional = (phishTokenCount + alpha)
      / (model.totalClassTokens.phishing + alpha * vocabularySize);
    const legitConditional = (legitTokenCount + alpha)
      / (model.totalClassTokens.legitimate + alpha * vocabularySize);
    const effectiveCount = 1 + Math.log(count);
    logPhishing += effectiveCount * Math.log(Math.max(phishConditional, 1e-9));
    logLegitimate += effectiveCount * Math.log(Math.max(legitConditional, 1e-9));
  });

  // Stable normalization: P(phish) = exp(lp) / (exp(lp) + exp(ll))
  const maxLog = Math.max(logPhishing, logLegitimate);
  const phishExp = Math.exp(logPhishing - maxLog);
  const legitExp = Math.exp(logLegitimate - maxLog);
  const probability = phishExp / (phishExp + legitExp);

  return {
    probability,
    matchedTerms: Object.keys(termCounts),
    termCounts,
    logPhishing: Number(logPhishing.toFixed(4)),
    logLegitimate: Number(logLegitimate.toFixed(4)),
  };
}

function findOptimalThreshold(probabilities, labels) {
  let bestThreshold = 0.5;
  let bestScore = -1;

  for (let threshold = 0.32; threshold <= 0.52; threshold += 0.01) {
    let tp = 0;
    let fp = 0;
    let fn = 0;

    probabilities.forEach((probability, index) => {
      const predicted = probability >= threshold ? 1 : 0;
      const actual = labels[index];
      if (predicted === 1 && actual === 1) tp += 1;
      else if (predicted === 1 && actual === 0) fp += 1;
      else if (predicted === 0 && actual === 1) fn += 1;
    });

    const recall = tp / (tp + fn || 1);
    const precision = tp / (tp + fp || 1);
    const f1 = (2 * precision * recall) / (precision + recall || 1);

    if (recall >= 0.9 && f1 >= bestScore) {
      bestScore = f1;
      bestThreshold = threshold;
    }
  }

  return Number(bestThreshold.toFixed(2));
}

function calibrateDecisionThresholds(model, validationDocs) {
  const lrProbabilities = [];
  const nbProbabilities = [];
  const labels = [];

  validationDocs.forEach((doc) => {
    labels.push(doc.label === 'phishing' ? 1 : 0);
    lrProbabilities.push(predictLogisticRegression(doc.tokens, model).probability);
    nbProbabilities.push(predictNaiveBayes(doc.tokens, model).probability);
  });

  return {
    logistic_regression: findOptimalThreshold(lrProbabilities, labels),
    naive_bayes: findOptimalThreshold(nbProbabilities, labels),
  };
}

function getDecisionThreshold(model, modelType) {
  return model.decisionThresholds?.[modelType] ?? DEFAULT_DECISION_THRESHOLDS[modelType] ?? 0.5;
}

function applyLowCoverageBoost(mlProbability, tokens, matchedFeatures, totalTokens) {
  const keywordHits = countPhishingKeywordHits(tokens);
  const coverage = matchedFeatures / Math.max(totalTokens, 1);
  let boost = 0;

  if (coverage < 0.12) {
    boost += 0.05;
  }
  if (matchedFeatures === 0 && keywordHits > 0) {
    boost += Math.min(0.2, keywordHits * 0.05);
  }
  if (keywordHits >= 3) {
    boost += Math.min(0.12, keywordHits * 0.03);
  }

  return Math.min(0.9999, mlProbability + boost);
}

const datasetLoadResult = loadAllDatasets();
const MODEL_CACHE_PATH = join(__dirname, 'data', '.model-cache.json');
const MODEL_CACHE_VERSION = 13;

function buildModelFingerprint() {
  const datasetPaths = listDatasetCsvFiles();
  if (!datasetPaths.length) {
    return `${MODEL_CACHE_VERSION}:fallback:${ML_RANDOM_SEED}`;
  }

  const fileSignature = datasetPaths
    .map((datasetPath) => {
      const stat = statSync(datasetPath);
      const fileName = datasetPath.split(/[\\/]/).pop();
      return `${fileName}:${stat.size}:${stat.mtimeMs}`;
    })
    .join('|');

  return `${MODEL_CACHE_VERSION}:${fileSignature}:${ML_RANDOM_SEED}`;
}

function loadModelCache(fingerprint) {
  if (!existsSync(MODEL_CACHE_PATH)) {
    return null;
  }

  try {
    const cache = JSON.parse(readFileSync(MODEL_CACHE_PATH, 'utf8'));
    if (cache.fingerprint === fingerprint) {
      return cache.model;
    }
  } catch {
    return null;
  }

  return null;
}

function saveModelCache(fingerprint, model) {
  writeFileSync(MODEL_CACHE_PATH, JSON.stringify({ fingerprint, model }), 'utf8');
}

function printTrainingReport(datasetStats, model, evaluation, trainingTimeMs) {
  console.log('\n=== ML Training Complete ===');
  console.log(`Total emails: ${datasetStats.totalRows}`);
  console.log(`Phishing emails: ${datasetStats.phishing}`);
  console.log(`Legitimate emails: ${datasetStats.legitimate}`);
  console.log(`Vocabulary size: ${model.vocabulary.length}`);
  console.log(`LR intercept (bias): ${model.logisticBias?.toFixed(4) ?? 'n/a'}`);
  console.log(`LR class prior (training): ${model.logisticClassPrior ?? 'n/a'}`);
  console.log(`NB priors (data-driven): phishing=${model.predictionPriors?.phishing}, legitimate=${model.predictionPriors?.legitimate}`);
  console.log(`PHISHING_CLASS_WEIGHT: ${model.trainingConfig?.phishingClassWeight ?? PHISHING_CLASS_WEIGHT}`);
  console.log(`Training time: ${(trainingTimeMs / 1000).toFixed(2)}s`);
  console.log(`Train rows used: ${model.trainingMeta?.trainingRows ?? 'n/a'} | Validation rows: ${model.trainingMeta?.validationRows ?? 'n/a'} | Test rows: ${evaluation.sampleSize}`);

  ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
    const metrics = evaluation[modelType];
    console.log(`\n=== Test set (${modelType.replace('_', ' ')}) ===`);
    console.log(`Accuracy: ${metrics.accuracy}%`);
    console.log(`Precision: ${metrics.precision}%`);
    console.log(`Recall: ${metrics.recall}%`);
    console.log(`F1-score: ${metrics.f1}%`);
    console.log(`ROC-AUC: ${metrics.rocAuc}`);
    console.log(`Confusion Matrix: ${JSON.stringify(metrics.confusionMatrix)}`);
  });

  if (evaluation.errorAnalysis) {
    console.log('\n=== Holdout error analysis ===');
    ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
      const errors = evaluation.errorAnalysis[modelType];
      console.log(`\n${modelType} false positives: ${errors.falsePositives.length}`);
      errors.falsePositives.slice(0, 5).forEach((sample, index) => {
        console.log(`  FP ${index + 1}: prob=${sample.probability} | ${sample.preview}`);
      });
      console.log(`${modelType} false negatives: ${errors.falseNegatives.length}`);
      errors.falseNegatives.slice(0, 5).forEach((sample, index) => {
        console.log(`  FN ${index + 1}: prob=${sample.probability} | ${sample.preview}`);
      });
    });
  }

  if (evaluation.diverseValidation) {
    console.log('\n=== Diverse validation set ===');
    ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
      const summary = evaluation.diverseValidation[modelType];
      console.log(`\n${modelType}: ${summary.correct}/${summary.total} correct (${summary.accuracy}%)`);
      summary.results.forEach((row) => {
        const mark = row.correct ? 'OK' : 'MISS';
        console.log(`  [${mark}] ${row.category} | expected=${row.expected} | prob=${row.probability} | ${row.verdict}`);
      });
    });
  }
  console.log('');
}

function initializeMlModels() {
  resetRandomSeed();
  const fingerprint = buildModelFingerprint();
  const cachedModel = loadModelCache(fingerprint);

  if (cachedModel) {
    console.log('Loaded trained ML model from cache.');
    return {
      trainedModel: cachedModel,
      holdoutTestSet: [],
      trainingRows: [],
      datasetStats: datasetLoadResult.stats,
      fromCache: true,
    };
  }

  const combinedRows = shuffleArray(datasetLoadResult.rows);
  const { train: trainingRows, test: holdoutTestSet } = splitTrainTest(combinedRows, 0.2);
  console.log(`Shuffled 80/20 split -> training: ${trainingRows.length}, testing: ${holdoutTestSet.length}`);
  const trainingStartedAt = Date.now();
  const trainedModel = trainDatasetModel(trainingRows, holdoutTestSet);
  const testDocs = holdoutTestSet.map((row) => ({ ...row, tokens: tokenizeClean(row.text) }));
  const evaluation = evaluateModelHoldout(testDocs, trainedModel);
  const trainingTimeMs = Date.now() - trainingStartedAt;

  trainedModel.trainingMeta = {
    ...trainedModel.trainingMeta,
    totalTrainingPipelineMs: trainingTimeMs,
    totalTrainingPipelineSeconds: Number((trainingTimeMs / 1000).toFixed(2)),
  };

  saveModelCache(fingerprint, trainedModel);
  printTrainingReport(datasetLoadResult.stats, trainedModel, evaluation, trainingTimeMs);
  console.log(`Saved refreshed model cache to ${MODEL_CACHE_PATH}`);

  return {
    trainedModel,
    holdoutTestSet,
    trainingRows,
    datasetStats: datasetLoadResult.stats,
    fromCache: false,
  };
}

let trainedModel = null;
let holdoutTestSet = [];
let trainingRows = [];
let mlModelFromCache = false;
let mlReady = false;

const mlBootstrapPromise = new Promise((resolve, reject) => {
  setImmediate(() => {
    try {
      const result = initializeMlModels();
      trainedModel = result.trainedModel;
      holdoutTestSet = result.holdoutTestSet;
      trainingRows = result.trainingRows;
      mlModelFromCache = result.fromCache;
      mlReady = true;
      console.log(`Training rows: ${trainingRows.length || 'cached'} | Holdout test rows: ${holdoutTestSet.length || 'skipped'}`);
      resolve(result);
    } catch (error) {
      reject(error);
    }
  });
});

async function ensureModelReady() {
  await mlBootstrapPromise;
  if (!trainedModel) {
    throw new Error('ML model failed to load.');
  }
}

function runHoldoutEvaluation() {
  if (!holdoutTestSet.length) return;

  console.log('Running holdout evaluation in background...');
  const testDocs = holdoutTestSet.map((row) => ({ ...row, tokens: tokenizeClean(row.text) }));
  const evaluation = evaluateModelHoldout(testDocs);
  console.log(`LR config: epochs=${LR_EPOCHS}, lr=${LR_LEARNING_RATE}, l2=${LR_L2_REG}, seed=${ML_RANDOM_SEED}`);
  console.log('Label mapping -> 0: Legitimate, 1: Phishing');
  console.log('=== Holdout evaluation: Logistic Regression ===');
  console.log(JSON.stringify(evaluation.logistic_regression, null, 2));
  console.log('=== Holdout evaluation: Naive Bayes ===');
  console.log(JSON.stringify(evaluation.naive_bayes, null, 2));
}

function sigmoid(value) {
  if (value >= 0) {
    const z = Math.exp(-value);
    return 1 / (1 + z);
  }
  const z = Math.exp(value);
  return z / (1 + z);
}

function computeRocAuc(scores, labels) {
  const pairs = scores.map((score, index) => ({ score, label: labels[index] }));
  pairs.sort((a, b) => b.score - a.score);

  let tp = 0;
  let auc = 0;
  const totalPositive = labels.filter((label) => label === 1).length;
  const totalNegative = labels.length - totalPositive;

  if (totalPositive === 0 || totalNegative === 0) return 0.5;

  pairs.forEach(({ label }) => {
    if (label === 1) tp += 1;
    else auc += tp;
  });

  return Number((auc / (totalPositive * totalNegative)).toFixed(4));
}

const DIVERSE_VALIDATION_SAMPLES = [
  {
    category: 'banking',
    label: 'legitimate',
    text: 'Subject: Your Monthly Account Statement is Ready\n\nDear Customer,\n\nYour monthly account statement for your online banking account is now available.\n\nPlease log in to your bank account through our official website or mobile app to view your statement.\n\nIf you have any questions, contact customer support.\n\nThank you for banking with us.',
  },
  {
    category: 'shopping',
    label: 'legitimate',
    text: 'Subject: Your order has shipped\n\nHi Alex,\n\nGood news — your order #48291 has shipped and is on the way.\n\nEstimated delivery: Tuesday, March 12.\n\nTrack your package from your account dashboard.\n\nThanks for shopping with us.',
  },
  {
    category: 'university',
    label: 'legitimate',
    text: 'Subject: Fall registration opens next week\n\nDear students,\n\nCourse registration for the fall semester opens Monday at 8 AM.\n\nPlease meet with your academic advisor before selecting classes.\n\nVisit the registrar website for the full schedule.\n\nUniversity Office of the Registrar',
  },
  {
    category: 'hr',
    label: 'legitimate',
    text: 'Subject: Benefits enrollment reminder\n\nHello team,\n\nThis is a reminder that open enrollment for health and dental benefits closes Friday.\n\nReview the HR portal for plan details and submit your selections.\n\nContact HR support if you need assistance.\n\nPeople Operations',
  },
  {
    category: 'shipping',
    label: 'legitimate',
    text: 'Subject: Delivery update for package 1Z999\n\nYour package is out for delivery today.\n\nDelivery address on file will be used. You can manage delivery preferences in the shipping app.\n\nThank you.',
  },
  {
    category: 'meeting',
    label: 'legitimate',
    text: 'Subject: Project sync tomorrow\n\nHi everyone,\n\nLet us meet tomorrow at 10 AM to review the roadmap and sprint backlog.\n\nAgenda attached. Please bring status updates from your teams.\n\nThanks,\nJordan',
  },
  {
    category: 'password_change',
    label: 'legitimate',
    text: 'Subject: Password changed successfully\n\nHello,\n\nThis confirms that the password for your account was changed successfully.\n\nIf you did not make this change, contact support immediately through the official help center.\n\nSecurity Team',
  },
  {
    category: 'newsletter',
    label: 'legitimate',
    text: 'Subject: Weekly community newsletter\n\nHello members,\n\nWelcome to this week\'s newsletter with product updates, community highlights, and upcoming events.\n\nWe hope you enjoy this edition.\n\nBest regards,\nThe Team',
  },
  {
    category: 'real_phishing',
    label: 'phishing',
    text: 'URGENT: Your account blocked. Immediate action required. Verify your password at http://secure-login-verify.xyz/update within 24 hours or your account will be suspended.',
  },
  {
    category: 'fake_invoice',
    label: 'phishing',
    text: 'Subject: Invoice overdue — payment required today\n\nDear customer,\n\nYour invoice is overdue. Open the attached document and confirm payment immediately to avoid service interruption.\n\nPay now using the link below.',
  },
  {
    category: 'credential_theft',
    label: 'phishing',
    text: 'Security alert: unusual sign-in detected. Confirm your login credentials now at http://account-verify-security.xyz/signin to restore access to your account.',
  },
];

function previewEmailText(text, maxLength = 120) {
  return cleanEmailText(text).slice(0, maxLength);
}

function predictRawProbability(tokens, model, modelType) {
  return modelType === 'naive_bayes'
    ? predictNaiveBayes(tokens, model).probability
    : predictLogisticRegression(tokens, model).probability;
}

function analyzeHoldoutErrors(docs, model) {
  const analysis = {
    logistic_regression: { falsePositives: [], falseNegatives: [] },
    naive_bayes: { falsePositives: [], falseNegatives: [] },
  };

  docs.forEach((doc) => {
    const expectedPhishing = doc.label === 'phishing';

    ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
      const probability = predictRawProbability(doc.tokens, model, modelType);
      const threshold = getDecisionThreshold(model, modelType);
      const predictedPhishing = probability >= threshold;
      const bucket = analysis[modelType];
      const sample = {
        probability: Number(probability.toFixed(4)),
        threshold,
        preview: previewEmailText(doc.text),
      };

      if (!expectedPhishing && predictedPhishing) {
        bucket.falsePositives.push(sample);
      } else if (expectedPhishing && !predictedPhishing) {
        bucket.falseNegatives.push(sample);
      }
    });
  });

  return analysis;
}

function evaluateDiverseValidationSet(model) {
  const resultsByModel = {
    logistic_regression: { total: 0, correct: 0, results: [] },
    naive_bayes: { total: 0, correct: 0, results: [] },
  };

  DIVERSE_VALIDATION_SAMPLES.forEach((sample) => {
    const tokens = tokenizeClean(sample.text);
    const expectedPhishing = sample.label === 'phishing';

    ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
      const probability = predictRawProbability(tokens, model, modelType);
      const threshold = getDecisionThreshold(model, modelType);
      const predictedPhishing = probability >= threshold;
      const correct = predictedPhishing === expectedPhishing;
      const bucket = resultsByModel[modelType];

      bucket.total += 1;
      if (correct) bucket.correct += 1;
      bucket.results.push({
        category: sample.category,
        expected: sample.label,
        probability: Number(probability.toFixed(4)),
        threshold,
        verdict: predictedPhishing ? 'Phishing' : 'Legitimate',
        correct,
      });
    });
  });

  return {
    logistic_regression: {
      ...resultsByModel.logistic_regression,
      accuracy: Number(((resultsByModel.logistic_regression.correct / resultsByModel.logistic_regression.total) * 100).toFixed(2)),
    },
    naive_bayes: {
      ...resultsByModel.naive_bayes,
      accuracy: Number(((resultsByModel.naive_bayes.correct / resultsByModel.naive_bayes.total) * 100).toFixed(2)),
    },
  };
}

function evaluateModelHoldout(docs, model = trainedModel) {
  const previousModel = trainedModel;
  trainedModel = model;

  try {
    const metrics = {
      logistic_regression: { tp: 0, tn: 0, fp: 0, fn: 0, probabilities: [], labels: [] },
      naive_bayes: { tp: 0, tn: 0, fp: 0, fn: 0, probabilities: [], labels: [] },
    };

    docs.forEach((doc) => {
      const expectedLabel = doc.label === 'phishing' ? 1 : 0;

      ['logistic_regression', 'naive_bayes'].forEach((modelType) => {
        const probability = predictRawProbability(doc.tokens, model, modelType);
        const threshold = getDecisionThreshold(model, modelType);
        const predictedPhishing = probability >= threshold;
        const bucket = metrics[modelType];

        bucket.probabilities.push(probability);
        bucket.labels.push(expectedLabel);

        if (expectedLabel === 1 && predictedPhishing) bucket.tp += 1;
        else if (expectedLabel === 0 && !predictedPhishing) bucket.tn += 1;
        else if (expectedLabel === 0 && predictedPhishing) bucket.fp += 1;
        else bucket.fn += 1;
      });
    });

    const summarize = (bucket, total) => {
      const accuracy = Number((((bucket.tp + bucket.tn) / total) * 100).toFixed(2));
      const precision = bucket.tp + bucket.fp > 0
        ? Number(((bucket.tp / (bucket.tp + bucket.fp)) * 100).toFixed(2))
        : 0;
      const recall = bucket.tp + bucket.fn > 0
        ? Number(((bucket.tp / (bucket.tp + bucket.fn)) * 100).toFixed(2))
        : 0;
      const f1 = precision + recall > 0
        ? Number(((2 * precision * recall) / (precision + recall)).toFixed(2))
        : 0;

      return {
        confusionMatrix: { tp: bucket.tp, tn: bucket.tn, fp: bucket.fp, fn: bucket.fn },
        accuracy,
        precision,
        recall,
        f1,
        rocAuc: computeRocAuc(bucket.probabilities, bucket.labels),
      };
    };

    return {
      sampleSize: docs.length,
      logistic_regression: summarize(metrics.logistic_regression, docs.length),
      naive_bayes: summarize(metrics.naive_bayes, docs.length),
      errorAnalysis: analyzeHoldoutErrors(docs, model),
      diverseValidation: evaluateDiverseValidationSet(model),
    };
  } finally {
    trainedModel = previousModel;
  }
}

function findKeywordHighlights(text) {
  const highlights = [];

  HIGHLIGHT_KEYWORDS.forEach((keyword) => {
    const regex = new RegExp(`\\b${escapeRegex(keyword)}\\b`, 'gi');
    let match = regex.exec(text);

    while (match) {
      highlights.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
        category: 'keyword',
        reason: 'Suspicious phishing keyword',
      });
      match = regex.exec(text);
    }
  });

  return highlights;
}

function buildPhishingIndicators(text, tokens, sentiment) {
  const suspiciousUrls = getSuspiciousUrls(text);
  const credentialMatches = findPhraseMatches(text, 'credential', CREDENTIAL_PHRASES, 'Credential request');
  const financialMatches = findPhraseMatches(text, 'financial', FINANCIAL_PHRASES, 'Financial or payment request');
  const suspensionMatches = findPhraseMatches(text, 'suspension', ACCOUNT_SUSPENSION_PHRASES, 'Account suspension threat');
  const urgencyMatches = findPhraseMatches(text, 'urgency', URGENCY_PHRASES, 'Urgency language');
  const fearMatches = findPhraseMatches(text, 'fear', FEAR_PHRASES, 'Fear tactic');
  const matchedKeywords = [...new Set(tokens.filter((token) => HIGHLIGHT_KEYWORDS.includes(token)))];

  const buildIndicator = (id, label, matches, evidenceMapper) => {
    const evidence = matches.slice(0, 5).map(evidenceMapper);
    return {
      id,
      label,
      detected: matches.length > 0,
      count: matches.length,
      severity: matches.length >= 2 ? 'high' : matches.length === 1 ? 'medium' : 'none',
      evidence,
    };
  };

  return [
    buildIndicator('suspicious_urls', 'Suspicious URLs', suspiciousUrls, (url) => url),
    buildIndicator('credential_requests', 'Credential requests', credentialMatches, (match) => match.text),
    buildIndicator('urgent_language', 'Urgent language', urgencyMatches, (match) => match.text),
    buildIndicator('fear_tactics', 'Fear tactics', fearMatches, (match) => match.text),
    buildIndicator('financial_requests', 'Financial/payment requests', financialMatches, (match) => match.text),
    buildIndicator('account_suspension', 'Account suspension threats', suspensionMatches, (match) => match.text),
    {
      id: 'suspicious_keywords',
      label: 'Suspicious keywords',
      detected: matchedKeywords.length > 0,
      count: matchedKeywords.length,
      severity: matchedKeywords.length >= 4 ? 'high' : matchedKeywords.length >= 2 ? 'medium' : matchedKeywords.length ? 'low' : 'none',
      evidence: matchedKeywords.slice(0, 8),
    },
    {
      id: 'psychological_pressure',
      label: 'Psychological pressure',
      detected: sentiment.urgencyScore >= 15 || sentiment.fearScore >= 15,
      count: sentiment.triggerCount,
      severity: sentiment.urgencyScore >= 35 || sentiment.fearScore >= 35 ? 'high'
        : sentiment.urgencyScore >= 15 || sentiment.fearScore >= 15 ? 'medium' : 'none',
      evidence: sentiment.triggers.slice(0, 5).map((trigger) => trigger.phrase),
    },
  ];
}

function buildTopContributingWords(modelContributors, modelType) {
  if (modelType === 'logistic_regression') {
    return modelContributors
      .map(({ term, contribution, tfidf, weight }) => ({
        term,
        tfidf,
        impact: contribution > 0 ? 'phishing' : contribution < 0 ? 'legitimate' : 'neutral',
        score: Number(Math.abs(contribution).toFixed(4)),
        detail: `weight ${weight}, contribution ${contribution}`,
      }))
      .filter((entry) => entry.impact !== 'neutral')
      .sort((a, b) => b.score - a.score)
      .slice(0, 8);
  }

  return modelContributors
    .filter(({ favors }) => favors === 'phishing' || favors === 'legitimate')
    .map(({ term, tfidf, favors, trainingPhishingTokens, trainingLegitimateTokens }) => ({
      term,
      tfidf,
      impact: favors,
      score: tfidf,
      detail: `training tokens — phishing: ${trainingPhishingTokens}, legitimate: ${trainingLegitimateTokens}`,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 8);
}

function buildExplainabilitySummary(verdict, indicators, topWords, modelType, confidenceScore) {
  const modelName = modelType === 'logistic_regression' ? 'Logistic Regression' : 'Naive Bayes';
  const detectedIndicators = indicators.filter((indicator) => indicator.detected);

  if (verdict === 'Legitimate') {
    if (!detectedIndicators.length) {
      return `This email was classified as Legitimate with ${confidenceScore}% confidence using ${modelName}. No strong phishing indicators such as suspicious links, credential requests, or pressure language were detected.`;
    }

    return `This email was classified as Legitimate with ${confidenceScore}% confidence using ${modelName}. Mild signals were detected (${detectedIndicators.map((indicator) => indicator.label.toLowerCase()).join(', ')}), but the overall model evidence supports a legitimate message.`;
  }

  const indicatorSummary = detectedIndicators.map((indicator) => indicator.label.toLowerCase()).join(', ');
  const topPhishingTerms = topWords
    .filter((word) => word.impact === 'phishing')
    .slice(0, 4)
    .map((word) => word.term)
    .join(', ');

  let summary = `This email was classified as Phishing with ${confidenceScore}% confidence using ${modelName}.`;

  if (indicatorSummary) {
    summary += ` Detected phishing indicators include ${indicatorSummary}.`;
  }

  if (topPhishingTerms) {
    summary += ` The strongest model signal words are ${topPhishingTerms}.`;
  }

  return summary;
}

function buildRecommendations(verdict, indicators) {
  if (verdict === 'Legitimate') {
    return [
      {
        priority: 'low',
        icon: 'shield',
        text: 'This email appears legitimate, but remain cautious with unexpected attachments or links.',
      },
      {
        priority: 'low',
        icon: 'verify',
        text: 'If anything feels unusual, verify the sender through an official contact channel.',
      },
    ];
  }

  const indicatorMap = Object.fromEntries(indicators.map((indicator) => [indicator.id, indicator]));
  const recommendations = [];

  if (indicatorMap.suspicious_urls?.detected) {
    recommendations.push({
      priority: 'high',
      icon: 'link',
      text: 'Do not click suspicious links.',
    });
  }

  if (indicatorMap.credential_requests?.detected || indicatorMap.suspicious_keywords?.detected) {
    recommendations.push({
      priority: 'high',
      icon: 'password',
      text: 'Do not enter your password or login credentials from this email.',
    });
  }

  recommendations.push({
    priority: 'medium',
    icon: 'website',
    text: 'Verify through the official website by typing the address yourself — not via email links.',
  });

  recommendations.push({
    priority: 'medium',
    icon: 'phone',
    text: 'Contact the company directly using official phone numbers or support channels.',
  });

  if (indicatorMap.financial_requests?.detected || indicatorMap.account_suspension?.detected) {
    recommendations.push({
      priority: 'high',
      icon: 'alert',
      text: 'Do not respond to payment or account suspension requests in this email.',
    });
  }

  recommendations.push({
    priority: 'high',
    icon: 'delete',
    text: 'Delete the email if it still looks suspicious after verification.',
  });

  const seen = new Set();
  return recommendations.filter((item) => {
    if (seen.has(item.text)) return false;
    seen.add(item.text);
    return true;
  });
}

function findTfidfTermHighlights(text, tfIdfVector) {
  const highlights = [];
  const terms = Object.keys(tfIdfVector).sort((a, b) => b.length - a.length);

  terms.forEach((term) => {
    if (term.length < 3) return;

    const regex = new RegExp(`\\b${escapeRegex(term)}\\b`, 'gi');
    let match = regex.exec(text);

    while (match) {
      highlights.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
        category: 'tfidf',
        reason: 'Model signal term',
      });
      match = regex.exec(text);
    }
  });

  return highlights;
}

function findSuspiciousDomainHighlights(text) {
  const highlights = [];
  const urlPattern = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;
  let match = urlPattern.exec(text);

  while (match) {
    const url = match[0];
    const domain = extractDomain(url);
    let reason = null;

    if (domain) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        reason = 'IP address link';
      } else if (SUSPICIOUS_DOMAIN_KEYWORDS.some((keyword) => domain.includes(keyword))) {
        reason = 'Domain mimics a trusted service';
      } else if (domain.split('.').length > 3) {
        reason = 'Unusually nested domain';
      }
    }

    if (reason) {
      highlights.push({
        start: match.index,
        end: match.index + url.length,
        text: url,
        category: 'domain',
        reason,
      });
    }

    match = urlPattern.exec(text);
  }

  const anchorPattern = /href=["']([^"']+)["'][^>]*>([^<]{1,120})</gi;
  let anchorMatch = anchorPattern.exec(text);

  while (anchorMatch) {
    const href = anchorMatch[1];
    const label = anchorMatch[2].trim();
    const hrefDomain = extractDomain(href);
    const labelDomain = extractDomain(label.includes('.') ? label : '');

    if (hrefDomain && labelDomain && hrefDomain !== labelDomain) {
      const labelStart = text.indexOf(label, anchorMatch.index);
      if (labelStart !== -1) {
        highlights.push({
          start: labelStart,
          end: labelStart + label.length,
          text: label,
          category: 'domain',
          reason: 'Displayed link text does not match destination domain',
        });
      }
    }

    anchorMatch = anchorPattern.exec(text);
  }

  return highlights;
}

function normalizeHighlights(highlights) {
  const priority = { domain: 5, keyword: 4, fear: 3, urgency: 2, tfidf: 1 };
  const sorted = [...highlights].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return (priority[b.category] || 0) - (priority[a.category] || 0);
  });

  const merged = [];

  sorted.forEach((highlight) => {
    const overlaps = merged.some((existing) => highlight.start < existing.end && highlight.end > existing.start);
    if (!overlaps) {
      merged.push(highlight);
    }
  });

  return merged.sort((a, b) => a.start - b.start);
}

function buildHighlights(text, tfIdfVector) {
  return normalizeHighlights([
    ...findSuspiciousDomainHighlights(text),
    ...findKeywordHighlights(text),
    ...findPhraseMatches(text, 'urgency', URGENCY_PHRASES, 'Urgency trigger'),
    ...findPhraseMatches(text, 'fear', FEAR_PHRASES, 'Fear trigger'),
    ...findTfidfTermHighlights(text, tfIdfVector),
  ]);
}

function analyzeSentiment(text) {
  const urgencyMatches = findPhraseMatches(text, 'urgency', URGENCY_PHRASES, 'Urgency trigger');
  const fearMatches = findPhraseMatches(text, 'fear', FEAR_PHRASES, 'Fear trigger');

  const urgencyScore = Math.min(
    100,
    urgencyMatches.length * 18
      + (urgencyMatches.some((match) => /immediate|urgent|now|expires/i.test(match.text)) ? 22 : 0),
  );
  const fearScore = Math.min(
    100,
    fearMatches.length * 18
      + (fearMatches.some((match) => /blocked|suspended|compromised|unauthorized/i.test(match.text)) ? 22 : 0),
  );

  let overallTone = 'neutral';
  if (urgencyScore >= 35 && fearScore >= 35) overallTone = 'urgent and fearful';
  else if (urgencyScore >= 35) overallTone = 'urgent';
  else if (fearScore >= 35) overallTone = 'fearful';
  else if (urgencyScore >= 15 || fearScore >= 15) overallTone = 'mild pressure';

  const triggerMap = new Map();
  [...urgencyMatches, ...fearMatches].forEach((match) => {
    const key = match.text.toLowerCase();
    if (!triggerMap.has(key)) {
      triggerMap.set(key, {
        phrase: match.text,
        category: match.category,
        reason: match.reason,
      });
    }
  });

  return {
    overallTone,
    urgencyScore,
    fearScore,
    triggerCount: triggerMap.size,
    triggers: [...triggerMap.values()],
  };
}

function buildPredictionExplanation(tokens, model, modelType, tfIdfVector, text, sentiment, verdict, confidenceScore) {
  const terms = Object.keys(tfIdfVector);
  const suspiciousUrls = getSuspiciousUrls(text);
  const urgencyPhrases = findPhraseMatches(text, 'urgency', URGENCY_PHRASES, 'Urgency trigger')
    .map((match) => match.text);
  const fearPhrases = findPhraseMatches(text, 'fear', FEAR_PHRASES, 'Fear trigger')
    .map((match) => match.text);
  const indicators = buildPhishingIndicators(text, tokens, sentiment);

  const topTfidfTerms = Object.entries(tfIdfVector)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([term, value]) => ({ term, tfidf: Number(value.toFixed(4)) }));

  let modelContributors = [];

  if (modelType === 'logistic_regression') {
    modelContributors = terms
      .map((term) => ({
        term,
        tfidf: Number(tfIdfVector[term].toFixed(4)),
        weight: Number((model.logisticWeights[term] || 0).toFixed(4)),
        contribution: Number(((model.logisticWeights[term] || 0) * tfIdfVector[term]).toFixed(4)),
        trainingPhishingDocs: model.termDocCounts.phishing[term] || 0,
        trainingLegitimateDocs: model.termDocCounts.legitimate[term] || 0,
      }))
      .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
      .slice(0, 10);
  } else {
    modelContributors = terms
      .map((term) => {
        const phishCount = model.classTokenCounts.phishing[term] || 0;
        const legitCount = model.classTokenCounts.legitimate[term] || 0;
        return {
          term,
          tfidf: Number(tfIdfVector[term].toFixed(4)),
          trainingPhishingTokens: phishCount,
          trainingLegitimateTokens: legitCount,
          trainingPhishingDocs: model.termDocCounts.phishing[term] || 0,
          trainingLegitimateDocs: model.termDocCounts.legitimate[term] || 0,
          favors: phishCount > legitCount ? 'phishing' : legitCount > phishCount ? 'legitimate' : 'neutral',
        };
      })
      .sort((a, b) => b.tfidf - a.tfidf)
      .slice(0, 10);
  }

  const topContributingWords = buildTopContributingWords(modelContributors, modelType);
  const summary = buildExplainabilitySummary(verdict, indicators, topContributingWords, modelType, confidenceScore);
  const recommendations = buildRecommendations(verdict, indicators);

  return {
    summary,
    indicators,
    topContributingWords,
    recommendations,
    topTfidfTerms,
    modelContributors,
    logisticRegressionWeights: modelType === 'logistic_regression'
      ? modelContributors.map(({ term, weight, contribution }) => ({ term, weight, contribution }))
      : undefined,
    naiveBayesWordCounts: modelType === 'naive_bayes'
      ? modelContributors.map(({ term, trainingPhishingTokens, trainingLegitimateTokens, favors }) => ({
        term,
        trainingPhishingTokens,
        trainingLegitimateTokens,
        favors,
      }))
      : undefined,
    suspiciousUrls,
    urgencyPhrases: [...new Set(urgencyPhrases)],
    fearPhrases: [...new Set(fearPhrases)],
    urgencyScore: sentiment.urgencyScore,
    fearScore: sentiment.fearScore,
    contributors: modelContributors,
  };
}

function calibrateProbability(mlProbability, tokens, model, sentiment, text, threshold) {
  let adjustment = 0;
  const suspiciousUrlCount = countSuspiciousUrls(text);
  const keywordHits = countPhishingKeywordHits(tokens);

  if (suspiciousUrlCount > 0) {
    adjustment += Math.min(0.08, suspiciousUrlCount * 0.04);
  }

  if (sentiment.urgencyScore >= 35) {
    adjustment += 0.05;
  } else if (sentiment.urgencyScore >= 15) {
    adjustment += 0.03;
  }

  if (sentiment.fearScore >= 35) {
    adjustment += 0.05;
  } else if (sentiment.fearScore >= 15) {
    adjustment += 0.03;
  }

  if (keywordHits >= 2) {
    adjustment += Math.min(0.06, keywordHits * 0.015);
  }

  const clearlyNeutral = sentiment.urgencyScore < 10
    && sentiment.fearScore < 10
    && suspiciousUrlCount === 0
    && keywordHits === 0;

  if (clearlyNeutral && mlProbability < 0.55) {
    const vocabularySet = new Set(model.vocabulary);
    let legitSignals = 0;

    [...new Set(tokens.filter((token) => vocabularySet.has(token)))].forEach((term) => {
      const phishDocs = model.termDocCounts?.phishing[term] || 0;
      const legitDocs = model.termDocCounts?.legitimate[term] || 0;
      if (legitDocs > phishDocs * 2) legitSignals += 1;
    });

    if (legitSignals >= 5) {
      adjustment -= Math.min(0.05, legitSignals * 0.008);
    }
  }

  adjustment = Math.max(-0.05, Math.min(0.08, adjustment));
  let calibrated = Math.min(0.9999, Math.max(0.0001, mlProbability + adjustment));

  const mlIsPhishing = mlProbability >= threshold;
  const calibratedIsPhishing = calibrated >= threshold;

  if (mlIsPhishing !== calibratedIsPhishing) {
    calibrated = mlIsPhishing
      ? Math.max(threshold + 0.001, mlProbability)
      : Math.min(threshold - 0.001, mlProbability);
    adjustment = Number((calibrated - mlProbability).toFixed(4));
  }

  return {
    calibrated,
    adjustment: Number(adjustment.toFixed(4)),
    mlProbability: Number(mlProbability.toFixed(4)),
  };
}

function logPredictionTrace(trace) {
  console.log('[prediction-trace]', JSON.stringify(trace, null, 2));
}

function mapProbabilityToResult(rawProbability, threshold = 0.5) {
  const phishingProbability = Number(Math.min(0.9999, Math.max(0.0001, rawProbability)).toFixed(4));
  const legitimateProbability = Number((1 - phishingProbability).toFixed(4));
  const prediction = phishingProbability > threshold ? 1 : 0;
  const verdict = prediction === 1 ? 'Phishing' : 'Legitimate';
  const confidenceScore = Math.round((prediction === 1 ? phishingProbability : legitimateProbability) * 100);

  return {
    calibratedProbability: phishingProbability,
    legitimateProbability,
    prediction,
    score: confidenceScore,
    phishingScore: Math.round(phishingProbability * 100),
    verdict,
    modelClasses: ['Legitimate (0)', 'Phishing (1)'],
    predictProba: {
      legitimate: legitimateProbability,
      phishing: phishingProbability,
    },
  };
}

function classifyEmail(text, modelType, options = {}) {
  const cleanedText = cleanEmailText(text);
  const tokens = tokenizeClean(text);
  const vocabularySet = new Set(trainedModel.vocabulary);
  const tfIdfVector = buildTfIdfVector(tokens, trainedModel.idf, vocabularySet);
  const featureCount = Object.keys(tfIdfVector).length;
  const topTerms = Object.entries(tfIdfVector)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([term, value]) => ({ term, value: Number(value.toFixed(4)) }));

  const lrResult = predictLogisticRegression(tokens, trainedModel);
  const nbResult = predictNaiveBayes(tokens, trainedModel);
  const rawLogisticProbability = lrResult.probability;
  const rawNaiveBayesProbability = nbResult.probability;
  const decisionThreshold = getDecisionThreshold(trainedModel, modelType);
  const rawProbability = modelType === 'naive_bayes'
    ? rawNaiveBayesProbability
    : rawLogisticProbability;

  const boostedProbability = applyLowCoverageBoost(
    rawProbability,
    tokens,
    featureCount,
    tokens.length,
  );
  const sentiment = analyzeSentiment(text);
  const calibration = calibrateProbability(
    boostedProbability,
    tokens,
    trainedModel,
    sentiment,
    text,
    decisionThreshold,
  );
  const result = mapProbabilityToResult(calibration.calibrated, decisionThreshold);
  const explanation = buildPredictionExplanation(
    tokens,
    trainedModel,
    modelType,
    tfIdfVector,
    text,
    sentiment,
    result.verdict,
    result.score,
  );
  const highlights = buildHighlights(text, tfIdfVector);
  const recommendations = explanation.recommendations || [];
  const keywordHits = countPhishingKeywordHits(tokens);
  const vocabularyCoverage = Number((featureCount / Math.max(tokens.length, 1)).toFixed(4));

  const predictionTrace = {
    cleanedText: cleanedText.slice(0, 500),
    tokens,
    tfIdfTerms: topTerms,
    tfIdfVector: Object.fromEntries(
      Object.entries(tfIdfVector).map(([term, value]) => [term, Number(value.toFixed(4))]),
    ),
    rawLogisticRegressionProbability: Number(rawLogisticProbability.toFixed(4)),
    rawNaiveBayesProbability: Number(rawNaiveBayesProbability.toFixed(4)),
    probabilityBeforeCalibration: Number(boostedProbability.toFixed(4)),
    lowCoverageBoost: Number((boostedProbability - rawProbability).toFixed(4)),
    calibrationAdjustment: calibration.adjustment,
    finalProbability: result.calibratedProbability,
    decisionThreshold,
    finalPrediction: result.prediction,
    finalVerdict: result.verdict,
    vocabularyCoverage,
    phishingKeywordHits: keywordHits,
    topContributors: explanation.modelContributors?.slice(0, 8) ?? [],
  };

  if (options.includeDebug) {
    logPredictionTrace(predictionTrace);
  }

  const response = {
    verdict: result.verdict,
    prediction: result.prediction,
    score: result.score,
    confidenceScore: result.score,
    phishingScore: result.phishingScore,
    cleanedText,
    rawPhishingProbability: Number(rawProbability.toFixed(4)),
    rawLogisticRegressionProbability: Number(rawLogisticProbability.toFixed(4)),
    rawNaiveBayesProbability: Number(rawNaiveBayesProbability.toFixed(4)),
    probabilityBeforeCalibration: Number(boostedProbability.toFixed(4)),
    calibratedPhishingProbability: Number(calibration.calibrated.toFixed(4)),
    calibrationAdjustment: calibration.adjustment,
    finalPhishingProbability: result.calibratedProbability,
    decisionThreshold,
    vocabularyCoverage,
    phishingKeywordHits: keywordHits,
    phishingProbability: result.calibratedProbability,
    legitimateProbability: result.legitimateProbability,
    modelClasses: result.modelClasses,
    predictProba: result.predictProba,
    modelUsed: modelType,
    explanation,
    recommendations,
    explainability: {
      summary: explanation.summary,
      indicators: explanation.indicators,
      topContributingWords: explanation.topContributingWords,
    },
    tfidf: {
      totalTerms: tokens.length,
      matchedTerms: featureCount,
      topTerms,
    },
    highlights,
    sentiment,
    predictionTrace: options.includeDebug ? predictionTrace : undefined,
  };

  if (options.includeDebug) {
    response._debug = predictionTrace;
  }

  return response;
}

async function initializeDatabase() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS detection_history (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      email_content TEXT NOT NULL,
      model_used ENUM('logistic_regression', 'naive_bayes') NOT NULL,
      logistic_regression_score INT DEFAULT NULL,
      naive_bayes_score INT DEFAULT NULL,
      result VARCHAR(30) NOT NULL,
      tfidf_terms JSON NULL,
      scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

async function ensureDatabaseReady() {
  if (databaseReady) return true;
  await initializeDatabase();
  databaseReady = true;
  return true;
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Registration or login is required for this action.' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: 'Your session expired. Please log in again.' });
  }
}

app.get('/api/health', async (_req, res) => {
  let database = 'unavailable';
  try {
    await ensureDatabaseReady();
    database = databaseReady ? 'connected' : 'unavailable';
  } catch {
    database = 'unavailable';
  }

  return res.json({
    ok: true,
    database,
    ml: mlReady ? 'ready' : 'loading',
    port: PORT,
  });
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    await ensureDatabaseReady();
    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name.trim(), email.trim().toLowerCase(), passwordHash],
    );
    return res.status(201).json({
      success: true,
      message: 'Registration successful. Please log in to continue.',
      user: { id: result.insertId, name: name.trim(), email: email.trim().toLowerCase() },
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'This email is already registered.' });
    }
    return res.status(500).json({ error: 'Registration failed. Check the database connection.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    await ensureDatabaseReady();
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch {
    return res.status(500).json({ error: 'Login failed. Check the database connection.' });
  }
});

app.post('/api/analyze', async (req, res) => {
  const { text, modelType = 'logistic_regression' } = req.body;
  const safeModel = modelType === 'naive_bayes' ? 'naive_bayes' : 'logistic_regression';

  if (!text || !text.trim()) {
    return res.status(400).json({ error: 'Paste or upload email content before scanning.' });
  }

  if (!mlReady) {
    try {
      await mlBootstrapPromise;
    } catch (error) {
      return res.status(503).json({ error: 'ML model failed to load. Restart the backend and try again.' });
    }
  }

  if (!mlReady) {
    return res.status(503).json({ error: 'ML model is still loading. Wait a few seconds and try again.' });
  }

  let analysis;
  try {
    analysis = classifyEmail(text, safeModel, { includeDebug: true });
  } catch (error) {
    console.error('[analyze] classification failed:', error);
    return res.status(500).json({ error: 'Scan failed while analyzing the email. Restart the backend and try again.' });
  }

  console.log('[analyze] debug trace', analysis.predictionTrace ?? analysis._debug);

  const { _debug, ...clientAnalysis } = analysis;
  void _debug;

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  let historyWarning = null;

  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      await ensureDatabaseReady();
      await db.query(
        `INSERT INTO detection_history
          (user_id, email_content, model_used, logistic_regression_score, naive_bayes_score, result, tfidf_terms)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          user.id,
          text.trim().slice(0, 500),
          safeModel,
          safeModel === 'logistic_regression' ? analysis.score : null,
          safeModel === 'naive_bayes' ? analysis.score : null,
          analysis.verdict,
          JSON.stringify(analysis.tfidf.topTerms),
        ],
      );
    } catch (error) {
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Your session expired. Please log in again.' });
      }
      historyWarning = 'Scan completed, but history was not saved because the database is unavailable. Start XAMPP MySQL to enable scan history.';
      console.warn('[analyze] history save skipped:', error.message);
    }
  }

  return res.json(historyWarning ? { ...clientAnalysis, historyWarning } : clientAnalysis);
});

app.get('/api/history', authMiddleware, async (req, res) => {
  try {
    await ensureDatabaseReady();
    const [rows] = await db.query(
      `SELECT id, email_content, model_used, logistic_regression_score, naive_bayes_score,
              result, tfidf_terms, scanned_at
       FROM detection_history
       WHERE user_id = ?
       ORDER BY scanned_at DESC`,
      [req.user.id],
    );
    return res.json(rows);
  } catch {
    return res.status(500).json({ error: 'Could not load scan history.' });
  }
});

app.delete('/api/history/:id', authMiddleware, async (req, res) => {
  try {
    await ensureDatabaseReady();
    const [result] = await db.query(
      'DELETE FROM detection_history WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'History item not found.' });
    }

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Could not delete scan history item.' });
  }
});

app.delete('/api/history', authMiddleware, async (req, res) => {
  try {
    await ensureDatabaseReady();
    await db.query('DELETE FROM detection_history WHERE user_id = ?', [req.user.id]);
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Could not delete scan history.' });
  }
});

initializeDatabase()
  .then(() => {
    databaseReady = true;
    console.log('XAMPP MySQL database connected.');
  })
  .catch((error) => {
    databaseReady = false;
    console.error('Database is not connected yet:', error.message);
    console.error('Guest scans still work. Start XAMPP MySQL before register/login/history.');
  })
  .finally(() => {
    const httpServer = app.listen(PORT, '127.0.0.1', () => {
      console.log(`MailShield backend running at http://127.0.0.1:${PORT}`);
      console.log('API is available immediately; ML model loads in the background if needed.');

      mlBootstrapPromise
        .then(() => {
          console.log(`Selected features: ${trainedModel.vocabulary.length}`);
          if (mlModelFromCache) {
            console.log('ML model loaded from cache (delete data/.model-cache.json to retrain).');
            return;
          }

          console.log(`Fresh training complete: ${trainingRows.length} training rows.`);
        })
        .catch((error) => {
          console.error('ML model failed to load:', error.message);
        });
    });

    httpServer.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Close the other terminal running node server.js, or run: set PORT=5002 && node server.js`);
      } else {
        console.error('Backend failed to start:', error.message);
      }
      process.exit(1);
    });
  });

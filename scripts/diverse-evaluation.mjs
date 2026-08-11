import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { API_BASE, API_PORT, isApiReachable, waitForAnalyzeApi } from './api-config.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

const samples = [
  ['banking', 'legitimate', 'Subject: Your Monthly Account Statement is Ready\n\nDear Customer,\n\nYour monthly account statement for your online banking account is now available.\n\nPlease log in to your bank account through our official website or mobile app to view your statement.\n\nIf you have any questions, contact customer support.\n\nThank you for banking with us.'],
  ['shopping', 'legitimate', 'Subject: Your order has shipped\n\nHi Alex,\n\nGood news — your order #48291 has shipped and is on the way.\n\nEstimated delivery: Tuesday, March 12.\n\nTrack your package from your account dashboard.\n\nThanks for shopping with us.'],
  ['university', 'legitimate', 'Subject: Fall registration opens next week\n\nDear students,\n\nCourse registration for the fall semester opens Monday at 8 AM.\n\nPlease meet with your academic advisor before selecting classes.\n\nVisit the registrar website for the full schedule.\n\nUniversity Office of the Registrar'],
  ['hr', 'legitimate', 'Subject: Benefits enrollment reminder\n\nHello team,\n\nThis is a reminder that open enrollment for health and dental benefits closes Friday.\n\nReview the HR portal for plan details and submit your selections.\n\nContact HR support if you need assistance.\n\nPeople Operations'],
  ['shipping', 'legitimate', 'Subject: Delivery update for package 1Z999\n\nYour package is out for delivery today.\n\nDelivery address on file will be used. You can manage delivery preferences in the shipping app.\n\nThank you.'],
  ['meeting', 'legitimate', 'Subject: Project sync tomorrow\n\nHi everyone,\n\nLet us meet tomorrow at 10 AM to review the roadmap and sprint backlog.\n\nAgenda attached. Please bring status updates from your teams.\n\nThanks,\nJordan'],
  ['password_change', 'legitimate', 'Subject: Password changed successfully\n\nHello,\n\nThis confirms that the password for your account was changed successfully.\n\nIf you did not make this change, contact support immediately through the official help center.\n\nSecurity Team'],
  ['newsletter', 'legitimate', 'Subject: Weekly community newsletter\n\nHello members,\n\nWelcome to this week\'s newsletter with product updates, community highlights, and upcoming events.\n\nWe hope you enjoy this edition.\n\nBest regards,\nThe Team'],
  ['real_phishing', 'phishing', 'URGENT: Your account blocked. Immediate action required. Verify your password at http://secure-login-verify.xyz/update within 24 hours or your account will be suspended.'],
  ['fake_invoice', 'phishing', 'Subject: Invoice overdue — payment required today\n\nDear customer,\n\nYour invoice is overdue. Open the attached document and confirm payment immediately to avoid service interruption.\n\nPay now using the link below.'],
  ['credential_theft', 'phishing', 'Security alert: unusual sign-in detected. Confirm your login credentials now at http://account-verify-security.xyz/signin to restore access to your account.'],
];

let apiBase = API_BASE;
let managedServer = null;

if (await isApiReachable(apiBase)) {
  console.log(`Using existing API at ${apiBase}`);
} else {
  console.log(`Starting temporary API on port ${API_PORT}...`);
  managedServer = spawn(process.execPath, ['server.js'], {
    cwd: root,
    env: { ...process.env, PORT: String(API_PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  managedServer.stdout.on('data', (chunk) => process.stdout.write(chunk));
  managedServer.stderr.on('data', (chunk) => process.stderr.write(chunk));

  if (!(await waitForAnalyzeApi(120, apiBase))) {
    managedServer.kill();
    console.error('Server failed to become ready.');
    process.exit(1);
  }
}

console.log('\n=== DIVERSE VALIDATION (API raw probabilities) ===\n');

for (const modelType of ['logistic_regression', 'naive_bayes']) {
  let correct = 0;
  console.log(`--- ${modelType} ---`);
  for (const [category, expected, text] of samples) {
    const res = await fetch(`${apiBase}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, modelType }),
    });
    const data = await res.json();
    const predicted = data.verdict?.toLowerCase() || (data.prediction === 1 ? 'phishing' : 'legitimate');
    const ok = predicted === expected;
    if (ok) correct += 1;
    console.log(`[${ok ? 'OK' : 'MISS'}] ${category} | expected=${expected} | raw=${data.rawPhishingProbability} | verdict=${data.verdict}`);
  }
  console.log(`Accuracy: ${correct}/${samples.length} (${((correct / samples.length) * 100).toFixed(1)}%)\n`);
}

if (managedServer) {
  managedServer.kill();
}

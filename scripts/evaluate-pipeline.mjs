const PORT = Number(process.env.EVAL_PORT || 5002);
const baseUrl = `http://127.0.0.1:${PORT}`;

const newsletter = `Hello community members,

We hope you find this monthly newsletter helpful. This edition covers new community features,
upcoming events, and helpful resources for everyone.

Thank you for being part of our community.

Best regards,
The Team`;

const samples = [
  { name: 'newsletter (legitimate)', text: newsletter, expected: 'legitimate' },
  { name: 'meeting (legitimate)', text: 'Hello team, the project meeting is scheduled for tomorrow. Please review the agenda. Thanks, Sarah', expected: 'legitimate' },
  { name: 'urgent phishing', text: 'URGENT: Your account blocked. Immediate action required. Verify your password at http://secure-login-verify.xyz/update', expected: 'phishing' },
];

async function waitForServer(maxAttempts = 60) {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const res = await fetch(`${baseUrl}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'ping', modelType: 'logistic_regression' }),
      });
      if (res.ok) return true;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  return false;
}

console.log(`Waiting for backend at ${baseUrl} ...`);
if (!(await waitForServer())) {
  console.error(`Start the server first: $env:PORT=${PORT}; node server.js`);
  process.exit(1);
}

console.log('\n=== PREDICTION PIPELINE CHECK ===\n');

for (const sample of samples) {
  for (const modelType of ['logistic_regression', 'naive_bayes']) {
    const res = await fetch(`${baseUrl}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: sample.text, modelType }),
    });
    const d = await res.json();

    console.log('='.repeat(72));
    console.log(`${sample.name} | ${modelType}`);
    console.log('Expected:', sample.expected);
    console.log('modelClasses:', d.modelClasses);
    console.log('predictProba:', d.predictProba);
    console.log('prediction (0=Legitimate, 1=Phishing):', d.prediction);
    console.log('verdict:', d.verdict);
    console.log('confidenceScore:', d.confidenceScore, '%');
    console.log('rawPhishingProbability:', d.rawPhishingProbability);
    console.log('matchedFeatures:', d.tfidf?.matchedTerms);
    console.log('topContributors:', d.explanation?.modelContributors?.slice(0, 5) ?? d.explanation?.contributors?.slice(0, 5));
    console.log('sentiment:', d.sentiment?.overallTone, '| urgency:', d.sentiment?.urgencyScore, '| fear:', d.sentiment?.fearScore);
  }
}

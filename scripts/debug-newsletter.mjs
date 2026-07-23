const newsletter = `Hello community members,

We hope you find this monthly newsletter helpful. This edition covers new community features,
upcoming events, and helpful resources for everyone.

Thank you for being part of our community.

Best regards,
The Team`;

const samples = [
  ['newsletter', newsletter],
  ['meeting', 'Hello team, the project meeting is scheduled for tomorrow. Please review the agenda. Thanks, Sarah'],
];

for (const [name, text] of samples) {
  for (const modelType of ['logistic_regression', 'naive_bayes']) {
    try {
      const res = await fetch('http://127.0.0.1:5001/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, modelType }),
      });
      const d = await res.json();
      console.log('\n' + '='.repeat(60));
      console.log(name, modelType);
      console.log('verdict:', d.verdict, 'prediction:', d.prediction);
      console.log('rawPhishingProbability:', d.rawPhishingProbability);
      console.log('phishingProbability:', d.phishingProbability);
      console.log('matchedFeatures:', d.tfidf?.matchedTerms);
      console.log('topTerms:', d.tfidf?.topTerms);
      console.log('sentiment:', d.sentiment?.overallTone, 'urgency:', d.sentiment?.urgencyScore, 'fear:', d.sentiment?.fearScore);
    } catch (e) {
      console.log('API error - start server first:', e.message);
      break;
    }
  }
}

const backendUrl = process.env.BACKEND_HEALTH_URL || 'http://127.0.0.1:5001/api/health';
const maxAttempts = Number(process.env.BACKEND_WAIT_ATTEMPTS || 120);
const delayMs = Number(process.env.BACKEND_WAIT_DELAY_MS || 1000);

async function waitForBackend() {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(backendUrl);
      if (response.ok) {
        console.log(`Backend is ready at ${backendUrl}`);
        return;
      }
    } catch {
      // backend not up yet
    }

    if (attempt === 1) {
      console.log('Waiting for backend on http://127.0.0.1:5001 ...');
    }

    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  console.error('Backend did not start in time. Make sure "node server.js" is running on port 5001.');
  process.exit(1);
}

await waitForBackend();

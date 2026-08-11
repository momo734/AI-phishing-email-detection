export const API_PORT = Number(process.env.EVAL_PORT || process.env.PORT || 5001);
export const API_BASE = `http://127.0.0.1:${API_PORT}`;

export async function waitForAnalyzeApi(maxAttempts = 60, baseUrl = API_BASE) {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'ping', modelType: 'logistic_regression' }),
      });
      if (response.ok) return true;
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return false;
}

export async function isApiReachable(baseUrl = API_BASE) {
  try {
    const response = await fetch(`${baseUrl}/api/health`);
    return response.ok;
  } catch {
    return false;
  }
}

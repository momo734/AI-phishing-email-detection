import { execSync } from 'node:child_process';

const PORTS = [5001, 5174, 5173];

function getListeningPids(port) {
  try {
    const output = execSync(`netstat -ano | findstr :${port} | findstr LISTENING`, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });

    const pids = new Set();
    for (const line of output.split('\n')) {
      const match = line.trim().match(/\s(\d+)\s*$/);
      if (match) pids.add(match[1]);
    }
    return [...pids];
  } catch {
    return [];
  }
}

let stopped = 0;

for (const port of PORTS) {
  for (const pid of getListeningPids(port)) {
    try {
      execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
      console.log(`Stopped PID ${pid} on port ${port}`);
      stopped += 1;
    } catch {
      console.log(`Could not stop PID ${pid} on port ${port}`);
    }
  }
}

if (stopped === 0) {
  console.log('MailShield is not running (no servers on ports 5001/5173/5174).');
} else {
  console.log(`Stopped ${stopped} MailShield process(es).`);
}

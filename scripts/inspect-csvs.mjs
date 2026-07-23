import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = join(root, 'data');

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
      if (char === '\r' && next === '\n') index += 1;
      row.push(current.trim());
      if (row.some((value) => value !== '')) records.push(row);
      row = [];
      current = '';
    } else {
      current += char;
    }
  }

  row.push(current.trim());
  if (row.some((value) => value !== '')) records.push(row);
  return records;
}

for (const file of readdirSync(dataDir).filter((name) => name.endsWith('.csv')).sort()) {
  const records = parseCsvRecords(readFileSync(join(dataDir, file), 'utf8'));
  const headers = records[0].map((header) => header.toLowerCase().replace(/[\s_-]/g, ''));
  const labelIndex = headers.findIndex((header) => ['label', 'class', 'category', 'target', 'emailtype', 'type'].includes(header));
  const labels = new Set(records.slice(1, 20).map((row) => row[labelIndex]).filter(Boolean));
  console.log(`${file}: rows=${records.length - 1}, labels=${[...labels].join(' | ')}`);
}

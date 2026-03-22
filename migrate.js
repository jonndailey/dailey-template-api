const mysql = require('mysql2/promise');

async function migrate() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) { console.log('[migrate] No DATABASE_URL set, skipping migrations'); return; }
  console.log('[migrate] Connecting to database...');
  const connection = await mysql.createConnection(dbUrl);
  await connection.execute(`CREATE TABLE IF NOT EXISTS _migrations (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  const [applied] = await connection.execute('SELECT name FROM _migrations ORDER BY id');
  const appliedSet = new Set(applied.map(r => r.name));
  const fs = require('fs');
  const path = require('path');
  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) { console.log('[migrate] No migrations directory found'); await connection.end(); return; }
  const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
  let ran = 0;
  for (const file of files) {
    if (appliedSet.has(file)) continue;
    console.log(`[migrate] Running: ${file}`);
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
    for (const stmt of statements) { await connection.execute(stmt); }
    await connection.execute('INSERT INTO _migrations (name) VALUES (?)', [file]);
    ran++;
  }
  console.log(`[migrate] Done. ${ran} migration(s) applied, ${files.length} total.`);
  await connection.end();
}

module.exports = { migrate };
if (require.main === module) migrate().catch(e => { console.error(e); process.exit(1); });

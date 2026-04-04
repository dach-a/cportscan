const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DB_PATH || './data/cportscan.db';

// Ensure data directory exists
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('✅ Database connected:', dbPath);
  }
});

db.configure('busyTimeout', 5000);

// Promisify database operations
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Initialize tables
async function initializeTables() {
  try {
    // Users table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1
      )
    `);

    // Scans table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        hostname TEXT NOT NULL,
        start_port INTEGER NOT NULL,
        end_port INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        progress INTEGER DEFAULT 0,
        open_ports_count INTEGER DEFAULT 0,
        total_ports_count INTEGER DEFAULT 0,
        scan_time_seconds REAL,
        error_message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Scan results table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        port INTEGER NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
      )
    `);

    // Create indexes
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)`);

    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('Table initialization error:', error);
  }
}

module.exports = {
  db,
  dbRun,
  dbGet,
  dbAll,
  initializeTables
};

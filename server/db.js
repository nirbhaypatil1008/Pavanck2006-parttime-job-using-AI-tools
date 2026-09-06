const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');


const dbPath = path.join(__dirname, '..', 'data', 'parttimejob.db');
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── MySQL → SQLite SQL Transformer ────────────────────────────────────────

function convertSchemaSql(sql) {
  let s = sql;
  s = s.replace(/ENGINE\s*=\s*InnoDB[^;]*/gi, '');
  s = s.replace(/DEFAULT\s+CHARSET\s*=\s*\w+/gi, '');
  s = s.replace(/COLLATE\s*=\s*\w+/gi, '');
  s = s.replace(/\bBIGINT\b\s+AUTO_INCREMENT\s+PRIMARY\s+KEY/gi, 'INTEGER PRIMARY KEY AUTOINCREMENT');
  s = s.replace(/\bBIGINT\b/gi, 'INTEGER');
  s = s.replace(/\bVARCHAR\s*\([^)]+\)/gi, 'TEXT');
  s = s.replace(/\bDOUBLE\b/gi, 'REAL');
  s = s.replace(/\bDECIMAL\s*\([^)]+\)/gi, 'REAL');
  s = s.replace(/\bBOOLEAN\b/gi, 'INTEGER');
  s = s.replace(/,\s*ON\s+UPDATE\s+CURRENT_TIMESTAMP/gi, '');
  s = s.replace(/ON\s+UPDATE\s+CURRENT_TIMESTAMP\s*,?/gi, '');
  s = s.replace(/DEFAULT\s+TRUE/gi, 'DEFAULT 1');
  s = s.replace(/DEFAULT\s+FALSE/gi, 'DEFAULT 0');
  s = s.replace(/\bTIMESTAMP\b(?!\s+NULL\b)/gi, 'TEXT');
  s = s.replace(/\bTIMESTAMP\s+NULL\b/gi, 'TEXT');
  s = s.replace(/DEFAULT\s+CURRENT_TIMESTAMP/gi, "DEFAULT (datetime('now','localtime'))");
  s = s.replace(/UNIQUE\s+KEY\s+\w+/gi, 'UNIQUE');
  s = s.replace(/,?\s*INDEX\s+\w+\s*\([^)]+\)/gi, '');
  s = s.replace(/,?\s*CONSTRAINT\s+\w+\s+FOREIGN\s+KEY[^)]+\)\s+REFERENCES[^)]+\)(?:\s+ON\s+DELETE\s+(?:CASCADE|SET\s+NULL))?/gi, '');
  s = s.replace(/,\s*\)/g, '\n)');
  return s;
}

function convertQuerySql(sql) {
  let s = sql;
  s = s.replace(/\bNOW\(\)/gi, "datetime('now','localtime')");
  s = s.replace(/\bFOR\s+UPDATE\b/gi, '');
  s = s.replace(/\bIF\s*\(([^,]+),\s*'([^']*)',\s*'([^']*)'\)/gi, "CASE WHEN $1 THEN '$2' ELSE '$3' END");
  s = s.replace(/\bIF\s*\(([^,]+),\s*(\d+),\s*(\d+)\)/gi, "CASE WHEN $1 THEN $2 ELSE $3 END");
  // MySQL YEAR()/MONTH() → SQLite strftime
  s = s.replace(/\bYEAR\(([^)]+)\)/gi, "strftime('%Y',$1)");
  s = s.replace(/\bMONTH\(([^)]+)\)/gi, "strftime('%m',$1)");
  // MySQL IS TRUE/FALSE comparisons
  s = s.replace(/(\w+)\s*=\s*FALSE/gi, "$1 = 0");
  s = s.replace(/(\w+)\s*=\s*TRUE/gi, "$1 = 1");
  // Handle standalone FALSE/TRUE in WHERE clauses
  s = s.replace(/\bFALSE\b/gi, '0');
  s = s.replace(/\bTRUE\b/gi, '1');
  // MySQL double-quoted string literals → single-quoted (SQLite treats double quotes as identifiers)
  s = s.replace(/"([^"]+)"/g, "'$1'");

  // ─── UPDATE ... JOIN ... SET ... WHERE ... ──────────────────────────────
  const updateJoinMatch = s.match(
    /^UPDATE\s+(\w+)\s+(\w+)\s+JOIN\s+(\w+)\s+(\w+)\s+ON\s+\w+\.(\w+)\s*=\s*\w+\.(\w+)\s+SET\s+(.+?)\s+WHERE\s+(.+)$/is
  );
  if (updateJoinMatch) {
    const [, t1, a, t2, b, joinCol2, joinCol1, setClause, whereClause] = updateJoinMatch;
    let newSet = setClause.replace(new RegExp(`\\b${a}\\.`, 'g'), '');
    let newWhere = whereClause;
    newWhere = newWhere.replace(
      new RegExp(`(\\w+\\.)?(\\w+)\\s*=\\s*\\?`, 'g'),
      (match, prefix, colName) => {
        if (prefix && prefix.trim() === b + '.') {
          return `${joinCol1} IN (SELECT ${joinCol2} FROM ${t2} WHERE ${colName}=?)`;
        }
        return match;
      }
    );
    newWhere = newWhere.replace(new RegExp(`\\b${a}\\.`, 'g'), '');
    s = `UPDATE ${t1} SET ${newSet} WHERE ${newWhere}`;
  }

  // ─── DELETE ... JOIN ... WHERE ... ──────────────────────────────────────
  const deleteJoinMatch = s.match(
    /^DELETE\s+\w+\s+FROM\s+(\w+)\s+(\w+)\s+JOIN\s+(\w+)\s+(\w+)\s+ON\s+\w+\.(\w+)\s*=\s*\w+\.(\w+)\s+WHERE\s+(.+)$/is
  );
  if (deleteJoinMatch) {
    const [, t1, a, t2, b, joinCol2, joinCol1, whereClause] = deleteJoinMatch;
    let newWhere = whereClause;
    newWhere = newWhere.replace(
      new RegExp(`(\\w+\\.)?(\\w+)\\s*=\\s*\\?`, 'g'),
      (match, prefix, colName) => {
        if (prefix && prefix.trim() === b + '.') {
          return `${joinCol1} IN (SELECT ${joinCol2} FROM ${t2} WHERE ${colName}=?)`;
        }
        return match;
      }
    );
    newWhere = newWhere.replace(new RegExp(`\\b${a}\\.`, 'g'), '');
    s = `DELETE FROM ${t1} WHERE ${newWhere}`;
  }

  return s;
}

// ─── Query API (mysql2/promise compatible) ─────────────────────────────────

function executeQuery(sql, params = []) {
  // Convert JS booleans, Date objects, and undefined to SQLite-safe values
  const safeParams = (params || []).map(p => {
    if (typeof p === 'boolean') return p ? 1 : 0;
    if (p instanceof Date) return p.toISOString();
    if (p === undefined) return null;
    return p;
  });
  const converted = convertQuerySql(sql);
  const trimmed = converted.trim();
  const upperStart = trimmed.toUpperCase();

  try {
    if (upperStart.startsWith('SELECT')) {
      return [db.prepare(converted).all(...safeParams), []];
    } else if (upperStart.startsWith('INSERT')) {
      const result = db.prepare(converted).run(...safeParams);
      return [{ insertId: Number(result.lastInsertRowid), affectedRows: result.changes }, []];
    } else if (upperStart.startsWith('UPDATE') || upperStart.startsWith('DELETE')) {
      const result = db.prepare(converted).run(...safeParams);
      return [{ affectedRows: result.changes }, []];
    } else {
      db.exec(converted);
      return [{}, []];
    }
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE' || e.code === 'SQLITE_CONSTRAINT') {
      if (/^\s*INSERT\s+OR\s+IGNORE\b/i.test(trimmed)) {
        return [{ insertId: 0, affectedRows: 0 }, []];
      }
      // MySQL ER_DUP_ENTRY equivalent for duplicate key
      e.code = 'ER_DUP_ENTRY';
    }
    throw e;
  }
}

const pool = {
  query(sqlOrOpts, params) {
    const sql = typeof sqlOrOpts === 'string' ? sqlOrOpts : (sqlOrOpts.sql || sqlOrOpts);
    return Promise.resolve(executeQuery(sql, params || []));
  },
  getConnection() {
    return {
      query(sql, params) { return Promise.resolve(executeQuery(sql, params || [])); },
      beginTransaction() { db.exec('BEGIN'); return Promise.resolve(); },
      commit() { db.exec('COMMIT'); return Promise.resolve(); },
      rollback() { try { db.exec('ROLLBACK'); } catch(e) {} return Promise.resolve(); },
      release() {},
    };
  },
  end() { db.close(); return Promise.resolve(); }
};

// ─── Database Initialization ───────────────────────────────────────────────

let initialized = false;

async function initializeDatabase() {
  if (initialized) return;
  initialized = true;

  // Read and convert schema
  const schemaPath = path.join(__dirname, '..', 'src', 'main', 'resources', 'schema.sql');
  const rawSchema = fs.readFileSync(schemaPath, 'utf8');
  const statements = rawSchema
    .replace(/--.*$/gm, '')
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  for (const stmt of statements) {
    const converted = convertSchemaSql(stmt);
    if (converted.trim()) {
      try { db.exec(converted); } catch (e) {
        if (!e.message.includes('already exists')) {
          console.error('Schema error:', e.message.substring(0, 100));
        }
      }
    }
  }

  // OTP verifications table
  db.exec(`CREATE TABLE IF NOT EXISTS otp_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'registration',
    expires_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 5,
    is_verified INTEGER DEFAULT 0,
    is_used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  )`);
  try { db.exec('CREATE INDEX idx_otp_email_purpose ON otp_verifications(email, purpose)'); } catch(e) {}
  try { db.exec('CREATE INDEX idx_otp_expires ON otp_verifications(expires_at)'); } catch(e) {}
  try { db.exec('CREATE INDEX idx_otp_created ON otp_verifications(created_at)'); } catch(e) {}

  // Pending registrations table (multi-step registration state)
  db.exec(`CREATE TABLE IF NOT EXISTS pending_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    college_name TEXT,
    preferred_area TEXT,
    skills TEXT,
    bio TEXT,
    emergency_contact TEXT,
    catering_name TEXT,
    business_address TEXT,
    business_phone TEXT,
    phone_verified INTEGER DEFAULT 0,
    email_verified INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    current_step TEXT DEFAULT 'info',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT NOT NULL
  )`);
  try { db.exec('CREATE INDEX idx_pend_token ON pending_registrations(token)'); } catch(e) {}
  try { db.exec('CREATE INDEX idx_pend_email ON pending_registrations(email)'); } catch(e) {}
  try { db.exec('CREATE INDEX idx_pend_phone ON pending_registrations(phone)'); } catch(e) {}

  // Add complaint_messages table
  db.exec(`CREATE TABLE IF NOT EXISTS complaint_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Migrations - safe ALTER TABLE that only adds columns if they don't exist
  try { db.exec('ALTER TABLE catering_jobs ADD COLUMN location_photo_url TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE student_profiles ADD COLUMN profile_photo_url TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE owner_profiles ADD COLUMN profile_photo_url TEXT'); } catch(e) {}
  // payment_records missing columns for Razorpay integration
  try { db.exec('ALTER TABLE payment_records ADD COLUMN razorpay_order_id TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN razorpay_payment_id TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN razorpay_signature TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN razorpay_receipt TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN payment_method TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN transaction_id TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN environment TEXT DEFAULT "TEST"'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN failure_reason TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN confirmed_paid_at TEXT'); } catch(e) {}
  try { db.exec('ALTER TABLE payment_records ADD COLUMN initiated_at TEXT'); } catch(e) {}
  try { db.exec("ALTER TABLE payment_records ADD COLUMN updated_at TEXT DEFAULT (datetime('now','localtime'))"); } catch(e) {}

  // Job lifecycle migrations
  try { db.exec('ALTER TABLE catering_jobs ADD COLUMN owner_decision TEXT'); } catch(e) {}
  try { db.exec("ALTER TABLE catering_jobs ADD COLUMN owner_decision_at TEXT"); } catch(e) {}

  // Seed data
  if (process.env.RUN_SEED !== 'false') {
    const seedPath = path.join(__dirname, '..', 'src', 'main', 'resources', 'data.sql');
    if (fs.existsSync(seedPath)) {
      const rawSeed = fs.readFileSync(seedPath, 'utf8');
      const convertedSeed = rawSeed
        .replace(/--.*$/gm, '')
        .replace(/\bINSERT\s+IGNORE\s+INTO\b/gi, 'INSERT OR IGNORE INTO')
        .replace(/\bNOW\(\)/gi, "datetime('now','localtime')");
      
      const seedStatements = convertedSeed
        .split(';')
        .map(s => s.trim())
        .filter(s => s.length > 0 && s.toUpperCase().startsWith('INSERT'));

      for (const stmt of seedStatements) {
        try {
          db.exec(stmt);
        } catch (e) {
          if (!e.message.includes('UNIQUE constraint') && !e.message.includes('PRIMARY KEY constraint')) {
            console.warn('Seed warning:', e.message.substring(0, 120));
          }
        }
      }
    }
  }

  console.log('SQLite database initialized successfully');
}

async function transaction(work) {
  try {
    db.exec('BEGIN');
    const result = await work(pool);
    db.exec('COMMIT');
    return result;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch(x) {}
    throw e;
  }
}

module.exports = { pool, initializeDatabase, transaction };

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

// ─── MySQL connection (mysql2/promise) ───────────────────────────────────────

const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_NAME = process.env.DB_NAME || 'parttimejob_db';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  dateStrings: true, // return DATETIME/TIMESTAMP as strings, matching previous string-based timestamps
  charset: 'utf8mb4_general_ci',
});

// ─── Dialect translation (a few server statements still contain SQLite-isms) ─
// Server-side SQL was written while the backend ran on SQLite, so a couple of
// statements use datetime('now','localtime') / INSERT OR IGNORE. They are
// translated here so the rest of the server keeps working unchanged on MySQL.

function translateSql(sql) {
  if (typeof sql !== 'string') return sql;
  let s = sql;

  // SQLite datetime('now'[,'localtime'][,'±N unit']) → MySQL NOW() with INTERVAL offsets
  //   datetime('now','localtime')              → NOW()
  //   datetime('now','localtime','-15 minutes') → NOW() - 15 MINUTE
  //   datetime('now','-1 day','localtime')      → NOW() - 1 DAY
  s = s.replace(
    /datetime\s*\(\s*'now'\s*((?:,\s*'[^']*'\s*)*)\)/gi,
    (match, argsRaw) => {
      const mods = [];
      const re = /'([^']*)'/g;
      let m;
      while ((m = re.exec(argsRaw))) mods.push(m[1].trim().toLowerCase());
      const offsets = [];
      for (const mod of mods) {
        if (mod === 'localtime' || mod === 'utc') continue; // NOW() is already local time
        const off = mod.match(/^([+-])?\s*(\d+)\s+(days?|hours?|minutes?|seconds?|months?|years?)$/);
        if (off) {
          const n = parseInt(off[2], 10) * (off[1] === '-' ? -1 : 1);
          let unit = off[3].toUpperCase();
          if (unit.endsWith('S')) unit = unit.slice(0, -1);
          offsets.push(`${n < 0 ? '-' : '+'} ${Math.abs(n)} ${unit}`);
        }
      }
      if (offsets.length === 0) return 'NOW()';
      return `NOW() ${offsets.join(' ')}`;
    }
  );

  // SQLite INSERT OR IGNORE / REPLACE → MySQL INSERT IGNORE / REPLACE
  s = s.replace(/\bINSERT\s+OR\s+IGNORE\s+INTO\b/gi, 'INSERT IGNORE INTO');
  s = s.replace(/\bINSERT\s+OR\s+REPLACE\s+INTO\b/gi, 'REPLACE INTO');

  return s;
}

// ─── Query API (mysql2/promise compatible) ───────────────────────────────────

function query(sqlOrOpts, params) {
  const sql = typeof sqlOrOpts === 'string' ? sqlOrOpts : (sqlOrOpts && (sqlOrOpts.sql || sqlOrOpts));
  return pool.query(translateSql(sql), params);
}

// ─── Transactions ────────────────────────────────────────────────────────────

async function transaction(work) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const wrapped = {
      query(sql, params) { return conn.query(translateSql(sql), params); },
    };
    const result = await work(wrapped);
    await conn.commit();
    return result;
  } catch (e) {
    try { await conn.rollback(); } catch (x) { /* connection may already be broken */ }
    throw e;
  } finally {
    conn.release();
  }
}

// ─── Database Initialization ─────────────────────────────────────────────────

let initialized = false;

async function initializeDatabase() {
  if (initialized) return;
  initialized = true;

  // 1. Ensure the database exists (mysql2 pools connect lazily)
  const admin = await mysql.createConnection({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
  });
  try {
    await admin.query(
      `CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
    );
  } finally {
    await admin.end();
  }

  // 2. Apply schema (MySQL 8 DDL from src/main/resources/schema.sql)
  const schemaPath = path.join(__dirname, '..', 'src', 'main', 'resources', 'schema.sql');
  const rawSchema = fs.readFileSync(schemaPath, 'utf8');
  const statements = rawSchema
    .replace(/--.*$/gm, '')
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  for (const stmt of statements) {
    try {
      await pool.query(stmt);
    } catch (e) {
      if (e.code !== 'ER_TABLE_EXISTS_ERROR') {
        console.error('Schema error:', e.message.substring(0, 100));
      }
    }
  }

  // 3. pending_registrations table — the schema.sql block for this table still
  // contains SQLite-only column defaults, so it is created here in MySQL dialect.
  // Mirrors the columns the previous (SQLite) implementation created.
  await pool.query(`CREATE TABLE IF NOT EXISTS pending_registrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    role VARCHAR(30) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    college_name VARCHAR(150),
    preferred_area VARCHAR(100),
    skills TEXT,
    bio TEXT,
    emergency_contact VARCHAR(20),
    catering_name VARCHAR(150),
    business_address TEXT,
    business_phone VARCHAR(20),
    phone_verified TINYINT(1) DEFAULT 0,
    email_verified TINYINT(1) DEFAULT 0,
    status VARCHAR(30) DEFAULT 'pending',
    current_step VARCHAR(30) DEFAULT 'info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at VARCHAR(64) NOT NULL,
    INDEX idx_pend_token (token),
    INDEX idx_pend_email (email),
    INDEX idx_pend_phone (phone)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  // 4. complaint_messages table (used by the complaint chat routes)
  await pool.query(`CREATE TABLE IF NOT EXISTS complaint_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    report_id BIGINT NOT NULL,
    sender_id BIGINT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  // 5. Safe additive migrations — add columns only when missing
  const addColumn = async (table, column, ddl) => {
    try {
      const [cols] = await pool.query(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
        [DB_NAME, table, column]
      );
      if (cols.length === 0) {
        await pool.query(`ALTER TABLE \`${table}\` ADD COLUMN ${ddl}`);
      }
    } catch (e) {
      console.error(`Migration ${table}.${column} failed:`, e.message.substring(0, 120));
    }
  };

  await addColumn('catering_jobs', 'location_photo_url', 'TEXT');
  await addColumn('student_profiles', 'profile_photo_url', 'TEXT');
  await addColumn('owner_profiles', 'profile_photo_url', 'TEXT');
  // payment_records columns for Razorpay integration
  await addColumn('payment_records', 'razorpay_order_id', 'TEXT');
  await addColumn('payment_records', 'razorpay_payment_id', 'TEXT');
  await addColumn('payment_records', 'razorpay_signature', 'TEXT');
  await addColumn('payment_records', 'razorpay_receipt', 'VARCHAR(255) NULL');
  await addColumn('payment_records', 'payment_method', 'VARCHAR(50) NULL');
  await addColumn('payment_records', 'transaction_id', 'VARCHAR(64) NULL');
  await addColumn('payment_records', 'environment', `VARCHAR(10) DEFAULT 'TEST'`);
  await addColumn('payment_records', 'failure_reason', 'TEXT');
  await addColumn('payment_records', 'confirmed_paid_at', 'TIMESTAMP NULL');
  await addColumn('payment_records', 'initiated_at', 'TIMESTAMP NULL');
  await addColumn('payment_records', 'updated_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

  // Job lifecycle migrations
  await addColumn('catering_jobs', 'owner_decision', 'VARCHAR(30) NULL');
  await addColumn('catering_jobs', 'owner_decision_at', 'TIMESTAMP NULL');

  // 6. Seed data
  if (process.env.RUN_SEED !== 'false') {
    const seedPath = path.join(__dirname, '..', 'src', 'main', 'resources', 'data.sql');
    if (fs.existsSync(seedPath)) {
      const rawSeed = fs.readFileSync(seedPath, 'utf8');
      const seedStatements = rawSeed
        .replace(/--.*$/gm, '')
        .split(';')
        .map(s => s.trim())
        .filter(s => s.length > 0 && s.toUpperCase().startsWith('INSERT'));

      for (const stmt of seedStatements) {
        try {
          await pool.query(stmt);
        } catch (e) {
          if (e.code !== 'ER_DUP_ENTRY') {
            console.warn('Seed warning:', e.message.substring(0, 120));
          }
        }
      }
    }
  }

  console.log('MySQL database initialized successfully');
}

module.exports = { pool, initializeDatabase, transaction };

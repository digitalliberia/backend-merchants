require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.MERCHANT_PORT || 3000;

// ============ TRUST PROXY (for Nginx reverse proxy) ============
app.set('trust proxy', true);

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(express.json());

// ============ RATE LIMITING ============
const merchantLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please wait a moment.' }
});
app.use('/merchants', merchantLimiter);

// ============ DATABASE CONNECTION ============
let pool;

async function initDatabase() {
  pool = await mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'PJ',
    password: process.env.DB_PASSWORD || 'SergioB1994@@',
    database: process.env.DB_NAME || 'libpay',
    waitForConnections: true,
    connectionLimit: 20,
    enableKeepAlive: true
  });

  console.log('✅ Database connected');
}

// ============ HELPER FUNCTIONS ============

function generateReference() {
  return `MRCH-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

// ============ MERCHANT AUTHENTICATION ============

// Check if merchant exists
app.post('/merchants/check', async (req, res) => {
  const { dssn } = req.body;
  
  if (!dssn) {
    return res.status(400).json({ error: 'DSSN is required' });
  }
  
  try {
    const [merchants] = await pool.execute(
      'SELECT DSSN, email, business_name FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ 
        exists: false, 
        message: 'No merchant found with this DSSN' 
      });
    }
    
    const merchant = merchants[0];
    const [passwordExists] = await pool.execute(
      'SELECT password_hash IS NOT NULL as has_password FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    res.json({
      exists: true,
      has_password: passwordExists[0].has_password === 1,
      merchant: {
        dssn: merchant.DSSN,
        email: merchant.email,
        business_name: merchant.business_name
      }
    });
    
  } catch (error) {
    console.error('Merchant check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create merchant password
app.post('/merchants/create-password', async (req, res) => {
  const { dssn, password } = req.body;
  
  if (!dssn || !password) {
    return res.status(400).json({ error: 'DSSN and password are required' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  try {
    const [merchants] = await pool.execute(
      'SELECT DSSN FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ error: 'Merchant not found' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    await pool.execute(
      'UPDATE merchants SET password_hash = ? WHERE DSSN = ?',
      [hashedPassword, dssn]
    );
    
    res.json({
      success: true,
      message: 'Password created successfully. You can now log in.'
    });
    
  } catch (error) {
    console.error('Create merchant password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Merchant login
app.post('/merchants/login', async (req, res) => {
  const { dssn, password } = req.body;
  
  if (!dssn || !password) {
    return res.status(400).json({ error: 'DSSN and password are required' });
  }
  
  try {
    const [merchants] = await pool.execute(
      'SELECT * FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const merchant = merchants[0];
    
    if (!merchant.password_hash) {
      return res.status(403).json({ 
        error: 'Please create a password first',
        requires_password_setup: true
      });
    }
    
    const validPassword = await bcrypt.compare(password, merchant.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { 
        dssn: merchant.DSSN, 
        email: merchant.email, 
        business_name: merchant.business_name,
        merchant_id: merchant.merchant_id,
        type: 'merchant'
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      token: token,
      merchant: {
        dssn: merchant.DSSN,
        email: merchant.email,
        business_name: merchant.business_name,
        merchant_id: merchant.merchant_id,
        phone_number: merchant.phone_number
      }
    });
    
  } catch (error) {
    console.error('Merchant login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ MERCHANT AUTHENTICATION MIDDLEWARE ============
async function requireMerchantAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (decoded.type !== 'merchant') {
      return res.status(403).json({ error: 'Invalid token type' });
    }
    
    // Verify merchant still exists
    const [merchants] = await pool.execute(
      'SELECT DSSN, email, business_name, merchant_id FROM merchants WHERE DSSN = ?',
      [decoded.dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(401).json({ error: 'Merchant not found' });
    }
    
    req.merchant = merchants[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============ MERCHANT PROFILE ============

app.get('/merchants/profile', requireMerchantAuth, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        DSSN: req.merchant.DSSN,
        business_name: req.merchant.business_name,
        merchant_id: req.merchant.merchant_id,
        email: req.merchant.email
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ WALLET BALANCE (Using wallets table) ============

app.get('/merchants/wallet', requireMerchantAuth, async (req, res) => {
  try {
    const [wallets] = await pool.execute(
      'SELECT balance as usd_balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    if (wallets.length === 0) {
      return res.json({
        success: true,
        data: {
          usd_balance: 0,
          lrd_balance: 0
        }
      });
    }
    
    res.json({
      success: true,
      data: {
        usd_balance: parseFloat(wallets[0].usd_balance) || 0,
        lrd_balance: parseFloat(wallets[0].lrd_balance) || 0
      }
    });
  } catch (error) {
    console.error('Get wallet error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ BUSINESS STATISTICS ============

app.get('/merchants/stats', requireMerchantAuth, async (req, res) => {
  try {
    const [salesStats] = await pool.execute(
      `SELECT 
        COALESCE(SUM(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as total_sales_usd,
        COALESCE(SUM(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as total_sales_lrd,
        COUNT(*) as total_transactions
       FROM transactions
       WHERE recipient_email = ? AND status = 'completed'`,
      [req.merchant.email]
    );
    
    res.json({
      success: true,
      data: {
        total_sales: parseFloat(salesStats[0]?.total_sales_usd || 0),
        total_sales_lrd: parseFloat(salesStats[0]?.total_sales_lrd || 0),
        total_transactions: parseInt(salesStats[0]?.total_transactions || 0),
        average_order_value: salesStats[0]?.total_transactions > 0 
          ? parseFloat(salesStats[0]?.total_sales_usd / salesStats[0]?.total_transactions) 
          : 0,
        monthly_growth: 0,
        pending_orders: 0,
        completed_orders: parseInt(salesStats[0]?.total_transactions || 0),
        top_customers: 0
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ TRANSACTIONS (FIXED - Using query instead of execute for LIMIT) ============

app.get('/merchants/transactions', requireMerchantAuth, async (req, res) => {
  const { limit = 50 } = req.query;
  const limitNum = parseInt(limit) || 50;
  
  try {
    // Use query() instead of execute() to avoid parameter binding issues with LIMIT
    const [transactions] = await pool.query(
      `SELECT 
        transactionId as id,
        reference,
        amount,
        currency,
        status,
        notes as description,
        purpose,
        created_at,
        sender_email,
        recipient_email,
        transaction_type as type
      FROM transactions
      WHERE sender_email = ? OR recipient_email = ?
      ORDER BY created_at DESC
      LIMIT ${limitNum}`,
      [req.merchant.email, req.merchant.email]
    );
    
    const formattedTransactions = transactions.map(t => {
      const isSender = t.sender_email === req.merchant.email;
      return {
        id: t.id,
        reference: t.reference,
        amount: parseFloat(t.amount),
        currency: t.currency,
        status: t.status,
        description: t.description || '',
        purpose: t.purpose || '',
        created_at: t.created_at,
        type: isSender ? 'debit' : 'credit',
        counterparty_email: isSender ? t.recipient_email : t.sender_email,
        counterparty_name: isSender ? t.recipient_email : t.sender_email
      };
    });
    
    res.json({
      success: true,
      data: formattedTransactions
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.json({
      success: true,
      data: []
    });
  }
});

// ============ DASHBOARD OVERVIEW ============

app.get('/merchants/dashboard/overview', requireMerchantAuth, async (req, res) => {
  try {
    const [wallets] = await pool.execute(
      'SELECT balance as usd_balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    const [recentTransactions] = await pool.query(
      `SELECT 
        transactionId as id,
        reference,
        amount,
        currency,
        status,
        notes as description,
        created_at,
        sender_email,
        recipient_email
      FROM transactions
      WHERE sender_email = ? OR recipient_email = ?
      ORDER BY created_at DESC
      LIMIT 5`,
      [req.merchant.email, req.merchant.email]
    );
    
    res.json({
      success: true,
      data: {
        wallet: {
          usd_balance: parseFloat(wallets[0]?.usd_balance || 0),
          lrd_balance: parseFloat(wallets[0]?.lrd_balance || 0)
        },
        recent_transactions: recentTransactions.map(t => ({
          ...t,
          amount: parseFloat(t.amount),
          is_sender: t.sender_email === req.merchant.email
        }))
      }
    });
  } catch (error) {
    console.error('Dashboard overview error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ HEALTH CHECK ============

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'merchants', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============

async function start() {
  await initDatabase();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🏪 Merchant service running on port ${PORT}`);
    console.log(`   Health: http://localhost:${PORT}/health`);
    console.log(`   Endpoints:`);
    console.log(`   - POST /merchants/check`);
    console.log(`   - POST /merchants/create-password`);
    console.log(`   - POST /merchants/login`);
    console.log(`   - GET  /merchants/profile`);
    console.log(`   - GET  /merchants/wallet`);
    console.log(`   - GET  /merchants/stats`);
    console.log(`   - GET  /merchants/transactions`);
    console.log(`   - GET  /merchants/dashboard/overview`);
  });
}

start().catch(console.error);

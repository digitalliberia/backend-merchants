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
app.set('trust proxy', 1);

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(express.json());

// ============ RATE LIMITING ============
const merchantLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please wait a moment.' },
  trustProxy: true
});
app.use('/merchants', merchantLimiter);

// ============ DATABASE CONNECTION ============
let pool;

async function initDatabase() {
  pool = await mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'libpay',
    waitForConnections: true,
    connectionLimit: 20,
    enableKeepAlive: true
  });

  console.log('✅ Database connected');

  // Ensure merchants table exists with correct structure
  const ensureMerchantsTableSQL = `
    CREATE TABLE IF NOT EXISTS merchants (
      DSSN VARCHAR(50) PRIMARY KEY,
      business_name VARCHAR(255) NOT NULL,
      merchant_id INT UNIQUE AUTO_INCREMENT,
      business_registration_number VARCHAR(100) UNIQUE NOT NULL,
      tax_identification_number VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      phone_number VARCHAR(15) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NULL,
      reset_token VARCHAR(255) NULL,
      reset_token_expires DATETIME NULL,
      status ENUM('active', 'suspended', 'pending') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_email (email),
      INDEX idx_merchant_id (merchant_id),
      INDEX idx_status (status)
    );
  `;

  try {
    await pool.execute(ensureMerchantsTableSQL);
    console.log('✅ merchants table ready');
  } catch (err) {
    console.log('⚠️ merchants table error:', err.message);
  }

  // Ensure merchant_wallets table exists
  const ensureMerchantWalletsSQL = `
    CREATE TABLE IF NOT EXISTS merchant_wallets (
      id INT PRIMARY KEY AUTO_INCREMENT,
      merchant_dssn VARCHAR(50) NOT NULL,
      usd_balance DECIMAL(10,2) DEFAULT 0.00,
      lrd_balance DECIMAL(10,2) DEFAULT 0.00,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (merchant_dssn) REFERENCES merchants(DSSN) ON DELETE CASCADE,
      UNIQUE KEY unique_merchant (merchant_dssn),
      INDEX idx_merchant (merchant_dssn)
    );
  `;

  try {
    await pool.execute(ensureMerchantWalletsSQL);
    console.log('✅ merchant_wallets table ready');
  } catch (err) {
    console.log('⚠️ merchant_wallets table error:', err.message);
  }

  // Ensure merchant_transactions table exists
  const ensureMerchantTransactionsSQL = `
    CREATE TABLE IF NOT EXISTS merchant_transactions (
      id INT PRIMARY KEY AUTO_INCREMENT,
      reference VARCHAR(36) UNIQUE NOT NULL,
      merchant_dssn VARCHAR(50) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency ENUM('USD', 'LRD') NOT NULL,
      type ENUM('payment', 'transfer', 'refund', 'withdrawal') NOT NULL,
      status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
      recipient_email VARCHAR(255),
      recipient_dssn VARCHAR(50),
      sender_email VARCHAR(255),
      sender_dssn VARCHAR(50),
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (merchant_dssn) REFERENCES merchants(DSSN) ON DELETE CASCADE,
      INDEX idx_merchant (merchant_dssn),
      INDEX idx_reference (reference),
      INDEX idx_status (status),
      INDEX idx_created_at (created_at)
    );
  `;

  try {
    await pool.execute(ensureMerchantTransactionsSQL);
    console.log('✅ merchant_transactions table ready');
  } catch (err) {
    console.log('⚠️ merchant_transactions table error:', err.message);
  }

  // Create trigger to automatically create wallet for new merchants
  const createWalletTriggerSQL = `
    DROP TRIGGER IF EXISTS create_merchant_wallet;
    CREATE TRIGGER create_merchant_wallet
    AFTER INSERT ON merchants
    FOR EACH ROW
    BEGIN
      INSERT INTO merchant_wallets (merchant_dssn, usd_balance, lrd_balance)
      VALUES (NEW.DSSN, 0.00, 0.00)
      ON DUPLICATE KEY UPDATE updated_at = NOW();
    END;
  `;

  try {
    await pool.execute(createWalletTriggerSQL);
    console.log('✅ merchant wallet trigger ready');
  } catch (err) {
    console.log('⚠️ Trigger may already exist:', err.message);
  }
}

// ============ HELPER FUNCTIONS ============

// Generate unique reference
function generateReference() {
  return 'TXN-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// Get merchant wallet balance
async function getMerchantWallet(merchantDssn) {
  try {
    const [wallets] = await pool.execute(
      'SELECT usd_balance, lrd_balance FROM merchant_wallets WHERE merchant_dssn = ?',
      [merchantDssn]
    );
    
    if (wallets.length === 0) {
      return { usd_balance: 0, lrd_balance: 0 };
    }
    
    return {
      usd_balance: parseFloat(wallets[0].usd_balance) || 0,
      lrd_balance: parseFloat(wallets[0].lrd_balance) || 0
    };
  } catch (error) {
    console.error('Error fetching merchant wallet:', error.message);
    return { usd_balance: 0, lrd_balance: 0 };
  }
}

// Update merchant wallet balance
async function updateMerchantBalance(merchantDssn, currency, amount, operation) {
  const balanceField = currency === 'USD' ? 'usd_balance' : 'lrd_balance';
  const operator = operation === 'add' ? '+' : '-';
  
  const [result] = await pool.execute(
    `UPDATE merchant_wallets 
     SET ${balanceField} = ${balanceField} ${operator} ?, updated_at = NOW()
     WHERE merchant_dssn = ?`,
    [Math.abs(amount), merchantDssn]
  );
  
  return result.affectedRows > 0;
}

// Get merchant by DSSN
async function getMerchantByDSSN(dssn) {
  const [merchants] = await pool.execute(
    'SELECT DSSN, business_name, merchant_id, business_registration_number, tax_identification_number, email, phone_number, status, password_hash, created_at FROM merchants WHERE DSSN = ?',
    [dssn]
  );
  return merchants[0] || null;
}

// Get merchant by email
async function getMerchantByEmail(email) {
  const [merchants] = await pool.execute(
    'SELECT DSSN, business_name, merchant_id, business_registration_number, tax_identification_number, email, phone_number, status, password_hash, created_at FROM merchants WHERE email = ?',
    [email]
  );
  return merchants[0] || null;
}

// ============ MERCHANT AUTHENTICATION ENDPOINTS ============

// Check if merchant exists and if password is set
app.post('/merchants/check', async (req, res) => {
  const { dssn } = req.body;
  
  if (!dssn) {
    return res.status(400).json({ error: 'DSSN is required' });
  }
  
  try {
    const [merchants] = await pool.execute(
      'SELECT DSSN, email, business_name, status FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ 
        exists: false, 
        message: 'No merchant found with this DSSN. Please contact support.' 
      });
    }
    
    const merchant = merchants[0];
    
    if (merchant.status === 'suspended') {
      return res.status(403).json({
        exists: true,
        has_password: false,
        suspended: true,
        message: 'Your merchant account has been suspended. Please contact support.'
      });
    }
    
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
        business_name: merchant.business_name,
        status: merchant.status
      }
    });
    
  } catch (error) {
    console.error('Merchant check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create merchant password (first time setup)
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
      'SELECT DSSN, email, business_name, status FROM merchants WHERE DSSN = ?',
      [dssn]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ error: 'Merchant not found' });
    }
    
    const merchant = merchants[0];
    
    if (merchant.status === 'suspended') {
      return res.status(403).json({ error: 'Account suspended. Cannot set password.' });
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
    
    if (merchant.status === 'suspended') {
      return res.status(403).json({ error: 'Your account has been suspended. Please contact support.' });
    }
    
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
        phone_number: merchant.phone_number,
        status: merchant.status
      }
    });
    
  } catch (error) {
    console.error('Merchant login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify merchant token
app.post('/merchants/verify', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (decoded.type !== 'merchant') {
      return res.status(401).json({ valid: false, error: 'Invalid token type' });
    }
    
    // Check if merchant still exists and is active
    const merchant = await getMerchantByDSSN(decoded.dssn);
    
    if (!merchant || merchant.status === 'suspended') {
      return res.status(401).json({ valid: false, error: 'Account no longer active' });
    }
    
    res.json({ 
      valid: true, 
      merchant: { 
        dssn: decoded.dssn, 
        email: decoded.email,
        business_name: decoded.business_name,
        merchant_id: decoded.merchant_id
      } 
    });
    
  } catch (error) {
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
});

// ============ MERCHANT AUTHENTICATION MIDDLEWARE ============
function requireMerchantAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', code: 'UNAUTHORIZED' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (decoded.type !== 'merchant') {
      return res.status(403).json({ error: 'Invalid token type', code: 'FORBIDDEN' });
    }
    
    req.merchant = {
      dssn: decoded.dssn,
      email: decoded.email,
      business_name: decoded.business_name,
      merchant_id: decoded.merchant_id
    };
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token', code: 'UNAUTHORIZED' });
  }
}

// ============ MERCHANT PROFILE ENDPOINTS ============

// Get merchant profile
app.get('/merchants/profile', requireMerchantAuth, async (req, res) => {
  try {
    const merchant = await getMerchantByDSSN(req.merchant.dssn);
    
    if (!merchant) {
      return res.status(404).json({ error: 'Merchant not found' });
    }
    
    res.json({
      success: true,
      data: {
        DSSN: merchant.DSSN,
        business_name: merchant.business_name,
        merchant_id: merchant.merchant_id,
        business_registration_number: merchant.business_registration_number,
        tax_identification_number: merchant.tax_identification_number,
        email: merchant.email,
        phone_number: merchant.phone_number,
        status: merchant.status,
        created_at: merchant.created_at
      }
    });
  } catch (error) {
    console.error('Get merchant profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update merchant profile
app.put('/merchants/profile', requireMerchantAuth, async (req, res) => {
  const { phone_number, business_name } = req.body;
  
  try {
    const updates = [];
    const params = [];
    
    if (phone_number) {
      updates.push('phone_number = ?');
      params.push(phone_number);
    }
    
    if (business_name) {
      updates.push('business_name = ?');
      params.push(business_name);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    params.push(req.merchant.dssn);
    
    await pool.execute(
      `UPDATE merchants SET ${updates.join(', ')} WHERE DSSN = ?`,
      params
    );
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update merchant profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ WALLET ENDPOINTS ============

// Get merchant wallet balance
app.get('/merchants/wallet', requireMerchantAuth, async (req, res) => {
  try {
    const wallet = await getMerchantWallet(req.merchant.dssn);
    
    res.json({
      success: true,
      data: {
        usd_balance: wallet.usd_balance,
        lrd_balance: wallet.lrd_balance
      }
    });
  } catch (error) {
    console.error('Get wallet error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Initiate transfer from merchant wallet
app.post('/merchants/wallet/transfer', requireMerchantAuth, async (req, res) => {
  const { amount, currency, recipient_email, recipient_dssn, description } = req.body;
  
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid amount is required' });
  }
  
  if (!currency || !['USD', 'LRD'].includes(currency)) {
    return res.status(400).json({ error: 'Valid currency is required' });
  }
  
  if (!recipient_email && !recipient_dssn) {
    return res.status(400).json({ error: 'Recipient email or DSSN is required' });
  }
  
  try {
    const wallet = await getMerchantWallet(req.merchant.dssn);
    const balance = currency === 'USD' ? wallet.usd_balance : wallet.lrd_balance;
    
    if (balance < amount) {
      return res.status(400).json({ error: `Insufficient ${currency} balance` });
    }
    
    // Find recipient user
    let recipient = null;
    if (recipient_email) {
      const [users] = await pool.execute(
        'SELECT email, DSSN, first_name, last_name FROM users WHERE email = ?',
        [recipient_email]
      );
      if (users.length > 0) recipient = users[0];
    } else if (recipient_dssn) {
      const [users] = await pool.execute(
        'SELECT email, DSSN, first_name, last_name FROM users WHERE DSSN = ?',
        [recipient_dssn]
      );
      if (users.length > 0) recipient = users[0];
    }
    
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    // Update merchant balance
    await updateMerchantBalance(req.merchant.dssn, currency, amount, 'subtract');
    
    // Update recipient wallet
    await pool.execute(
      `UPDATE wallets 
       SET ${currency === 'USD' ? 'balance' : 'lrd_balance'} = ${currency === 'USD' ? 'balance' : 'lrd_balance'} + ?
       WHERE email = ?`,
      [amount, recipient.email]
    );
    
    // Create transaction record
    const reference = generateReference();
    await pool.execute(
      `INSERT INTO merchant_transactions 
       (reference, merchant_dssn, amount, currency, type, status, recipient_email, recipient_dssn, description)
       VALUES (?, ?, ?, ?, 'transfer', 'completed', ?, ?, ?)`,
      [reference, req.merchant.dssn, amount, currency, recipient.email, recipient.DSSN, description || `Transfer to ${recipient.email}`]
    );
    
    res.json({
      success: true,
      message: `Transfer of ${currency} ${amount.toLocaleString()} completed successfully`,
      data: { reference, new_balance: balance - amount }
    });
    
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ BUSINESS STATISTICS ENDPOINTS ============

// Get business statistics
app.get('/merchants/stats', requireMerchantAuth, async (req, res) => {
  try {
    // Get total sales from transactions where merchant received payments
    const [salesStats] = await pool.execute(
      `SELECT 
        COALESCE(SUM(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as total_sales_usd,
        COALESCE(SUM(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as total_sales_lrd,
        COUNT(*) as total_transactions,
        COALESCE(AVG(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as avg_order_usd,
        COALESCE(AVG(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as avg_order_lrd
       FROM merchant_transactions
       WHERE merchant_dssn = ? AND type = 'payment' AND status = 'completed'`,
      [req.merchant.dssn]
    );
    
    // Get monthly growth (compare last 30 days with previous 30 days)
    const [growthStats] = await pool.execute(
      `SELECT 
        COALESCE(SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN amount ELSE 0 END), 0) as recent_sales,
        COALESCE(SUM(CASE WHEN created_at BETWEEN DATE_SUB(NOW(), INTERVAL 60 DAY) AND DATE_SUB(NOW(), INTERVAL 30 DAY) THEN amount ELSE 0 END), 0) as previous_sales
       FROM merchant_transactions
       WHERE merchant_dssn = ? AND type = 'payment' AND status = 'completed'`,
      [req.merchant.dssn]
    );
    
    const recentSales = parseFloat(growthStats[0]?.recent_sales || 0);
    const previousSales = parseFloat(growthStats[0]?.previous_sales || 0);
    const monthlyGrowth = previousSales > 0 ? ((recentSales - previousSales) / previousSales) * 100 : recentSales > 0 ? 100 : 0;
    
    // Get order statistics
    const [orderStats] = await pool.execute(
      `SELECT 
        COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed_orders,
        COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as pending_orders
       FROM merchant_transactions
       WHERE merchant_dssn = ?`,
      [req.merchant.dssn]
    );
    
    // Get top customers count
    const [customerStats] = await pool.execute(
      `SELECT COUNT(DISTINCT recipient_email) as unique_customers
       FROM merchant_transactions
       WHERE merchant_dssn = ? AND type = 'payment' AND status = 'completed'`,
      [req.merchant.dssn]
    );
    
    res.json({
      success: true,
      data: {
        total_sales: parseFloat(salesStats[0]?.total_sales_usd || 0),
        total_sales_lrd: parseFloat(salesStats[0]?.total_sales_lrd || 0),
        total_transactions: parseInt(salesStats[0]?.total_transactions || 0),
        average_order_value: parseFloat(salesStats[0]?.avg_order_usd || 0),
        average_order_value_lrd: parseFloat(salesStats[0]?.avg_order_lrd || 0),
        monthly_growth: Math.round(monthlyGrowth * 10) / 10,
        pending_orders: parseInt(orderStats[0]?.pending_orders || 0),
        completed_orders: parseInt(orderStats[0]?.completed_orders || 0),
        top_customers: parseInt(customerStats[0]?.unique_customers || 0)
      }
    });
  } catch (error) {
    console.error('Get business stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ TRANSACTION ENDPOINTS (FIXED) ============

// Get merchant transactions - FIXED VERSION
app.get('/merchants/transactions', requireMerchantAuth, async (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  
  try {
    console.log(`Fetching transactions for merchant: ${req.merchant.dssn}, limit: ${limit}, offset: ${offset}`);
    
    const [transactions] = await pool.execute(
      `SELECT id, reference, amount, currency, type, status, recipient_email, sender_email, description, created_at
       FROM merchant_transactions
       WHERE merchant_dssn = ?
       ORDER BY created_at DESC
       LIMIT ?
       OFFSET ?`,
      [req.merchant.dssn, limit, offset]
    );
    
    console.log(`Found ${transactions.length} transactions`);
    
    res.json({
      success: true,
      data: transactions
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get single transaction details
app.get('/merchants/transactions/:reference', requireMerchantAuth, async (req, res) => {
  const { reference } = req.params;
  
  try {
    const [transactions] = await pool.execute(
      `SELECT * FROM merchant_transactions
       WHERE reference = ? AND merchant_dssn = ?`,
      [reference, req.merchant.dssn]
    );
    
    if (transactions.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json({
      success: true,
      data: transactions[0]
    });
  } catch (error) {
    console.error('Get transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ PRODUCT MANAGEMENT ENDPOINTS ============

// Get all products
app.get('/merchants/products', requireMerchantAuth, async (req, res) => {
  const { limit = 100, offset = 0, category, status } = req.query;
  
  try {
    let query = `
      SELECT id, name, description, price_usd, price_lrd, stock, category, image_url, status, sales_count, created_at
      FROM merchant_products
      WHERE merchant_dssn = ?
    `;
    const params = [req.merchant.dssn];
    
    if (category && category !== 'all') {
      query += ' AND category = ?';
      params.push(category);
    }
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const [products] = await pool.execute(query, params);
    
    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add new product
app.post('/merchants/products', requireMerchantAuth, async (req, res) => {
  const { name, description, price_usd, price_lrd, stock, category, image_url } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Product name is required' });
  }
  
  try {
    const [result] = await pool.execute(
      `INSERT INTO merchant_products 
       (merchant_dssn, name, description, price_usd, price_lrd, stock, category, image_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.merchant.dssn, name, description || null, price_usd || 0, price_lrd || 0, stock || 0, category || null, image_url || null]
    );
    
    res.json({
      success: true,
      message: 'Product added successfully',
      data: { id: result.insertId }
    });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update product
app.put('/merchants/products/:productId', requireMerchantAuth, async (req, res) => {
  const { productId } = req.params;
  const { name, description, price_usd, price_lrd, stock, category, image_url, status } = req.body;
  
  try {
    const updates = [];
    const params = [];
    
    if (name !== undefined) {
      updates.push('name = ?');
      params.push(name);
    }
    if (description !== undefined) {
      updates.push('description = ?');
      params.push(description);
    }
    if (price_usd !== undefined) {
      updates.push('price_usd = ?');
      params.push(price_usd);
    }
    if (price_lrd !== undefined) {
      updates.push('price_lrd = ?');
      params.push(price_lrd);
    }
    if (stock !== undefined) {
      updates.push('stock = ?');
      params.push(stock);
    }
    if (category !== undefined) {
      updates.push('category = ?');
      params.push(category);
    }
    if (image_url !== undefined) {
      updates.push('image_url = ?');
      params.push(image_url);
    }
    if (status !== undefined) {
      updates.push('status = ?');
      params.push(status);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    params.push(productId, req.merchant.dssn);
    
    await pool.execute(
      `UPDATE merchant_products SET ${updates.join(', ')} WHERE id = ? AND merchant_dssn = ?`,
      params
    );
    
    res.json({ success: true, message: 'Product updated successfully' });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete product
app.delete('/merchants/products/:productId', requireMerchantAuth, async (req, res) => {
  const { productId } = req.params;
  
  try {
    await pool.execute(
      'DELETE FROM merchant_products WHERE id = ? AND merchant_dssn = ?',
      [productId, req.merchant.dssn]
    );
    
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ ORDER MANAGEMENT ENDPOINTS ============

// Get all orders
app.get('/merchants/orders', requireMerchantAuth, async (req, res) => {
  const { limit = 50, offset = 0, status } = req.query;
  
  try {
    let query = `
      SELECT id, order_number, customer_name, customer_email, customer_phone, total_usd, total_lrd, status, items, created_at
      FROM merchant_orders
      WHERE merchant_dssn = ?
    `;
    const params = [req.merchant.dssn];
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const [orders] = await pool.execute(query, params);
    
    res.json({
      success: true,
      data: orders
    });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update order status
app.put('/merchants/orders/:orderNumber/status', requireMerchantAuth, async (req, res) => {
  const { orderNumber } = req.params;
  const { status } = req.body;
  
  if (!status || !['pending', 'processing', 'completed', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Valid status is required' });
  }
  
  try {
    await pool.execute(
      'UPDATE merchant_orders SET status = ? WHERE order_number = ? AND merchant_dssn = ?',
      [status, orderNumber, req.merchant.dssn]
    );
    
    res.json({ success: true, message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ DASHBOARD OVERVIEW ============
app.get('/merchants/dashboard/overview', requireMerchantAuth, async (req, res) => {
  try {
    const wallet = await getMerchantWallet(req.merchant.dssn);
    
    const [salesStats] = await pool.execute(
      `SELECT 
        COALESCE(SUM(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as total_sales_usd,
        COALESCE(SUM(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as total_sales_lrd,
        COUNT(*) as total_transactions
       FROM merchant_transactions
       WHERE merchant_dssn = ? AND type = 'payment' AND status = 'completed'
       AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)`,
      [req.merchant.dssn]
    );
    
    const [recentTransactions] = await pool.execute(
      `SELECT id, reference, amount, currency, type, status, recipient_email, description, created_at
       FROM merchant_transactions
       WHERE merchant_dssn = ?
       ORDER BY created_at DESC
       LIMIT 10`,
      [req.merchant.dssn]
    );
    
    res.json({
      success: true,
      data: {
        wallet: {
          usd_balance: wallet.usd_balance,
          lrd_balance: wallet.lrd_balance
        },
        monthly_sales: {
          usd: parseFloat(salesStats[0]?.total_sales_usd || 0),
          lrd: parseFloat(salesStats[0]?.total_sales_lrd || 0),
          transactions: parseInt(salesStats[0]?.total_transactions || 0)
        },
        recent_transactions: recentTransactions
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
    console.log(`   - POST /merchants/wallet/transfer`);
    console.log(`   - GET  /merchants/stats`);
    console.log(`   - GET  /merchants/transactions`);
    console.log(`   - GET  /merchants/products`);
    console.log(`   - POST /merchants/products`);
    console.log(`   - GET  /merchants/orders`);
  });
}

start().catch(console.error);

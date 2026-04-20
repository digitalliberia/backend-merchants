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

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(express.json());

// ============ RATE LIMITING ============
const sendMoneyLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 10, 
  message: { error: 'Too many transactions. Please wait a moment.' } 
});
const lookupLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 30, 
  message: { error: 'Too many lookup requests. Please slow down.' } 
});

// Apply specific rate limits to wallet endpoints
app.use('/merchants/wallet/send', sendMoneyLimiter);
app.use('/merchants/wallet/lookup', lookupLimiter);

// Simple rate limiting for other endpoints
const requestCounts = new Map();
setInterval(() => requestCounts.clear(), 60000);

function simpleRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const count = requestCounts.get(ip) || 0;
  
  if (count > 100) {
    return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  }
  
  requestCounts.set(ip, count + 1);
  next();
}

app.use('/merchants', simpleRateLimit);

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
  return `TXN-${Date.now()}-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
}

function generateMerchantReference() {
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

// ============ WALLET BALANCE ============

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

// ============ LOOKUP USER (for sending money) ============

app.post('/merchants/wallet/lookup', requireMerchantAuth, async (req, res) => {
  const { contact } = req.body;
  
  if (!contact) {
    return res.status(400).json({ error: 'Contact is required' });
  }
  
  try {
    const isEmail = contact.includes('@');
    const query = isEmail 
      ? 'SELECT email, first_name, last_name, phone, is_active FROM users WHERE email = ?'
      : 'SELECT email, first_name, last_name, phone, is_active FROM users WHERE phone = ?';
    
    const [users] = await pool.execute(query, [contact]);
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = users[0];
    
    if (user.is_active === 0) {
      return res.status(403).json({ error: 'User account is frozen. Cannot send money.' });
    }
    
    res.json({ 
      success: true, 
      data: { 
        email: user.email, 
        first_name: user.first_name, 
        last_name: user.last_name, 
        phone: user.phone, 
        is_active: user.is_active === 1 
      } 
    });
  } catch (error) {
    console.error('Lookup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ SEND MONEY ============

app.post('/merchants/wallet/send', requireMerchantAuth, async (req, res) => {
  const { recipient_contact, amount, currency, description, purpose } = req.body;
  
  if (!recipient_contact) {
    return res.status(400).json({ error: 'Recipient contact is required' });
  }
  
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid amount is required' });
  }
  
  if (!['USD', 'LRD'].includes(currency)) {
    return res.status(400).json({ error: 'Invalid currency' });
  }
  
  let connection;
  
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // Find recipient
    const isEmail = recipient_contact.includes('@');
    const recipientQuery = isEmail 
      ? 'SELECT email, first_name, last_name, is_active FROM users WHERE email = ?'
      : 'SELECT email, first_name, last_name, is_active FROM users WHERE phone = ?';
    
    const [recipients] = await connection.execute(recipientQuery, [recipient_contact]);
    
    if (recipients.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Recipient not found' });
    }
    
    const recipient = recipients[0];
    
    // Check if sending to self
    if (recipient.email === req.merchant.email) {
      await connection.rollback();
      return res.status(400).json({ error: 'Cannot send money to yourself' });
    }
    
    // Check if recipient account is active
    if (recipient.is_active === 0) {
      await connection.rollback();
      return res.status(403).json({ error: 'Recipient account is frozen. Cannot send money.' });
    }
    
    // Get sender's wallet balance
    const [senderWallets] = await connection.execute(
      'SELECT balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    if (senderWallets.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Sender wallet not found' });
    }
    
    const balanceField = currency === 'USD' ? 'balance' : 'lrd_balance';
    const currentBalance = parseFloat(senderWallets[0][balanceField]);
    
    if (currentBalance < amount) {
      await connection.rollback();
      return res.status(400).json({ error: `Insufficient ${currency} balance` });
    }
    
    // Update sender's wallet (subtract)
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} - ? WHERE email = ?`,
      [amount, req.merchant.email]
    );
    
    // Update recipient's wallet (add)
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} + ? WHERE email = ?`,
      [amount, recipient.email]
    );
    
    // Create transaction record
    const reference = generateReference();
    const transactionPurpose = purpose || description || 'Money transfer';
    
    await connection.execute(
      `INSERT INTO transactions (reference, sender_email, recipient_email, amount, currency, original_amount, status, transaction_type, notes, purpose, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, 'completed', 'transfer', ?, ?, NOW())`,
      [reference, req.merchant.email, recipient.email, amount, currency, amount, transactionPurpose, transactionPurpose]
    );
    
    await connection.commit();
    
    // Get updated wallet balance
    const [updatedWallet] = await pool.execute(
      'SELECT balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    res.json({ 
      success: true, 
      message: `${currency} ${amount.toLocaleString()} sent successfully`, 
      data: { 
        transaction_reference: reference, 
        amount, 
        currency, 
        purpose: transactionPurpose, 
        recipient: { 
          name: `${recipient.first_name} ${recipient.last_name}`, 
          email: recipient.email 
        }, 
        new_balance_usd: parseFloat(updatedWallet[0].balance), 
        new_balance_lrd: parseFloat(updatedWallet[0].lrd_balance) 
      } 
    });
    
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Send money error:', error);
    res.status(500).json({ error: error.message || 'Internal server error' });
  } finally {
    if (connection) connection.release();
  }
});

// ============ GET TRANSACTIONS (for wallet) ============

app.get('/merchants/wallet/transactions', requireMerchantAuth, async (req, res) => {
  const { limit = 50 } = req.query;
  const limitNum = parseInt(limit) || 50;
  
  try {
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
    
    // Format transactions with counterparty names
    const formattedTransactions = [];
    
    for (const t of transactions) {
      const isSender = t.sender_email === req.merchant.email;
      let counterpartyName = isSender ? t.recipient_email : t.sender_email;
      let counterpartyEmail = isSender ? t.recipient_email : t.sender_email;
      
      // Try to get real name from users table
      try {
        const otherEmail = isSender ? t.recipient_email : t.sender_email;
        const [users] = await pool.query(
          'SELECT first_name, last_name FROM users WHERE email = ?',
          [otherEmail]
        );
        if (users.length > 0) {
          counterpartyName = `${users[0].first_name} ${users[0].last_name}`;
        }
      } catch (err) {
        // Use email as fallback
      }
      
      formattedTransactions.push({
        id: t.id,
        reference: t.reference,
        amount: parseFloat(t.amount),
        currency: t.currency,
        status: t.status,
        description: t.description || '',
        purpose: t.purpose || '',
        created_at: t.created_at,
        type: isSender ? 'debit' : 'credit',
        counterparty_name: counterpartyName,
        counterparty_email: counterpartyEmail,
        is_sender: isSender
      });
    }
    
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

// ============ TRANSACTIONS (legacy) ============

app.get('/merchants/transactions', requireMerchantAuth, async (req, res) => {
  const { limit = 50 } = req.query;
  const limitNum = parseInt(limit) || 50;
  
  try {
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

// ============ BULK PAYOUT / SALARY PAYMENT ============

const bulkPayoutLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 5, 
  message: { error: 'Too many bulk payout requests. Please wait a moment.' } 
});
app.use('/merchants/wallet/bulk-payout', bulkPayoutLimiter);

app.post('/merchants/wallet/bulk-payout', requireMerchantAuth, async (req, res) => {
  const { payments, currency, description, purpose } = req.body;
  
  // payments should be an array of { recipient_contact, amount, note? }
  if (!payments || !Array.isArray(payments) || payments.length === 0) {
    return res.status(400).json({ error: 'Payments array is required' });
  }
  
  if (!['USD', 'LRD'].includes(currency)) {
    return res.status(400).json({ error: 'Invalid currency' });
  }
  
  if (payments.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 payments per batch' });
  }
  
  let connection;
  const results = {
    successful: [],
    failed: [],
    total_amount: 0,
    total_successful: 0,
    total_failed: 0
  };
  
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // Calculate total amount and validate recipients
    const validatedPayments = [];
    
    for (const payment of payments) {
      const { recipient_contact, amount, note } = payment;
      
      if (!recipient_contact || !amount || amount <= 0) {
        results.failed.push({ 
          recipient_contact, 
          amount, 
          error: 'Invalid recipient or amount',
          note 
        });
        results.total_failed++;
        continue;
      }
      
      // Find recipient
      const isEmail = recipient_contact.includes('@');
      const recipientQuery = isEmail 
        ? 'SELECT email, first_name, last_name, is_active FROM users WHERE email = ?'
        : 'SELECT email, first_name, last_name, is_active FROM users WHERE phone = ?';
      
      const [recipients] = await connection.execute(recipientQuery, [recipient_contact]);
      
      if (recipients.length === 0) {
        results.failed.push({ 
          recipient_contact, 
          amount, 
          error: 'Recipient not found',
          note 
        });
        results.total_failed++;
        continue;
      }
      
      const recipient = recipients[0];
      
      if (recipient.email === req.merchant.email) {
        results.failed.push({ 
          recipient_contact, 
          amount, 
          error: 'Cannot pay yourself',
          note 
        });
        results.total_failed++;
        continue;
      }
      
      if (recipient.is_active === 0) {
        results.failed.push({ 
          recipient_contact, 
          amount, 
          error: 'Recipient account is frozen',
          note 
        });
        results.total_failed++;
        continue;
      }
      
      validatedPayments.push({
        recipient,
        amount,
        note: note || description || 'Salary payment'
      });
      
      results.total_amount += amount;
    }
    
    // Check if merchant has sufficient balance
    const [senderWallets] = await connection.execute(
      'SELECT balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    const balanceField = currency === 'USD' ? 'balance' : 'lrd_balance';
    const currentBalance = parseFloat(senderWallets[0][balanceField]);
    
    if (currentBalance < results.total_amount) {
      await connection.rollback();
      return res.status(400).json({ 
        error: `Insufficient ${currency} balance. Need ${results.total_amount}, have ${currentBalance}` 
      });
    }
    
    // Process each payment
    for (const payment of validatedPayments) {
      try {
        // Update sender's wallet (subtract)
        await connection.execute(
          `UPDATE wallets SET ${balanceField} = ${balanceField} - ? WHERE email = ?`,
          [payment.amount, req.merchant.email]
        );
        
        // Update recipient's wallet (add)
        await connection.execute(
          `UPDATE wallets SET ${balanceField} = ${balanceField} + ? WHERE email = ?`,
          [payment.amount, payment.recipient.email]
        );
        
        // Create transaction record
        const reference = generateReference();
        const transactionPurpose = purpose || payment.note || 'Salary payment';
        
        await connection.execute(
          `INSERT INTO transactions (reference, sender_email, recipient_email, amount, currency, original_amount, status, transaction_type, notes, purpose, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, 'completed', 'transfer', ?, ?, NOW())`,
          [reference, req.merchant.email, payment.recipient.email, payment.amount, currency, payment.amount, payment.note, transactionPurpose]
        );
        
        results.successful.push({
          recipient_contact: payment.recipient.email,
          recipient_name: `${payment.recipient.first_name} ${payment.recipient.last_name}`,
          amount: payment.amount,
          reference,
          note: payment.note
        });
        results.total_successful++;
        
      } catch (err) {
        results.failed.push({
          recipient_contact: payment.recipient.email,
          amount: payment.amount,
          error: err.message,
          note: payment.note
        });
        results.total_failed++;
      }
    }
    
    await connection.commit();
    
    // Get updated wallet balance
    const [updatedWallet] = await pool.execute(
      'SELECT balance, lrd_balance FROM wallets WHERE email = ?',
      [req.merchant.email]
    );
    
    res.json({
      success: true,
      message: `Bulk payout completed: ${results.total_successful} successful, ${results.total_failed} failed`,
      data: {
        summary: {
          total_successful: results.total_successful,
          total_failed: results.total_failed,
          total_amount: results.total_amount,
          currency,
          new_balance_usd: parseFloat(updatedWallet[0].balance),
          new_balance_lrd: parseFloat(updatedWallet[0].lrd_balance)
        },
        successful_transactions: results.successful,
        failed_transactions: results.failed
      }
    });
    
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Bulk payout error:', error);
    res.status(500).json({ error: error.message || 'Internal server error' });
  } finally {
    if (connection) connection.release();
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
    console.log(`   - POST /merchants/wallet/lookup`);
    console.log(`   - POST /merchants/wallet/send`);
    console.log(`   - GET  /merchants/wallet/transactions`);
    console.log(`   - GET  /merchants/stats`);
    console.log(`   - GET  /merchants/transactions`);
    console.log(`   - GET  /merchants/dashboard/overview`);
  });
}

start().catch(console.error);

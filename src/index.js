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
const bulkPayoutLimiter = rateLimit({ 
  windowMs: 60 * 1000, 
  max: 5, 
  message: { error: 'Too many bulk payout requests. Please wait a moment.' } 
});

// Apply specific rate limits to wallet endpoints
app.use('/merchants/wallet/send', sendMoneyLimiter);
app.use('/merchants/wallet/lookup', lookupLimiter);
app.use('/merchants/wallet/bulk-payout', bulkPayoutLimiter);

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

function generateInvoiceNumber() {
  return `INV-${Date.now()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
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
    const [merchants] = await pool.execute(
      `SELECT DSSN, business_name, merchant_id, business_registration_number, 
              tax_identification_number, email, phone_number, status, created_at 
       FROM merchants WHERE DSSN = ?`,
      [req.merchant.DSSN]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ error: 'Merchant not found' });
    }
    
    res.json({
      success: true,
      data: merchants[0]
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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
    
    params.push(req.merchant.DSSN);
    
    await pool.execute(
      `UPDATE merchants SET ${updates.join(', ')} WHERE DSSN = ?`,
      params
    );
    
    const [updated] = await pool.execute(
      `SELECT DSSN, business_name, merchant_id, business_registration_number, 
              tax_identification_number, email, phone_number, status 
       FROM merchants WHERE DSSN = ?`,
      [req.merchant.DSSN]
    );
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      data: updated[0]
    });
  } catch (error) {
    console.error('Update merchant profile error:', error);
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

// ============ LOOKUP USER ============

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
    
    if (recipient.email === req.merchant.email) {
      await connection.rollback();
      return res.status(400).json({ error: 'Cannot send money to yourself' });
    }
    
    if (recipient.is_active === 0) {
      await connection.rollback();
      return res.status(403).json({ error: 'Recipient account is frozen. Cannot send money.' });
    }
    
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
    
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} - ? WHERE email = ?`,
      [amount, req.merchant.email]
    );
    
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} + ? WHERE email = ?`,
      [amount, recipient.email]
    );
    
    const reference = generateReference();
    const transactionPurpose = purpose || description || 'Money transfer';
    
    await connection.execute(
      `INSERT INTO transactions (reference, sender_email, recipient_email, amount, currency, original_amount, status, transaction_type, notes, purpose, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, 'completed', 'transfer', ?, ?, NOW())`,
      [reference, req.merchant.email, recipient.email, amount, currency, amount, transactionPurpose, transactionPurpose]
    );
    
    await connection.commit();
    
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

// ============ GET TRANSACTIONS ============

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
    
    const formattedTransactions = [];
    
    for (const t of transactions) {
      const isSender = t.sender_email === req.merchant.email;
      let counterpartyName = isSender ? t.recipient_email : t.sender_email;
      let counterpartyEmail = isSender ? t.recipient_email : t.sender_email;
      
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

// ============ E-INVOICE SYSTEM (FIXED - USING pool.query) ============

// Lookup business by DSSN, Tax ID, or Registration Number
app.post('/merchants/invoices/lookup-business', requireMerchantAuth, async (req, res) => {
  const { identifier } = req.body;
  
  if (!identifier) {
    return res.status(400).json({ error: 'Identifier is required' });
  }
  
  try {
    const [merchants] = await pool.execute(
      `SELECT DSSN, business_name, business_registration_number, tax_identification_number, 
              email, phone_number, status
       FROM merchants 
       WHERE DSSN = ? OR tax_identification_number = ? OR business_registration_number = ?`,
      [identifier, identifier, identifier]
    );
    
    if (merchants.length === 0) {
      return res.status(404).json({ error: 'Business not found' });
    }
    
    const merchant = merchants[0];
    
    if (merchant.status !== 'active') {
      return res.status(403).json({ error: 'Business account is not active' });
    }
    
    res.json({
      success: true,
      data: {
        dssn: merchant.DSSN,
        business_name: merchant.business_name,
        registration_number: merchant.business_registration_number,
        tax_id: merchant.tax_identification_number,
        email: merchant.email,
        phone: merchant.phone_number
      }
    });
  } catch (error) {
    console.error('Lookup business error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Send invoice
app.post('/merchants/invoices/send', requireMerchantAuth, async (req, res) => {
  const { recipient_dssn, amount, currency, purpose, notes, due_date } = req.body;
  
  if (!recipient_dssn) {
    return res.status(400).json({ error: 'Recipient DSSN is required' });
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
    
    const [senders] = await connection.execute(
      `SELECT DSSN, business_name, email, phone_number, tax_identification_number, business_registration_number
       FROM merchants WHERE DSSN = ?`,
      [req.merchant.DSSN]
    );
    
    if (senders.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Sender not found' });
    }
    
    const sender = senders[0];
    
    const [recipients] = await connection.execute(
      `SELECT DSSN, business_name, email, phone_number, tax_identification_number, business_registration_number
       FROM merchants WHERE DSSN = ? AND status = 'active'`,
      [recipient_dssn]
    );
    
    if (recipients.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Recipient business not found' });
    }
    
    const recipient = recipients[0];
    
    if (recipient.DSSN === sender.DSSN) {
      await connection.rollback();
      return res.status(400).json({ error: 'Cannot send invoice to yourself' });
    }
    
    const invoiceNumber = generateInvoiceNumber();
    
    await connection.execute(
      `INSERT INTO merchant_invoices (
        invoice_number, sender_dssn, sender_business_name, sender_email, sender_phone,
        sender_tax_id, sender_reg_number, recipient_dssn, recipient_business_name,
        recipient_email, recipient_phone, recipient_tax_id, recipient_reg_number,
        amount, currency, purpose, notes, due_date, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [
        invoiceNumber, sender.DSSN, sender.business_name, sender.email, sender.phone_number,
        sender.tax_identification_number, sender.business_registration_number,
        recipient.DSSN, recipient.business_name, recipient.email, recipient.phone_number,
        recipient.tax_identification_number, recipient.business_registration_number,
        amount, currency, purpose || null, notes || null, due_date || null
      ]
    );
    
    await connection.commit();
    
    res.json({
      success: true,
      message: `Invoice ${invoiceNumber} sent successfully to ${recipient.business_name}`,
      data: {
        invoice_number: invoiceNumber,
        recipient: {
          business_name: recipient.business_name,
          dssn: recipient.DSSN,
          email: recipient.email
        },
        amount,
        currency,
        purpose,
        due_date
      }
    });
    
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Send invoice error:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    if (connection) connection.release();
  }
});

// Get invoices - FIXED: Using pool.query instead of pool.execute for LIMIT
app.get('/merchants/invoices', requireMerchantAuth, async (req, res) => {
  const { status, type, limit = 50 } = req.query;
  const limitNum = parseInt(limit) || 50;
  
  try {
    let query = `
      SELECT 
        id, invoice_number, sender_dssn, sender_business_name, sender_email,
        recipient_dssn, recipient_business_name, recipient_email,
        amount, currency, purpose, notes, status, due_date, paid_at, created_at
      FROM merchant_invoices
      WHERE sender_dssn = ? OR recipient_dssn = ?
    `;
    let params = [req.merchant.DSSN, req.merchant.DSSN];
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    if (type === 'sent') {
      query = `
        SELECT 
          id, invoice_number, sender_dssn, sender_business_name, sender_email,
          recipient_dssn, recipient_business_name, recipient_email,
          amount, currency, purpose, notes, status, due_date, paid_at, created_at
        FROM merchant_invoices
        WHERE sender_dssn = ?
      `;
      params = [req.merchant.DSSN];
      
      if (status && status !== 'all') {
        query += ' AND status = ?';
        params.push(status);
      }
    } else if (type === 'received') {
      query = `
        SELECT 
          id, invoice_number, sender_dssn, sender_business_name, sender_email,
          recipient_dssn, recipient_business_name, recipient_email,
          amount, currency, purpose, notes, status, due_date, paid_at, created_at
        FROM merchant_invoices
        WHERE recipient_dssn = ?
      `;
      params = [req.merchant.DSSN];
      
      if (status && status !== 'all') {
        query += ' AND status = ?';
        params.push(status);
      }
    }
    
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limitNum);
    
    // Use query() instead of execute() to avoid LIMIT parameter issues
    const [invoices] = await pool.query(query, params);
    
    const formattedInvoices = invoices.map(inv => ({
      id: inv.id,
      invoice_number: inv.invoice_number,
      direction: inv.sender_dssn === req.merchant.DSSN ? 'sent' : 'received',
      sender: {
        business_name: inv.sender_business_name,
        dssn: inv.sender_dssn,
        email: inv.sender_email
      },
      recipient: {
        business_name: inv.recipient_business_name,
        dssn: inv.recipient_dssn,
        email: inv.recipient_email
      },
      amount: parseFloat(inv.amount),
      currency: inv.currency,
      purpose: inv.purpose,
      notes: inv.notes,
      status: inv.status,
      due_date: inv.due_date,
      paid_at: inv.paid_at,
      created_at: inv.created_at
    }));
    
    res.json({
      success: true,
      data: formattedInvoices
    });
    
  } catch (error) {
    console.error('Get invoices error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single invoice details
app.get('/merchants/invoices/:invoiceNumber', requireMerchantAuth, async (req, res) => {
  const { invoiceNumber } = req.params;
  
  try {
    const [invoices] = await pool.execute(
      `SELECT * FROM merchant_invoices WHERE invoice_number = ?`,
      [invoiceNumber]
    );
    
    if (invoices.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    const invoice = invoices[0];
    
    if (invoice.sender_dssn !== req.merchant.DSSN && invoice.recipient_dssn !== req.merchant.DSSN) {
      return res.status(403).json({ error: 'Unauthorized to view this invoice' });
    }
    
    res.json({
      success: true,
      data: {
        id: invoice.id,
        invoice_number: invoice.invoice_number,
        sender: {
          business_name: invoice.sender_business_name,
          dssn: invoice.sender_dssn,
          email: invoice.sender_email,
          phone: invoice.sender_phone,
          tax_id: invoice.sender_tax_id,
          registration_number: invoice.sender_reg_number
        },
        recipient: {
          business_name: invoice.recipient_business_name,
          dssn: invoice.recipient_dssn,
          email: invoice.recipient_email,
          phone: invoice.recipient_phone,
          tax_id: invoice.recipient_tax_id,
          registration_number: invoice.recipient_reg_number
        },
        amount: parseFloat(invoice.amount),
        currency: invoice.currency,
        purpose: invoice.purpose,
        notes: invoice.notes,
        status: invoice.status,
        due_date: invoice.due_date,
        paid_at: invoice.paid_at,
        created_at: invoice.created_at
      }
    });
    
  } catch (error) {
    console.error('Get invoice error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Pay invoice
app.post('/merchants/invoices/:invoiceNumber/pay', requireMerchantAuth, async (req, res) => {
  const { invoiceNumber } = req.params;
  
  let connection;
  
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    const [invoices] = await connection.execute(
      `SELECT * FROM merchant_invoices WHERE invoice_number = ? AND status = 'pending'`,
      [invoiceNumber]
    );
    
    if (invoices.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Invoice not found or already paid' });
    }
    
    const invoice = invoices[0];
    
    if (invoice.recipient_dssn !== req.merchant.DSSN) {
      await connection.rollback();
      return res.status(403).json({ error: 'Only the recipient can pay this invoice' });
    }
    
    const [senderWallets] = await connection.execute(
      'SELECT balance, lrd_balance FROM wallets WHERE email = ?',
      [invoice.recipient_email]
    );
    
    const balanceField = invoice.currency === 'USD' ? 'balance' : 'lrd_balance';
    const currentBalance = parseFloat(senderWallets[0][balanceField]);
    
    if (currentBalance < invoice.amount) {
      await connection.rollback();
      return res.status(400).json({ error: `Insufficient ${invoice.currency} balance to pay invoice` });
    }
    
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} - ? WHERE email = ?`,
      [invoice.amount, invoice.recipient_email]
    );
    
    await connection.execute(
      `UPDATE wallets SET ${balanceField} = ${balanceField} + ? WHERE email = ?`,
      [invoice.amount, invoice.sender_email]
    );
    
    const reference = generateReference();
    const transactionPurpose = `Invoice payment: ${invoice.invoice_number}`;
    
    await connection.execute(
      `INSERT INTO transactions (reference, sender_email, recipient_email, amount, currency, original_amount, status, transaction_type, notes, purpose, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, 'completed', 'payment', ?, ?, NOW())`,
      [reference, invoice.recipient_email, invoice.sender_email, invoice.amount, invoice.currency, invoice.amount, `Payment for invoice ${invoice.invoice_number}`, transactionPurpose]
    );
    
    await connection.execute(
      `UPDATE merchant_invoices SET status = 'paid', paid_at = NOW() WHERE invoice_number = ?`,
      [invoiceNumber]
    );
    
    await connection.commit();
    
    res.json({
      success: true,
      message: `Invoice ${invoiceNumber} paid successfully`,
      data: {
        invoice_number: invoiceNumber,
        amount: invoice.amount,
        currency: invoice.currency,
        transaction_reference: reference,
        paid_at: new Date().toISOString()
      }
    });
    
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Pay invoice error:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    if (connection) connection.release();
  }
});

// Cancel invoice
app.post('/merchants/invoices/:invoiceNumber/cancel', requireMerchantAuth, async (req, res) => {
  const { invoiceNumber } = req.params;
  
  try {
    const [invoices] = await pool.execute(
      `SELECT * FROM merchant_invoices WHERE invoice_number = ? AND status = 'pending'`,
      [invoiceNumber]
    );
    
    if (invoices.length === 0) {
      return res.status(404).json({ error: 'Invoice not found or already processed' });
    }
    
    const invoice = invoices[0];
    
    if (invoice.sender_dssn !== req.merchant.DSSN) {
      return res.status(403).json({ error: 'Only the sender can cancel this invoice' });
    }
    
    await pool.execute(
      `UPDATE merchant_invoices SET status = 'cancelled' WHERE invoice_number = ?`,
      [invoiceNumber]
    );
    
    res.json({
      success: true,
      message: `Invoice ${invoiceNumber} cancelled successfully`
    });
    
  } catch (error) {
    console.error('Cancel invoice error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ BULK PAYOUT ============

app.post('/merchants/wallet/bulk-payout', requireMerchantAuth, async (req, res) => {
  const { payments, currency, description } = req.body;
  
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
    
    const validatedPayments = [];
    
    for (const payment of payments) {
      const { recipient_contact, amount, note } = payment;
      
      if (!recipient_contact || !amount || amount <= 0) {
        results.failed.push({ recipient_contact, amount, error: 'Invalid recipient or amount', note });
        results.total_failed++;
        continue;
      }
      
      const isEmail = recipient_contact.includes('@');
      const recipientQuery = isEmail 
        ? 'SELECT email, first_name, last_name, is_active FROM users WHERE email = ?'
        : 'SELECT email, first_name, last_name, is_active FROM users WHERE phone = ?';
      
      const [recipients] = await connection.execute(recipientQuery, [recipient_contact]);
      
      if (recipients.length === 0) {
        results.failed.push({ recipient_contact, amount, error: 'Recipient not found', note });
        results.total_failed++;
        continue;
      }
      
      const recipient = recipients[0];
      
      if (recipient.email === req.merchant.email) {
        results.failed.push({ recipient_contact, amount, error: 'Cannot pay yourself', note });
        results.total_failed++;
        continue;
      }
      
      if (recipient.is_active === 0) {
        results.failed.push({ recipient_contact, amount, error: 'Recipient account is frozen', note });
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
    
    for (const payment of validatedPayments) {
      try {
        await connection.execute(
          `UPDATE wallets SET ${balanceField} = ${balanceField} - ? WHERE email = ?`,
          [payment.amount, req.merchant.email]
        );
        
        await connection.execute(
          `UPDATE wallets SET ${balanceField} = ${balanceField} + ? WHERE email = ?`,
          [payment.amount, payment.recipient.email]
        );
        
        const reference = generateReference();
        
        await connection.execute(
          `INSERT INTO transactions (reference, sender_email, recipient_email, amount, currency, original_amount, status, transaction_type, notes, purpose, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, 'completed', 'transfer', ?, ?, NOW())`,
          [reference, req.merchant.email, payment.recipient.email, payment.amount, currency, payment.amount, payment.note, payment.note]
        );
        
        results.successful.push({
          recipient_contact: payment.recipient.email,
          recipient_name: `${payment.recipient.first_name} ${payment.recipient.last_name}`,
          amount: payment.amount,
          reference: reference,
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
    console.log(`   - POST /merchants/invoices/lookup-business`);
    console.log(`   - POST /merchants/invoices/send`);
    console.log(`   - GET  /merchants/invoices`);
    console.log(`   - GET  /merchants/invoices/:invoiceNumber`);
    console.log(`   - POST /merchants/invoices/:invoiceNumber/pay`);
    console.log(`   - POST /merchants/invoices/:invoiceNumber/cancel`);
    console.log(`   - POST /merchants/wallet/bulk-payout`);
    console.log(`   - GET  /merchants/transactions`);
    console.log(`   - GET  /merchants/dashboard/overview`);
  });
}

start().catch(console.error);

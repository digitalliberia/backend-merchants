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

// ============ BUSINESS ANALYTICS ENDPOINT ============

app.get('/merchants/analytics', requireMerchantAuth, async (req, res) => {
  try {
    const merchantEmail = req.merchant.email;
    
    // Get all transactions
    const [transactions] = await pool.query(
      `SELECT 
        amount,
        currency,
        status,
        transaction_type as type,
        notes as description,
        purpose,
        created_at,
        sender_email,
        recipient_email
      FROM transactions
      WHERE sender_email = ? OR recipient_email = ?
      ORDER BY created_at DESC`,
      [merchantEmail, merchantEmail]
    );
    
    // Calculate totals
    let total_received_usd = 0;
    let total_received_lrd = 0;
    let total_sent_usd = 0;
    let total_sent_lrd = 0;
    let salary_payouts_usd = 0;
    let salary_payouts_lrd = 0;
    let total_transactions = 0;
    let completed_transactions = 0;
    
    // Monthly data for charts
    const monthlyData = new Map();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    
    // Track unique customers
    const customerMap = new Map();
    
    for (const tx of transactions) {
      total_transactions++;
      if (tx.status === 'completed') completed_transactions++;
      
      const date = new Date(tx.created_at);
      const monthKey = `${date.getFullYear()}-${date.getMonth() + 1}`;
      
      if (!monthlyData.has(monthKey)) {
        monthlyData.set(monthKey, { 
          month: months[date.getMonth()], 
          received_usd: 0, 
          received_lrd: 0, 
          sent_usd: 0, 
          sent_lrd: 0 
        });
      }
      
      const isReceived = tx.recipient_email === merchantEmail;
      const amount = parseFloat(tx.amount);
      
      if (isReceived && tx.status === 'completed') {
        if (tx.currency === 'USD') {
          total_received_usd += amount;
          monthlyData.get(monthKey).received_usd += amount;
        } else {
          total_received_lrd += amount;
          monthlyData.get(monthKey).received_lrd += amount;
        }
        
        // Track customer
        const customerEmail = tx.sender_email;
        if (!customerMap.has(customerEmail)) {
          customerMap.set(customerEmail, { email: customerEmail, total_usd: 0, total_lrd: 0 });
        }
        const customer = customerMap.get(customerEmail);
        if (tx.currency === 'USD') {
          customer.total_usd += amount;
        } else {
          customer.total_lrd += amount;
        }
      } else if (!isReceived && tx.status === 'completed') {
        if (tx.currency === 'USD') {
          total_sent_usd += amount;
          monthlyData.get(monthKey).sent_usd += amount;
        } else {
          total_sent_lrd += amount;
          monthlyData.get(monthKey).sent_lrd += amount;
        }
        
        // Check if this is a salary payout
        if (tx.purpose && (tx.purpose.toLowerCase().includes('salary') || tx.purpose.toLowerCase().includes('payroll'))) {
          if (tx.currency === 'USD') {
            salary_payouts_usd += amount;
          } else {
            salary_payouts_lrd += amount;
          }
        }
      }
    }
    
    // Calculate growth (compare last 30 days with previous 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const sixtyDaysAgo = new Date();
    sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);
    
    const [recentStats] = await pool.query(
      `SELECT 
        COALESCE(SUM(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as recent_usd,
        COALESCE(SUM(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as recent_lrd
      FROM transactions
      WHERE recipient_email = ? AND status = 'completed' AND created_at >= ?`,
      [merchantEmail, thirtyDaysAgo]
    );
    
    const [previousStats] = await pool.query(
      `SELECT 
        COALESCE(SUM(CASE WHEN currency = 'USD' THEN amount ELSE 0 END), 0) as previous_usd,
        COALESCE(SUM(CASE WHEN currency = 'LRD' THEN amount ELSE 0 END), 0) as previous_lrd
      FROM transactions
      WHERE recipient_email = ? AND status = 'completed' AND created_at BETWEEN ? AND ?`,
      [merchantEmail, sixtyDaysAgo, thirtyDaysAgo]
    );
    
    const recentTotal = parseFloat(recentStats[0].recent_usd) + (parseFloat(recentStats[0].recent_lrd) / 200);
    const previousTotal = parseFloat(previousStats[0].previous_usd) + (parseFloat(previousStats[0].previous_lrd) / 200);
    const monthlyGrowth = previousTotal > 0 ? ((recentTotal - previousTotal) / previousTotal) * 100 : recentTotal > 0 ? 100 : 0;
    
    // Prepare monthly chart data (last 6 months)
    const monthlyChartData = [];
    const now = new Date();
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthKey = `${d.getFullYear()}-${d.getMonth() + 1}`;
      const data = monthlyData.get(monthKey) || { received_usd: 0, received_lrd: 0, sent_usd: 0, sent_lrd: 0 };
      monthlyChartData.push({
        month: months[d.getMonth()],
        received_usd: data.received_usd,
        received_lrd: data.received_lrd,
        sent_usd: data.sent_usd,
        sent_lrd: data.sent_lrd
      });
    }
    
    // Get top customers
    const topCustomers = Array.from(customerMap.entries())
      .map(([email, data]) => ({
        name: email.split('@')[0],
        email: email,
        total_spent_usd: data.total_usd,
        total_spent_lrd: data.total_lrd
      }))
      .sort((a, b) => (b.total_spent_usd + b.total_spent_lrd / 200) - (a.total_spent_usd + a.total_spent_lrd / 200))
      .slice(0, 10);
    
    const receivedCount = transactions.filter(t => t.recipient_email === merchantEmail && t.status === 'completed').length;
    
    res.json({
      success: true,
      data: {
        summary: {
          total_received_usd,
          total_received_lrd,
          total_sent_usd,
          total_sent_lrd,
          salary_payouts_usd,
          salary_payouts_lrd,
          total_transactions,
          completed_transactions,
          pending_transactions: total_transactions - completed_transactions,
          monthly_growth: Math.round(monthlyGrowth * 10) / 10
        },
        monthly_data: monthlyChartData,
        top_customers: topCustomers,
        average_order_value_usd: receivedCount > 0 ? total_received_usd / receivedCount : 0,
        average_order_value_lrd: receivedCount > 0 ? total_received_lrd / receivedCount : 0
      }
    });
    
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ IMAGE UPLOAD SYSTEM ============

const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directories exist
const uploadDir = '/home/digitalliberia1/backend/uploads/products';
const kycDir = '/home/digitalliberia1/backend/uploads/kyc';

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
if (!fs.existsSync(kycDir)) {
  fs.mkdirSync(kycDir, { recursive: true });
}

// Configure multer for product images
const productStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'product-' + uniqueSuffix + ext);
  }
});

// Configure multer for KYC documents
const kycStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, kycDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'kyc-doc-' + uniqueSuffix + ext);
  }
});

// File filter for images
const imageFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'));
  }
};

const productUpload = multer({ 
  storage: productStorage, 
  fileFilter: imageFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

const kycUpload = multer({ 
  storage: kycStorage, 
  fileFilter: imageFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Upload product image
app.post('/merchants/store/upload-image', requireMerchantAuth, productUpload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const API_BASE_URL = process.env.API_BASE_URL || 'https://api.liberianpost.com';
    const imageUrl = `${API_BASE_URL}/uploads/products/${req.file.filename}`;
    
    res.json({
      success: true,
      data: {
        image_url: imageUrl,
        filename: req.file.filename,
        size: req.file.size
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Upload multiple product images
app.post('/merchants/store/upload-images', requireMerchantAuth, productUpload.array('images', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }
    
    const API_BASE_URL = process.env.API_BASE_URL || 'https://api.liberianpost.com';
    const imageUrls = req.files.map(file => ({
      url: `${API_BASE_URL}/uploads/products/${file.filename}`,
      filename: file.filename
    }));
    
    res.json({
      success: true,
      data: {
        images: imageUrls
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload images' });
  }
});

// Delete product image (optional - removes file from server)
app.delete('/merchants/store/delete-image', requireMerchantAuth, async (req, res) => {
  const { filename } = req.body;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  try {
    const filePath = path.join(uploadDir, filename);
    
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ success: true, message: 'Image deleted successfully' });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});

// ============ STORE MANAGEMENT ENDPOINTS ============

// Create products table if not exists
async function initStoreTables() {
  const createProductsTable = `
    CREATE TABLE IF NOT EXISTS merchant_products (
      id INT PRIMARY KEY AUTO_INCREMENT,
      merchant_dssn VARCHAR(50) NOT NULL,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      price_usd DECIMAL(10,2) DEFAULT 0.00,
      price_lrd DECIMAL(10,2) DEFAULT 0.00,
      stock INT DEFAULT 0,
      category VARCHAR(100),
      sub_category VARCHAR(100),
      product_type ENUM('physical', 'digital', 'service', 'food', 'ride') DEFAULT 'physical',
      image_url VARCHAR(500),
      images JSON,
      status ENUM('active', 'inactive') DEFAULT 'active',
      featured BOOLEAN DEFAULT FALSE,
      sales_count INT DEFAULT 0,
      rating DECIMAL(2,1) DEFAULT 0,
      reviews_count INT DEFAULT 0,
      metadata JSON,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (merchant_dssn) REFERENCES merchants(DSSN) ON DELETE CASCADE,
      INDEX idx_merchant (merchant_dssn),
      INDEX idx_category (category),
      INDEX idx_status (status),
      INDEX idx_type (product_type),
      FULLTEXT INDEX idx_search (name, description)
    );
  `;

  const createOrdersTable = `
    CREATE TABLE IF NOT EXISTS merchant_orders (
      id INT PRIMARY KEY AUTO_INCREMENT,
      order_number VARCHAR(50) UNIQUE NOT NULL,
      merchant_dssn VARCHAR(50) NOT NULL,
      customer_id INT,
      customer_name VARCHAR(255),
      customer_email VARCHAR(255),
      customer_phone VARCHAR(20),
      customer_address TEXT,
      items JSON NOT NULL,
      subtotal_usd DECIMAL(10,2) DEFAULT 0.00,
      subtotal_lrd DECIMAL(10,2) DEFAULT 0.00,
      tax_usd DECIMAL(10,2) DEFAULT 0.00,
      tax_lrd DECIMAL(10,2) DEFAULT 0.00,
      delivery_fee_usd DECIMAL(10,2) DEFAULT 0.00,
      delivery_fee_lrd DECIMAL(10,2) DEFAULT 0.00,
      total_usd DECIMAL(10,2) DEFAULT 0.00,
      total_lrd DECIMAL(10,2) DEFAULT 0.00,
      currency ENUM('USD', 'LRD') DEFAULT 'USD',
      status ENUM('pending', 'processing', 'completed', 'cancelled', 'refunded') DEFAULT 'pending',
      payment_status ENUM('pending', 'paid', 'failed', 'refunded') DEFAULT 'pending',
      payment_method VARCHAR(50),
      delivery_status ENUM('pending', 'preparing', 'ready', 'delivered', 'cancelled') DEFAULT 'pending',
      delivery_address TEXT,
      delivery_lat DECIMAL(10,8),
      delivery_lng DECIMAL(11,8),
      rider_id INT,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (merchant_dssn) REFERENCES merchants(DSSN) ON DELETE CASCADE,
      INDEX idx_merchant (merchant_dssn),
      INDEX idx_status (status),
      INDEX idx_order_number (order_number),
      INDEX idx_customer (customer_email)
    );
  `;

  const createRidersTable = `
    CREATE TABLE IF NOT EXISTS merchant_riders (
      id INT PRIMARY KEY AUTO_INCREMENT,
      merchant_dssn VARCHAR(50) NOT NULL,
      rider_name VARCHAR(255) NOT NULL,
      rider_phone VARCHAR(20) NOT NULL,
      rider_email VARCHAR(255),
      vehicle_type VARCHAR(50),
      vehicle_plate VARCHAR(50),
      status ENUM('active', 'inactive', 'busy') DEFAULT 'active',
      current_lat DECIMAL(10,8),
      current_lng DECIMAL(11,8),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (merchant_dssn) REFERENCES merchants(DSSN) ON DELETE CASCADE
    );
  `;

  try {
    await pool.execute(createProductsTable);
    console.log('✅ merchant_products table ready');
  } catch (err) {
    console.log('⚠️ merchant_products table error:', err.message);
  }

  try {
    await pool.execute(createOrdersTable);
    console.log('✅ merchant_orders table ready');
  } catch (err) {
    console.log('⚠️ merchant_orders table error:', err.message);
  }

  try {
    await pool.execute(createRidersTable);
    console.log('✅ merchant_riders table ready');
  } catch (err) {
    console.log('⚠️ merchant_riders table error:', err.message);
  }
}

// Call this in initDatabase after pool is created
// Add this line to your initDatabase function after creating other tables:
// await initStoreTables();

// ============ PRODUCT ENDPOINTS ============

// Get all products
app.get('/merchants/store/products', requireMerchantAuth, async (req, res) => {
  const { limit = 100, offset = 0, category, status, type, search } = req.query;
  const limitNum = parseInt(limit) || 100;
  const offsetNum = parseInt(offset) || 0;
  
  try {
    let query = `
      SELECT id, name, description, price_usd, price_lrd, stock, category, sub_category,
             product_type, image_url, images, status, featured, sales_count, rating, 
             reviews_count, metadata, created_at
      FROM merchant_products
      WHERE merchant_dssn = ?
    `;
    const params = [req.merchant.DSSN];
    
    if (category && category !== 'all') {
      query += ' AND category = ?';
      params.push(category);
    }
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    if (type && type !== 'all') {
      query += ' AND product_type = ?';
      params.push(type);
    }
    
    if (search) {
      query += ' AND (name LIKE ? OR description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limitNum, offsetNum);
    
    const [products] = await pool.query(query, params);
    
    res.json({
      success: true,
      data: products.map(p => ({
        ...p,
        price_usd: parseFloat(p.price_usd),
        price_lrd: parseFloat(p.price_lrd)
      }))
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single product
app.get('/merchants/store/products/:productId', requireMerchantAuth, async (req, res) => {
  const { productId } = req.params;
  
  try {
    const [products] = await pool.execute(
      `SELECT id, name, description, price_usd, price_lrd, stock, category, sub_category,
              product_type, image_url, images, status, featured, sales_count, rating,
              reviews_count, metadata, created_at
       FROM merchant_products
       WHERE id = ? AND merchant_dssn = ?`,
      [productId, req.merchant.DSSN]
    );
    
    if (products.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({
      success: true,
      data: {
        ...products[0],
        price_usd: parseFloat(products[0].price_usd),
        price_lrd: parseFloat(products[0].price_lrd)
      }
    });
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add product
app.post('/merchants/store/products', requireMerchantAuth, async (req, res) => {
  const {
    name, description, price_usd, price_lrd, stock, category, sub_category,
    product_type, image_url, images, status, featured, metadata
  } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Product name is required' });
  }
  
  try {
    const [result] = await pool.execute(
      `INSERT INTO merchant_products (
        merchant_dssn, name, description, price_usd, price_lrd, stock, category,
        sub_category, product_type, image_url, images, status, featured, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.merchant.DSSN, name, description || null, price_usd || 0, price_lrd || 0,
        stock || 0, category || null, sub_category || null, product_type || 'physical',
        image_url || null, images ? JSON.stringify(images) : null,
        status || 'active', featured || false, metadata ? JSON.stringify(metadata) : null
      ]
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
app.put('/merchants/store/products/:productId', requireMerchantAuth, async (req, res) => {
  const { productId } = req.params;
  const updates = [];
  const params = [];
  
  const allowedFields = [
    'name', 'description', 'price_usd', 'price_lrd', 'stock', 'category',
    'sub_category', 'product_type', 'image_url', 'images', 'status', 'featured', 'metadata'
  ];
  
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      updates.push(`${field} = ?`);
      if (field === 'images' || field === 'metadata') {
        params.push(JSON.stringify(req.body[field]));
      } else {
        params.push(req.body[field]);
      }
    }
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  params.push(productId, req.merchant.DSSN);
  
  try {
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
app.delete('/merchants/store/products/:productId', requireMerchantAuth, async (req, res) => {
  const { productId } = req.params;
  
  try {
    await pool.execute(
      'DELETE FROM merchant_products WHERE id = ? AND merchant_dssn = ?',
      [productId, req.merchant.DSSN]
    );
    
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ ORDER ENDPOINTS ============

// Get all orders
app.get('/merchants/store/orders', requireMerchantAuth, async (req, res) => {
  const { limit = 50, offset = 0, status, payment_status, delivery_status } = req.query;
  const limitNum = parseInt(limit) || 50;
  const offsetNum = parseInt(offset) || 0;
  
  try {
    let query = `
      SELECT id, order_number, customer_name, customer_email, customer_phone,
             items, subtotal_usd, subtotal_lrd, tax_usd, tax_lrd,
             delivery_fee_usd, delivery_fee_lrd, total_usd, total_lrd,
             currency, status, payment_status, payment_method,
             delivery_status, delivery_address, notes, created_at
      FROM merchant_orders
      WHERE merchant_dssn = ?
    `;
    const params = [req.merchant.DSSN];
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    if (payment_status && payment_status !== 'all') {
      query += ' AND payment_status = ?';
      params.push(payment_status);
    }
    
    if (delivery_status && delivery_status !== 'all') {
      query += ' AND delivery_status = ?';
      params.push(delivery_status);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limitNum, offsetNum);
    
    const [orders] = await pool.query(query, params);
    
    res.json({
      success: true,
      data: orders.map(o => ({
        ...o,
        subtotal_usd: parseFloat(o.subtotal_usd),
        subtotal_lrd: parseFloat(o.subtotal_lrd),
        total_usd: parseFloat(o.total_usd),
        total_lrd: parseFloat(o.total_lrd),
        items: typeof o.items === 'string' ? JSON.parse(o.items) : o.items
      }))
    });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single order
app.get('/merchants/store/orders/:orderNumber', requireMerchantAuth, async (req, res) => {
  const { orderNumber } = req.params;
  
  try {
    const [orders] = await pool.execute(
      `SELECT * FROM merchant_orders WHERE order_number = ? AND merchant_dssn = ?`,
      [orderNumber, req.merchant.DSSN]
    );
    
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json({
      success: true,
      data: {
        ...orders[0],
        subtotal_usd: parseFloat(orders[0].subtotal_usd),
        subtotal_lrd: parseFloat(orders[0].subtotal_lrd),
        total_usd: parseFloat(orders[0].total_usd),
        total_lrd: parseFloat(orders[0].total_lrd),
        items: typeof orders[0].items === 'string' ? JSON.parse(orders[0].items) : orders[0].items
      }
    });
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update order status
app.put('/merchants/store/orders/:orderNumber/status', requireMerchantAuth, async (req, res) => {
  const { orderNumber } = req.params;
  const { status, payment_status, delivery_status } = req.body;
  
  try {
    const updates = [];
    const params = [];
    
    if (status) {
      updates.push('status = ?');
      params.push(status);
    }
    if (payment_status) {
      updates.push('payment_status = ?');
      params.push(payment_status);
    }
    if (delivery_status) {
      updates.push('delivery_status = ?');
      params.push(delivery_status);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    params.push(orderNumber, req.merchant.DSSN);
    
    await pool.execute(
      `UPDATE merchant_orders SET ${updates.join(', ')} WHERE order_number = ? AND merchant_dssn = ?`,
      params
    );
    
    res.json({ success: true, message: 'Order updated successfully' });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ CATEGORIES ENDPOINT ============

// Get unique categories for merchant
app.get('/merchants/store/categories', requireMerchantAuth, async (req, res) => {
  try {
    const [categories] = await pool.execute(
      `SELECT DISTINCT category FROM merchant_products WHERE merchant_dssn = ? AND category IS NOT NULL`,
      [req.merchant.DSSN]
    );
    
    res.json({
      success: true,
      data: categories.map(c => c.category)
    });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ STORE STATS ENDPOINT ============

app.get('/merchants/store/stats', requireMerchantAuth, async (req, res) => {
  try {
    const [productStats] = await pool.execute(
      `SELECT 
        COUNT(*) as total_products,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_products,
        SUM(stock) as total_stock,
        SUM(sales_count) as total_sales
       FROM merchant_products
       WHERE merchant_dssn = ?`,
      [req.merchant.DSSN]
    );
    
    const [orderStats] = await pool.execute(
      `SELECT 
        COUNT(*) as total_orders,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_orders,
        SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) as processing_orders,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_orders,
        SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_orders,
        COALESCE(SUM(total_usd), 0) as total_revenue_usd,
        COALESCE(SUM(total_lrd), 0) as total_revenue_lrd
       FROM merchant_orders
       WHERE merchant_dssn = ?`,
      [req.merchant.DSSN]
    );
    
    res.json({
      success: true,
      data: {
        products: {
          total: productStats[0]?.total_products || 0,
          active: productStats[0]?.active_products || 0,
          total_stock: productStats[0]?.total_stock || 0,
          total_sales: productStats[0]?.total_sales || 0
        },
        orders: {
          total: orderStats[0]?.total_orders || 0,
          pending: orderStats[0]?.pending_orders || 0,
          processing: orderStats[0]?.processing_orders || 0,
          completed: orderStats[0]?.completed_orders || 0,
          cancelled: orderStats[0]?.cancelled_orders || 0,
          total_revenue_usd: parseFloat(orderStats[0]?.total_revenue_usd || 0),
          total_revenue_lrd: parseFloat(orderStats[0]?.total_revenue_lrd || 0)
        }
      }
    });
  } catch (error) {
    console.error('Get store stats error:', error);
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

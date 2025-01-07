
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const useragent = require('useragent');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();
const EC = require('elliptic').ec;
const BN = require('bn.js'); // Import BN.js for big number support
const NodeRSA = require('node-rsa');
const { Bigtable } = require('@google-cloud/bigtable');
// Initialize EC and RSA
const ec = new EC('secp256k1'); // Using the secp256k1 curve
const rsa = new NodeRSA({ b: 512 }); // RSA with 512-bit key for example

function generateECChallenge() {
  // Generate a random key pair
  const ecKeyPair = ec.genKeyPair();
  const k = ecKeyPair.getPrivate('hex'); // Private scalar k
  const G = ec.curve.g; // Base point of the curve

  // Generate Q = k * G (base point of the curve)
  const Q = G.mul(ecKeyPair.getPrivate());

  return { P: G, Q, k };
}

// Function to generate RSA challenge using `k`
function generateRSAChallenge(k) {
  // Create a message using the private scalar `k`
  const message = `Solve this: ${k}`;
  // Encrypt message using RSA
  const encryptedMessage = rsa.encrypt(message, 'base64');
  
  return { encryptedMessage };
}

const app = express();
app.use(express.json());

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_HOST_NAME, // Allow requests from this origin
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions));

// Track IP-based request counts and timestamps for adjusting difficulty
const ipRequestLog = {};
let blockedIPs = new Set(); // Store the blocked IPs

// Function to download and parse IP blocklist
async function downloadBlockedIPs() {
  try {
    console.log('Downloading blocked IP list...');
    const response = await axios.get('https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt');
    const ipList = response.data.split('\n').filter(line => line && !line.startsWith('#'));

    blockedIPs = new Set(ipList); // Store IPs in a Set for quick lookup
    console.log(`Blocked IP list loaded with ${blockedIPs.size} entries.`);
  } catch (error) {
    console.error('Failed to download blocked IP list:', error);
  }
}

// Middleware to block requests from blocked IPs
function blockIPs(req, res, next) {
  const ip = req.ip.replace(/^::ffff:/, ''); // Normalize IPv4-mapped IPv6 addresses

  if (blockedIPs.has(ip)) {
    console.log(`Blocked request from IP: ${ip}`);
    return res.status(403).json({ message: 'Access denied: your IP is blocked.' });
  }

  next(); // Continue to the next middleware if not blocked
}

// Load blocked IPs into memory at startup
downloadBlockedIPs();

// Add blockIPs middleware before any other routes
app.use(blockIPs);

// Function to log CAPTCHA event to Bigtable
async function logCaptchaEvent(captchaData) {
  const rowKey = `captcha-${Date.now()}`; // Unique row key based on timestamp

  const row = table.row(rowKey);
  const data = {
    'event:timestamp': { value: Date.now().toString() },
    'event:ip': { value: captchaData.ip },
    'event:ecSolved': { value: captchaData.ecSolved.toString() },
    'event:rsaSolved': { value: captchaData.rsaSolved.toString() },
    'event:k': { value: captchaData.k || 'N/A' },
    'event:result': { value: captchaData.result },
    'event:difficulty': { value: captchaData.difficulty.toString() },
  };

  await row.create(data);
}

// Function to calculate CAPTCHA difficulty
function calculateDifficulty(req) {
  const agent = useragent.parse(req.headers['user-agent']);
  const ip = req.ip;

  // Adjust difficulty based on device type (mobile vs desktop)
  const isMobile = agent.device.family !== 'Other';
  let difficulty = isMobile ? 3 : 5; // Base difficulty

  // Dynamic difficulty based on request frequency
  const now = Date.now();
  if (!ipRequestLog[ip]) {
    ipRequestLog[ip] = { count: 0, lastRequestTime: now };
  }

  const timeSinceLastRequest = now - ipRequestLog[ip].lastRequestTime;
  ipRequestLog[ip].lastRequestTime = now;

  // Increase difficulty for rapid requests
  if (timeSinceLastRequest < 10000) {
    difficulty += 2;
  }

  // Adjust difficulty based on IP reputation
  ipRequestLog[ip].count += 1;
  if (ipRequestLog[ip].count > 50) {
    difficulty += 3;
  } else if (ipRequestLog[ip].count < 10) {
    difficulty -= 1;
  }

  // Progressive difficulty scaling over session
  if (ipRequestLog[ip].count >= 10) {
    difficulty += Math.floor(ipRequestLog[ip].count / 10);
  }

  return Math.min(Math.max(difficulty, 1), 10); // Clamp between 1 and 10
}


// Rate limiter middleware to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);


app.get('/api/captcha-challenge', (req, res) => {
  console.log('Received request for CAPTCHA challenge');
  
  // Step 1: Generate EC challenge
  const { P, Q, k } = generateECChallenge();

  // Step 2: Generate RSA challenge based on `k`
  const { encryptedMessage } = generateRSAChallenge(k);

  // Return both challenges to the client
  res.json({ 
    ecChallenge: { P, Q }, 
    rsaChallenge: { encryptedMessage } 
  });
});

// Initialize Bigtable client
const bigtable = new Bigtable();
const instance = bigtable.instance('your-instance-id'); // Replace with your Bigtable instance ID
const table = instance.table('captcha-log'); // Replace with your table name

// Function to log CAPTCHA event to Bigtable
async function logCaptchaEvent(captchaData) {
  const rowKey = `captcha-${Date.now()}`; // Unique row key based on timestamp

  const row = table.row(rowKey);
  const data = {
    'event:timestamp': { value: Date.now().toString() },
    'event:ip': { value: captchaData.ip },
    'event:ecSolved': { value: captchaData.ecSolved.toString() },
    'event:rsaSolved': { value: captchaData.rsaSolved.toString() },
    'event:k': { value: captchaData.k || 'N/A' },
    'event:result': { value: captchaData.result },
    'event:difficulty': { value: captchaData.difficulty.toString() },
  };

  await row.create(data);
}

// Function to calculate CAPTCHA difficulty
function calculateDifficulty(req) {
  const agent = useragent.parse(req.headers['user-agent']);
  const ip = req.ip;

  // Adjust difficulty based on device type (mobile vs desktop)
  const isMobile = agent.device.family !== 'Other';
  let difficulty = isMobile ? 3 : 5; // Base difficulty

  // Dynamic difficulty based on request frequency
  const now = Date.now();
  if (!ipRequestLog[ip]) {
    ipRequestLog[ip] = { count: 0, lastRequestTime: now };
  }

  const timeSinceLastRequest = now - ipRequestLog[ip].lastRequestTime;
  ipRequestLog[ip].lastRequestTime = now;

  // Increase difficulty for rapid requests
  if (timeSinceLastRequest < 10000) {
    difficulty += 2;
  }

  // Adjust difficulty based on IP reputation
  ipRequestLog[ip].count += 1;
  if (ipRequestLog[ip].count > 50) {
    difficulty += 3;
  } else if (ipRequestLog[ip].count < 10) {
    difficulty -= 1;
  }

  // Progressive difficulty scaling over session
  if (ipRequestLog[ip].count >= 10) {
    difficulty += Math.floor(ipRequestLog[ip].count / 10);
  }

  return Math.min(Math.max(difficulty, 1), 10); // Clamp between 1 and 10
}

// Modify the post handler to log to Bigtable and use calculated difficulty
app.post('/api/verify-captcha', async (req, res) => {
  const { ecSolution, rsaSolution } = req.body;
  const clientIP = req.ip; // Get the client's IP address
  let k;

  console.log(`Received CAPTCHA verification request`);

  // Calculate difficulty dynamically
  const difficulty = calculateDifficulty(req);

  // Step 1: Validate EC solution
  try {
    const { k: solvedK, P, Q } = ecSolution;
    k = solvedK;

    const basePoint = ec.curve.point(P[0], P[1]);
    const solutionQ = ec.curve.point(Q[0], Q[1]);
    const kBN = new BN(k, 10);
    const expectedQ = basePoint.mul(kBN);

    if (!expectedQ.eq(solutionQ)) {
      throw new Error('EC verification failed');
    }
    console.log('EC challenge solved successfully');
  } catch (error) {
    /*await logCaptchaEvent({
      ip: clientIP,
      ecSolved: false,
      rsaSolved: false,
      result: 'Failed',
      difficulty,
    });*/
    return res.status(400).json({ valid: false, message: 'Invalid EC solution' });
  }

  // Step 2: Validate RSA solution using `k`
  try {
    const decryptedMessage = rsa.decrypt(rsaSolution.encryptedMessage, 'utf8');
    if (!decryptedMessage.includes(k)) {
      throw new Error('RSA verification failed');
    }
    console.log('RSA challenge solved successfully');
    /*await logCaptchaEvent({
      ip: clientIP,
      ecSolved: true,
      rsaSolved: true,
      k,
      result: 'Success',
      difficulty,
    });*/
    return res.json({ valid: true });
  } catch (error) {
    console.error('RSA decryption error:', error);
    /*await logCaptchaEvent({
      ip: clientIP,
      ecSolved: true,
      rsaSolved: false,
      k,
      result: 'Failed',
      difficulty,
    });*/
    return res.status(400).json({ valid: false, message: 'Invalid RSA solution' });
  }
});


function generateECChallenge() {
  // Generate a random small integer `k` within a solvable range (e.g., 1 to 10000)
  const k = Math.floor(Math.random() * 10000) + 1; // Ensure `k` is between 1 and 10000

  // Use the curve's base point `G`
  const G = ec.curve.g;

  // Generate Q = k * G (base point of the curve)
  const Q = G.mul(k);

  // Return `P`, `Q`, and `k`
  // `P` is the base point `G`, `Q` is the result of `k * G`, and `k` is the scalar
  return { 
    P: [G.getX().toString('hex'), G.getY().toString('hex')], // Coordinates of `G`
    Q: [Q.getX().toString('hex'), Q.getY().toString('hex')], // Coordinates of `Q`
    k: k.toString() // Scalar `k` as a string
  };
}

FLY_ENV='PRD'

const port = process.env.PORT || 8449;
// Create HTTPS server
if (process.env.FLY_ENV === 'Dev'){
    const fs = require('fs');
    const path = require('path');//const rateLimit = require("express-rate-limit");
    const https = require('https');
    const privateKey = fs.readFileSync(path.join(__dirname, '../decryptedkey.pem'), 'utf8');
    const certificate = fs.readFileSync(path.join(__dirname, '../cert.pem'), 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    const httpsServer = https.createServer(credentials, app);
    httpsServer.listen(port, '0.0.0.0', () => {
        console.log(`Dev Server running on port ${port}`);
    });
}
else {
    app.listen(port, '0.0.0.0', () => {
        console.log(`Server running on port ${port}`);
    });
}

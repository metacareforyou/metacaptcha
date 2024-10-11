const express = require('express');
const cors = require('cors');
const { BN } = require('bn.js');
const { Bigtable } = require('@google-cloud/bigtable');
const jwt = require('jsonwebtoken');
const useragent = require('useragent');
const NodeRSA = require('node-rsa');
const EC = require('elliptic').ec;
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const ec = new EC('secp256k1');
const rsa = new NodeRSA({ b: 2048 }); // Use 2048-bit RSA key

const app = express();
app.use(express.json());
app.use(cors());

// Google Cloud Bigtable Setup
const bigtable = new Bigtable();
const instance = bigtable.instance('your-instance-id');
const table = instance.table('captcha-log');

// JWT Secret Key for Token Issuance
const JWT_SECRET = 'your_jwt_secret';

// IP blocklist storage
let blockedIPs = new Set(); // Store blocked IPs

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

// Apply the IP blocking middleware to all API routes
app.use(blockIPs);

// Function to log CAPTCHA events to Bigtable
async function logCaptchaEvent(data) {
  const rowKey = `captcha-${Date.now()}`;
  const row = table.row(rowKey);
  await row.create({
    'event:timestamp': { value: Date.now().toString() },
    'event:ip': { value: data.ip },
    'event:result': { value: data.result },
    'event:ecSolved': { value: data.ecSolved.toString() },
    'event:rsaSolved': { value: data.rsaSolved.toString() },
    'event:k': { value: data.k || 'N/A' },
    'event:difficulty': { value: data.difficulty.toString() },
  });
}

// Function to generate EC CAPTCHA challenge
function generateECChallenge() {
  const ecKeyPair = ec.genKeyPair();
  const k = ecKeyPair.getPrivate('hex');
  const P = ecKeyPair.getPublic();
  const Q = ecKeyPair.getPublic().mul(k);
  return { P, Q, k };
}

// Function to generate RSA CAPTCHA challenge based on `k`
function generateRSAChallenge(k) {
  const message = `Solve this: ${k}`;
  const encryptedMessage = rsa.encrypt(message, 'base64');
  return { encryptedMessage };
}

// Function to calculate CAPTCHA difficulty
function calculateDifficulty(req) {
  const agent = useragent.parse(req.headers['user-agent']);
  const isMobile = agent.device.family !== 'Other';
  let difficulty = isMobile ? 3 : 5;
  const ip = req.ip;
  return Math.min(Math.max(difficulty, 1), 10);
}

// Function to issue a JWT token with a 5-minute expiry
function issueAccessToken() {
  const token = jwt.sign({ access: true }, JWT_SECRET, { expiresIn: '5m' });
  return token;
}

// Apply rate limiting to API requests (max 10 requests per minute per IP)
const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 10, // Limit each IP to 10 requests per minute
  message: 'Too many requests from this IP, please try again later.',
});

app.use('/api/', apiRateLimiter); // Apply rate limiting to all API routes

// Request CAPTCHA challenge
app.get('/api/captcha-challenge', (req, res) => {
  const difficulty = calculateDifficulty(req);
  const { P, Q, k } = generateECChallenge();
  const { encryptedMessage } = generateRSAChallenge(k);
  res.json({
    ecChallenge: { P, Q },
    rsaChallenge: { encryptedMessage },
    difficulty
  });
});

// Verify CAPTCHA and issue token
app.post('/api/verify-captcha', async (req, res) => {
  const { ecSolution, rsaSolution } = req.body;
  const clientIP = req.ip;
  let k;

  // EC Challenge validation
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
  } catch (error) {
    await logCaptchaEvent({
      ip: clientIP,
      ecSolved: false,
      rsaSolved: false,
      result: 'Failed',
      difficulty: calculateDifficulty(req)
    });
    return res.status(400).json({ valid: false, message: 'Invalid EC solution' });
  }

  // RSA Challenge validation
  try {
    const decryptedMessage = rsa.decrypt(rsaSolution.encryptedMessage, 'utf8');
    if (!decryptedMessage.includes(k)) {
      throw new Error('RSA verification failed');
    }

    // CAPTCHA solved, issue token
    const token = issueAccessToken();
    await logCaptchaEvent({
      ip: clientIP,
      ecSolved: true,
      rsaSolved: true,
      k,
      result: 'Success',
      difficulty: calculateDifficulty(req)
    });
    return res.json({ valid: true, token });
  } catch (error) {
    await logCaptchaEvent({
      ip: clientIP,
      ecSolved: true,
      rsaSolved: false,
      k,
      result: 'Failed',
      difficulty: calculateDifficulty(req)
    });
    return res.status(400).json({ valid: false, message: 'Invalid RSA solution' });
  }
});

// Example of a secured API endpoint requiring CAPTCHA verification
app.get('/api/secured-endpoint', (req, res) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.access) {
      return res.json({ message: 'Access granted to secured API!' });
    } else {
      return res.status(401).json({ message: 'Access denied: Invalid token' });
    }
  } catch (error) {
    return res.status(401).json({ message: 'Access denied: Token expired or invalid' });
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`MetaCaptcha API Server running on port ${port}`);
});

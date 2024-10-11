const express = require('express');
const cors = require('cors');
const { BN } = require('bn.js');
const { Bigtable } = require('@google-cloud/bigtable');
const jwt = require('jsonwebtoken');
const useragent = require('useragent');
const rsa = new (require('node-rsa'))({ b: 512 });
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

const app = express();
app.use(express.json());
app.use(cors());

// Bigtable setup
const bigtable = new Bigtable();
const instance = bigtable.instance('your-instance-id');
const table = instance.table('captcha-log');

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

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret';

// CAPTCHA logic (reusing previous EC and RSA logic)
function generateECChallenge() {
  const ecKeyPair = ec.genKeyPair();
  const k = ecKeyPair.getPrivate('hex'); // Private scalar k
  const P = ecKeyPair.getPublic(); // Public key
  const Q = ecKeyPair.getPublic().mul(k); // Generate Q = k * P
  return { P, Q, k };
}

function generateRSAChallenge(k) {
  const message = `Solve this: ${k}`;
  const encryptedMessage = rsa.encrypt(message, 'base64');
  return { encryptedMessage };
}

// Token issuance after CAPTCHA is solved
function issueAccessToken() {
  const token = jwt.sign({ access: true }, JWT_SECRET, { expiresIn: '5m' }); // Token valid for 5 minutes
  return token;
}

// Function to calculate CAPTCHA difficulty (reused)
function calculateDifficulty(req) {
  const agent = useragent.parse(req.headers['user-agent']);
  const isMobile = agent.device.family !== 'Other';
  let difficulty = isMobile ? 3 : 5;
  const ip = req.ip;
  // Additional logic for dynamic difficulty (can add more rules)
  return Math.min(Math.max(difficulty, 1), 10);
}

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

  // EC challenge validation
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

  // RSA challenge validation
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

// Example secured API endpoint
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

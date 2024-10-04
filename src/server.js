const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const useragent = require('useragent');

const app = express();
app.use(express.json());

// Track IP-based request counts and timestamps for adjusting difficulty
const ipRequestLog = {};

// Function to calculate CAPTCHA difficulty based on multiple factors
function calculateDifficulty(req) {
  const agent = useragent.parse(req.headers['user-agent']);
  const ip = req.ip;

  // Strategy 2: Adjust based on device type (mobile vs desktop)
  const isMobile = agent.device.family !== 'Other';
  let difficulty = isMobile ? 3 : 5; // Base difficulty

  // Strategy 3: Dynamic difficulty based on request frequency
  const now = Date.now();
  if (!ipRequestLog[ip]) {
    ipRequestLog[ip] = { count: 0, lastRequestTime: now };
  }

  const timeSinceLastRequest = now - ipRequestLog[ip].lastRequestTime;
  ipRequestLog[ip].lastRequestTime = now;

  // Increase difficulty for rapid requests (less than 10 seconds apart)
  if (timeSinceLastRequest < 10000) {
    difficulty += 2;
  }

  // Strategy 4: IP reputation-based adjustment
  ipRequestLog[ip].count += 1;
  if (ipRequestLog[ip].count > 50) {
    // If the IP has made over 50 requests in a 15-minute window, increase difficulty
    difficulty += 3;
  } else if (ipRequestLog[ip].count < 10) {
    // If IP is a trusted (few requests), decrease difficulty
    difficulty -= 1;
  }

  // Strategy 5: Progressive difficulty scaling over session
  if (ipRequestLog[ip].count >= 10) {
    difficulty += Math.floor(ipRequestLog[ip].count / 10); // Increase for every 10 requests in session
  }

  // Clamp the difficulty between a reasonable range
  return Math.min(Math.max(difficulty, 1), 10);
}

// Rate limiter middleware to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Utility function to create a SHA-256 hash
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Generate a random challenge string
function generateChallenge() {
  return crypto.randomBytes(16).toString('hex');
}

// Route to provide the CAPTCHA challenge
app.get('/api/captcha-challenge', (req, res) => {
  // Calculate difficulty based on various strategies
  const difficulty = calculateDifficulty(req);
  const challenge = generateChallenge();

  res.json({ challenge, difficulty });
});

// Route to verify the CAPTCHA solution
app.post('/api/verify-captcha', (req, res) => {
  const { challenge, nonce, difficulty } = req.body;

  // Calculate the hash of the challenge and nonce
  const hash = sha256(challenge + nonce);

  // Check if the hash meets the required difficulty
  if (hash.startsWith('0'.repeat(difficulty))) {
    res.json({ valid: true });
  } else {
    res.status(400).json({ valid: false, message: 'Invalid CAPTCHA solution' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

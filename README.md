# metacapture
Private Secure Captcha with no Cookies
# example usage
```
import React, { useEffect, useRef, useState, useCallback } from 'react';
import axios from 'axios';
import { ec as EC } from 'elliptic';
import { RSAKey, b64tohex } from 'jsrsasign'; // For RSA operations

const ec = new EC('secp256k1');

// Function to solve EC challenge by finding `k`
function solveECChallenge(P, Q) {
  console.log('Solving EC Challenge with P:', P, 'and Q:', Q);

  // Convert coordinates to elliptic curve points
  const curvePointP = ec.curve.point(P[0], P[1]);
  const curvePointQ = ec.curve.point(Q[0], Q[1]);

  // Brute force to find `k`: iterate over all possible values of `k`
  let k = 1;
  while (k <= 10000) {
    const calculatedQ = curvePointP.mul(k);

    if (calculatedQ.eq(curvePointQ)) {
      console.log(`Found k: ${k}`);
      return k.toString(); // Return `k` as a string
    }

    k++;
  }

  console.error('Failed to solve EC Challenge within reasonable range.');
  return null;
}

const MetaCaptcha = ({ setIsVerified }) => {
  const hasSolved = useRef(false);
  const [captchaStatus, setCaptchaStatus] = useState('Fetching CAPTCHA...');
  const challengeData = useRef({ ecChallenge: null, rsaChallenge: null });

  const doneCallback = useCallback(async () => {
    if (!hasSolved.current && challengeData.current.ecChallenge) {
      try {
        setCaptchaStatus('Solving EC Challenge...');
  
        const { P, Q } = challengeData.current.ecChallenge;
        const k = solveECChallenge(P, Q);
  
        if (!k) throw new Error('Failed to solve EC challenge');
  
        setCaptchaStatus('Sending RSA Challenge to Server...');
  
        // Send the encrypted RSA challenge to the server for decryption
        const { encryptedMessage } = challengeData.current.rsaChallenge;
        const backend_host = process.env.REACT_APP_CAPTCHA_HOST;
        const backend_protocol = 'https://';
        const verifyResponse = await axios.post(
          `${backend_protocol}${backend_host}/api/verify-captcha`, 
          {
            ecSolution: { k, P, Q },
            rsaSolution: { encryptedMessage }
          }
        );
  
        if (verifyResponse.data.valid) {
          console.log('CAPTCHA Solved Successfully!');
          setIsVerified(true);
          hasSolved.current = true;
          setCaptchaStatus('CAPTCHA Solved!');
        } else {
          console.log('CAPTCHA Verification Failed!');
          setCaptchaStatus('Verification Failed! Please try again.');
        }
      } catch (error) {
        console.error('Error solving CAPTCHA:', error);
        setCaptchaStatus('An error occurred. Please try again.');
      }
    }
  }, [setIsVerified]);
  
  useEffect(() => {
    const fetchChallenge = async () => {
      try {
        const backend_host = process.env.REACT_APP_CAPTCHA_HOST;
        const backend_protocol = 'https://';
        const response = await axios.get(`${backend_protocol}${backend_host}/api/captcha-challenge`);
        const { ecChallenge, rsaChallenge } = response.data;

        challengeData.current = { ecChallenge, rsaChallenge };
        setCaptchaStatus('CAPTCHA challenge fetched.');
        doneCallback(); // Automatically start solving the CAPTCHA
      } catch (error) {
        console.error('Error fetching CAPTCHA challenge:', error);
        setCaptchaStatus('Error fetching CAPTCHA. Please reload.');
      }
    };

    fetchChallenge();
  }, [doneCallback]);

  return (
    <div className="metacaptcha-container">
      <div style={{ marginTop: '20px', fontSize: '18px', color: '#333' }}>
        {captchaStatus}
      </div>
    </div>
  );
};

export default MetaCaptcha;
```


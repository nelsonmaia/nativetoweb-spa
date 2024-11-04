const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const axios = require("axios"); 
const crypto = require("crypto"); 
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { verifyCertificateChain, parseCBOR, validateAttestation } = require('./attestationHelpers');


const app = express();


// Middleware setup
app.use(morgan("dev"));
app.use(helmet());
app.use(express.json()); // To parse incoming JSON requests
app.use(express.static(join(__dirname, "public")));

// Route for static files
app.get("/auth_config.json", (req, res) => {
  res.sendFile(join(__dirname, "auth_config.json"));
});

// Load the private key for JWT signing
const privateKey = process.env.PRIVATE_KEY;

const auth0PrivateKey = process.env.AUTH0_PRIVATE_KEY;

// Replace with your actual values
const teamId = 'GCAN367Y39';
const keyId = 'SVR9K69LLW';
const issuerId = '05eed3c0-d784-42b6-a078-58d67ce0ffc3';

// Function to generate the JWT token
function generateJWT() {
    const token = jwt.sign({}, privateKey, {
        algorithm: 'ES256',
        expiresIn: '10m', 
        audience: 'appstoreconnect-v1',
        issuer: issuerId,
        header: {
            alg: 'ES256',
            kid: keyId,
            typ: 'JWT'
        },
        subject: teamId
    });
    return token;
}

// app.post("/verify-attestation", async (req, res) => {
//   const { keyId, attestation } = req.body;

//   if (!keyId || !attestation) {
//     return res.status(400).json({ message: "Invalid request, missing keyId or attestation" });
//   }

//   try {
//     // Generate the JWT for authorization
//     const jwtToken = generateJWT();

//     // Call Apple's App Attestation service to verify the attestation
//     const appleResponse = await axios.post('https://api.appattest.apple.com/v1/attestation', {
//       keyId: keyId,
//       attestation: attestation
//     }, {
//       headers: {
//         'Content-Type': 'application/json',
//         'Authorization': `Bearer ${jwtToken}` // Use the generated JWT for authorization
//       }
//     });

//     // generate Auth0 JWT for authetnication on /token
//       const token = jwt.sign({}, auth0PrivateKey, {
//         expiresIn: '10m', 
//         audience: 'https://nelson.jp.auth0.com/',
//         issuer: "6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh",
//         header: {
//             alg: 'RS256',
//             kid: "2WitOoEuiUeIkGaB_j6QqjWCqSepKODyX8mZkwkayL0",
//             typ: 'JWT'
//         },
//         subject: "6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh",
//         jti: crypto.randomUUID,
//     });

//     const jwtAttested = {
//       appleData : appleResponse.data,
//       jwt: token
//     }
    

//     // If the attestation is verified successfully
//     return res.status(200).json({ message: "Attestation verified", data: jwtAttested });

//   } catch (error) {
//     console.error("Error verifying attestation:", error.response ? error.response.data : error.message);
//     return res.status(500).json({ message: "Internal server error", error: error.message });
//   }
// });

app.post("/verify-attestation", async (req, res) => {
  const { keyId, attestation } = req.body;

  if (!keyId || !attestation) {
    console.error("Invalid request: Missing keyId or attestation");
    return res.status(400).json({ message: "Invalid request, missing keyId or attestation" });
  }

  try {
    // Debug: Print incoming data
    console.log("Received keyId:", keyId);
    console.log("Received attestation (base64):", attestation);

    // Parse the attestation object from base64 to a buffer and then decode it as CBOR
    const attestationBuffer = Buffer.from(attestation, 'base64');
    console.log("Attestation buffer length:", attestationBuffer.length);

    const decodedAttestation = parseCBOR(attestationBuffer);
    console.log("Decoded attestation:", decodedAttestation);

    // Validate the attestation certificates with Apple's root certificate
    const isValidChain = verifyCertificateChain(decodedAttestation.attStmt.x5c);
    console.log("Certificate chain validation result:", isValidChain);
    if (!isValidChain) {
      console.error("Invalid certificate chain");
      return res.status(400).json({ message: "Invalid certificate chain" });
    }

    // Create the nonce by hashing the authenticator data and challenge
    const challengeHash = crypto.createHash('sha256').update(decodedAttestation.authData).digest();
    console.log("Challenge hash (hex):", challengeHash.toString('hex'));

    const compositeHash = crypto.createHash('sha256').update(Buffer.concat([decodedAttestation.authData, challengeHash])).digest();
    console.log("Composite hash (hex):", compositeHash.toString('hex'));

    // Extract and validate the nonce in the credential certificate
    const isNonceValid = validateAttestation(decodedAttestation, compositeHash);
    console.log("Nonce validation result:", isNonceValid);
    if (!isNonceValid) {
      console.error("Nonce validation failed");
      return res.status(400).json({ message: "Nonce validation failed" });
    }

    // If all validations pass, generate a response
    const responseMessage = {
      message: "Attestation verified",
      keyId: keyId
    };

    console.log("Attestation verification successful");
    return res.status(200).json(responseMessage);
  } catch (error) {
    console.error("Error verifying attestation:", error.message);
    return res.status(500).json({ message: "Internal server error", error: error.message });
  }
});


app.get("/get-challenge", (req, res) => {
  // Generate a secure random 32-byte challenge
  const challenge = crypto.randomBytes(32);

  // Hash the challenge using SHA-256
  const hashedChallenge = crypto.createHash('sha256').update(challenge).digest();

  // Return the hashed challenge as base64-encoded string
  res.status(200).json({
    challenge: challenge.toString("base64")
  });
});


// Default route to serve index.html
app.get("/*", (_, res) => {
  res.sendFile(join(__dirname, "index.html"));
});

// Graceful shutdown
process.on("SIGINT", function() {
  process.exit();
});

module.exports = app;

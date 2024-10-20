const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const axios = require("axios"); // Use axios for HTTP requests
const crypto = require("crypto"); // For generating the challenge
const jwt = require('jsonwebtoken');
const fs = require('fs');

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

app.post("/verify-attestation", async (req, res) => {
  const { keyId, attestation } = req.body;

  if (!keyId || !attestation) {
    return res.status(400).json({ message: "Invalid request, missing keyId or attestation" });
  }

  try {
    // Generate the JWT for authorization
    const jwtToken = generateJWT();

    // Call Apple's App Attestation service to verify the attestation
    const appleResponse = await axios.post('https://api.appattest.apple.com/v1/attestation', {
      keyId: keyId,
      attestation: attestation
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwtToken}` // Use the generated JWT for authorization
      }
    });

    // If the attestation is verified successfully
    return res.status(200).json({ message: "Attestation verified", data: appleResponse.data });

  } catch (error) {
    console.error("Error verifying attestation:", error.response ? error.response.data : error.message);
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

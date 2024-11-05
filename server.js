const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const crypto = require("crypto");
const jwt = require('jsonwebtoken');
import { v4 as uuid } from 'uuid';


const app = express();

app.use(morgan("dev"));
app.use(helmet());
app.use(express.json());
app.use(express.static(join(__dirname, "public")));

const privateKey = process.env.PRIVATE_KEY;
const auth0PrivateKey = process.env.AUTH0_PRIVATE_KEY;

// Replace with your actual values
const teamId = 'GCAN367Y39';
const bundleIdentifier = 'nelson.matias.SwiftSample'; // Replace with your app's bundle identifier
const keyId = 'SVR9K69LLW';
const issuerId = '05eed3c0-d784-42b6-a078-58d67ce0ffc3';

app.post("/verify-attestation", async (req, res) => {
  const { keyId, attestation, challenge } = req.body;

  // log the requestesd parameters
  console.log(`keyId: ${keyId}, attestation: ${attestation}, challenge: ${challenge}`)

  if (!keyId || !attestation || !challenge) {
      console.error("Invalid request: Missing keyId, attestation, or challenge");
      return res.status(400).json({ message: "Invalid request, missing keyId, attestation, or challenge" });
  }

  try {
      const { verifyAttestation } = await import('node-app-attest');

      const result = verifyAttestation({
          attestation: Buffer.from(attestation, 'base64'),
          challenge: challenge,
          keyId: keyId,
          bundleIdentifier: bundleIdentifier,
          teamIdentifier: teamId,
          allowDevelopmentEnvironment: true // Set to `false` in production
      });

      console.log("Attestation result:", result);

      //     // generate Auth0 JWT for authetnication on /token
          const token = jwt.sign({ jti: crypto.randomUUID,}, auth0PrivateKey, {
            expiresIn: '10m', 
            audience: 'https://nelson.jp.auth0.com/',
            issuer: "6AlelVCVUXlXozlThgtWp54GP8dOrnek",
            header: {
                alg: 'RS256',
                kid: "2WitOoEuiUeIkGaB_j6QqjWCqSepKODyX8mZkwkayL0",
                typ: 'JWT'
            },
            subject: "6AlelVCVUXlXozlThgtWp54GP8dOrnek",
           
        });

      return res.status(200).json({
          message: "Attestation verified successfully",
          publicKey: result.publicKey,
          keyId: keyId,
          auth0Token: token
      });
  } catch (error) {
      console.error("Error verifying attestation:", error);
      return res.status(401).json({ message: "Attestation verification failed", error: error.message });
  }
});


// Challenge endpoint for app attestation
app.get("/get-challenge", (req, res) => {
    // const challenge = crypto.randomBytes(32).toString('base64');
    const challenge = uuid();
    console.log(`Challenge generated ${challenge}`)
    res.status(200).json({ challenge });
});

app.get("/*", (_, res) => {
    res.sendFile(join(__dirname, "index.html"));
});

process.on("SIGINT", function() {
    process.exit();
});

module.exports = app;

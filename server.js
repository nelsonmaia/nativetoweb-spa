const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const crypto = require("crypto");
const jwt = require('jsonwebtoken');
const { verifyCertificateChain, parseCBOR, validateAttestation } = require('./attestationHelpers');

const app = express();

// Middleware setup
app.use(morgan("dev"));
app.use(helmet());
app.use(express.json());
app.use(express.static(join(__dirname, "public")));

// Load the private key for JWT signing
const privateKey = process.env.PRIVATE_KEY;
const auth0PrivateKey = process.env.AUTH0_PRIVATE_KEY;

// Replace with your actual values
const teamId = 'GCAN367Y39';
const keyId = 'SVR9K69LLW';
const issuerId = '05eed3c0-d784-42b6-a078-58d67ce0ffc3';

// Function to generate the JWT token
function generateJWT() {
    return jwt.sign({}, privateKey, {
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
}

// POST route to verify attestation
app.post("/verify-attestation", async (req, res) => {
    const { keyId, attestation } = req.body;

    if (!keyId || !attestation) {
        console.error("Invalid request: Missing keyId or attestation");
        return res.status(400).json({ message: "Invalid request, missing keyId or attestation" });
    }

    try {
        console.log("Received keyId:", keyId);
        console.log("Received attestation (base64):", attestation);

        const attestationBuffer = Buffer.from(attestation, 'base64');
        console.log("Attestation buffer length:", attestationBuffer.length);

        const decodedAttestation = parseCBOR(attestationBuffer);
        console.log("Decoded attestation:", decodedAttestation);

        const isValidChain = verifyCertificateChain(decodedAttestation.attStmt.x5c, process.env.APPLE_ROOT_CERT);
        console.log("Certificate chain validation result:", isValidChain);
        if (!isValidChain) {
            console.error("Invalid certificate chain");
            return res.status(400).json({ message: "Invalid certificate chain" });
        }

        const challengeHash = crypto.createHash('sha256').update(decodedAttestation.authData).digest();
        console.log("Challenge hash (hex):", challengeHash.toString('hex'));

        const compositeHash = crypto.createHash('sha256').update(Buffer.concat([decodedAttestation.authData, challengeHash])).digest();
        console.log("Composite hash (hex):", compositeHash.toString('hex'));

        const isNonceValid = validateAttestation(decodedAttestation, compositeHash);
        console.log("Nonce validation result:", isNonceValid);
        if (!isNonceValid) {
            console.error("Nonce validation failed");
            return res.status(400).json({ message: "Nonce validation failed" });
        }

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

// GET route to generate a challenge
app.get("/get-challenge", (req, res) => {
    const challenge = crypto.randomBytes(32);
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

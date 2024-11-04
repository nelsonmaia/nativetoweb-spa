import express from 'express';
import { join } from 'path';
import morgan from 'morgan';
import helmet from 'helmet';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { verifyAttestation } from 'node-app-attest';

const app = express();

app.use(morgan("dev"));
app.use(helmet());
app.use(express.json());
app.use(express.static(join(__dirname, "public")));

// Load the private key for JWT signing
const privateKey = process.env.PRIVATE_KEY;
const auth0PrivateKey = process.env.AUTH0_PRIVATE_KEY;

// Replace with your actual values
const teamId = 'GCAN367Y39';
const bundleIdentifier = 'com.yourapp.bundleid'; // Replace with your app's bundle identifier

app.post("/verify-attestation", async (req, res) => {
    const { keyId, attestation, challenge } = req.body;

    if (!keyId || !attestation || !challenge) {
        console.error("Invalid request: Missing keyId, attestation, or challenge");
        return res.status(400).json({ message: "Invalid request, missing keyId, attestation, or challenge" });
    }

    try {
        console.log("Received keyId:", keyId);
        console.log("Received attestation (base64):", attestation);

        const result = verifyAttestation({
            attestation: Buffer.from(attestation, 'base64'),
            challenge: challenge,
            keyId: keyId,
            bundleIdentifier: bundleIdentifier,
            teamIdentifier: teamId,
            allowDevelopmentEnvironment: true // Set to `false` in production
        });

        console.log("Attestation result:", result);

        return res.status(200).json({
            message: "Attestation verified successfully",
            publicKey: result.publicKey,
            keyId: keyId
        });
    } catch (error) {
        console.error("Error verifying attestation:", error);
        return res.status(401).json({ message: "Attestation verification failed", error: error.message });
    }
});

app.get("/get-challenge", (req, res) => {
    const challenge = crypto.randomBytes(32).toString('base64');
    res.status(200).json({ challenge });
});

app.get("/*", (_, res) => {
    res.sendFile(join(__dirname, "index.html"));
});

process.on("SIGINT", function() {
    process.exit();
});

export default app;

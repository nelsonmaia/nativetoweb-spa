const crypto = require('crypto');
const cbor = require('cbor');

// Function to parse CBOR
function parseCBOR(buffer) {
    return cbor.decodeFirstSync(buffer);
}

// Verify the certificate chain using Node.js `crypto` module
function verifyCertificateChain(certChain, rootCertPem) {
    try {
        for (let i = 0; i < certChain.length - 1; i++) {
            const certBuffer = Buffer.from(certChain[i]);
            const parentCertBuffer = Buffer.from(certChain[i + 1]);

            // Create the public key from the parent certificate
            const parentPublicKey = crypto.createPublicKey({
                key: parentCertBuffer,
                format: 'der',
                type: 'spki'
            });

            // Verify the current certificate with the parent public key
            const isVerified = crypto.verify(
                'sha256',
                certBuffer,
                parentPublicKey,
                certBuffer
            );

            if (!isVerified) {
                console.error(`Certificate ${i} verification failed`);
                return false;
            }
        }

        console.log("Certificate chain verified successfully.");
        return true;
    } catch (error) {
        console.error("Certificate verification process failed:", error);
        return false;
    }
}

// Function to extract and validate the nonce
function extractAndValidateNonce(cert, expectedNonce) {
    try {
        const nonceExtension = cert.extensions.find(ext => ext.id === '1.2.840.113635.100.8.2');
        if (!nonceExtension) {
            console.error("Nonce extension not found");
            return false;
        }

        const nonce = Buffer.from(nonceExtension.value, 'hex');
        return nonce.equals(expectedNonce);
    } catch (error) {
        console.error("Error extracting and validating nonce:", error);
        return false;
    }
}

// Function to validate attestation
function validateAttestation(attestationObj, expectedNonce) {
    const { attStmt, authData } = attestationObj;
    const certChain = attStmt.x5c;

    if (!verifyCertificateChain(certChain, process.env.APPLE_ROOT_CERT)) {
        console.error("Certificate chain verification failed");
        return false;
    }

    const firstCertBuffer = Buffer.from(certChain[0]);
    const credCert = crypto.createPublicKey({ key: firstCertBuffer, format: 'der', type: 'spki' });

    if (!extractAndValidateNonce(credCert, expectedNonce)) {
        console.error("Nonce validation failed");
        return false;
    }

    console.log("Attestation successfully validated.");
    return true;
}

module.exports = {
    verifyCertificateChain,
    parseCBOR,
    extractAndValidateNonce,
    validateAttestation,
};

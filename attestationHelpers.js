const forge = require('node-forge');
const crypto = require('crypto');
const cbor = require('cbor');

// Load Apple Root Certificate (PEM format)
const APPLE_ROOT_CERT_PEM = process.env.APPLE_ROOT_CERT; // Ensure the cert is set as an environment variable or load directly

// Convert PEM to DER format
function pemToDer(pem) {
    const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, '');
    return Buffer.from(base64, 'base64');
}

// Verify the certificate chain using Node.js `crypto` module
function verifyCertificateChain(certChain, rootCertPem) {
    try {
        for (let i = 0; i < certChain.length - 1; i++) {
            const cert = certChain[i];
            const parentCert = certChain[i + 1];

            // Extract the public key from the parent certificate
            const parentCertDer = Buffer.from(parentCert);
            const parentPublicKey = crypto.createPublicKey({
                key: parentCertDer,
                format: 'der',
                type: 'spki'
            });

            // Verify current certificate with the parent public key
            const isVerified = crypto.verify(
                'sha256',
                cert,
                {
                    key: parentPublicKey,
                    format: 'der',
                    type: 'spki'
                },
                cert
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


// Function to extract and validate nonce from a certificate
function extractAndValidateNonce(cert, expectedNonce) {
  const ext = cert.extensions.find(ext => ext.id === '1.2.840.113635.100.8.2');
  if (!ext) {
    console.error("Nonce extension not found");
    return false;
  }

  const nonceAsn1 = forge.asn1.fromDer(Buffer.from(ext.value, 'base64').toString('binary'));
  const nonce = nonceAsn1.value[0].value;

  return nonce === expectedNonce;
}

// Function to validate attestation
function validateAttestation(attestationObj, expectedNonce) {
  const { attStmt, authData } = attestationObj;
  const credCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(attStmt.x5c[0].toString('binary')));

  if (!verifyCertificateChain(attStmt.x5c)) {
    console.error("Certificate chain verification failed");
    return false;
  }

  if (!extractAndValidateNonce(credCert, expectedNonce)) {
    console.error("Nonce validation failed");
    return false;
  }

  console.log("Attestation successfully validated.");
  return true;
}

module.exports = {
  verifyCertificateChain,
  pemToDer,
  extractAndValidateNonce,
  validateAttestation,
};

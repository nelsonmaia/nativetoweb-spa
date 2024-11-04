const forge = require('node-forge');
const cbor = require('cbor');
const asn1 = forge.asn1;
const crypto = require("crypto"); 

// Load Apple Root Certificate
const APPLE_ROOT_CERT_PEM = process.env.APPLE_ROOT_CERT; // Ensure it is loaded from your environment or directly in the code

// Helper to convert PEM to DER format
function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, '');
  return Buffer.from(base64, 'base64');
}

// Function to verify the certificate chain using crypto module
function verifyCertificateChain(certChain) {
  try {
    const rootCert = crypto.createPublicKey({
      key: APPLE_ROOT_CERT_PEM,
      format: 'pem',
      type: 'spki',
    });

    for (let i = 0; i < certChain.length - 1; i++) {
      const cert = certChain[i];
      const parentCert = certChain[i + 1];
      // Verify the certificate using the parent public key
      const isVerified = crypto.verify(
        null,
        cert,
        {
          key: parentCert,
          format: 'der',
          type: 'spki',
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

function parseCBOR(buffer) {
  return cbor.decodeFirstSync(buffer);
}

function extractAndValidateNonce(cert, expectedNonce) {
  const ext = cert.extensions.find(ext => ext.id === '1.2.840.113635.100.8.2');
  if (!ext) {
    console.error("Nonce extension not found");
    return false;
  }

  const nonceAsn1 = asn1.fromDer(Buffer.from(ext.value, 'base64').toString('binary'));
  const nonce = nonceAsn1.value[0].value;

  return nonce === expectedNonce;
}

function validateAttestation(attestationObj, expectedNonce, keyId) {
  const { attStmt, authData } = attestationObj;

  const credCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(attStmt.x5c[0].toString('binary')));
  const isCertValid = verifyCertificateChain(attStmt.x5c);

  if (!isCertValid) {
    console.error("Certificate chain verification failed");
    return false;
  }

  const nonceIsValid = extractAndValidateNonce(credCert, expectedNonce);
  if (!nonceIsValid) {
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

const forge = require('node-forge');
const crypto = require('crypto');
const cbor = require('cbor');

// Load Apple Root Certificate (PEM format)
const APPLE_ROOT_CERT_PEM = process.env.APPLE_ROOT_CERT; // Load from an environment variable or directly in the code

// Helper function to convert PEM to DER format
function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, '');
  return Buffer.from(base64, 'base64');
}

// Function to verify the certificate chain using Node.js `crypto` module and `node-forge`
function verifyCertificateChain(certChain) {
  try {
    // Convert root certificate from PEM to a usable public key
    const rootCert = crypto.createPublicKey({
      key: APPLE_ROOT_CERT_PEM,
      format: 'pem',
      type: 'spki',
    });

    for (let i = 0; i < certChain.length - 1; i++) {
      const certBuffer = Buffer.from(certChain[i].toString('binary'), 'binary');
      const parentCertBuffer = Buffer.from(certChain[i + 1].toString('binary'), 'binary');

      const certPem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(certBuffer)));
      const parentCertPem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(parentCertBuffer)));

      const certPublicKey = crypto.createPublicKey({
        key: parentCertPem,
        format: 'pem',
        type: 'spki',
      });

      const isVerified = crypto.verify(
        null,
        certBuffer,
        {
          key: certPublicKey,
          format: 'der',
          type: 'spki',
        },
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

// Function to decode CBOR
function parseCBOR(buffer) {
  return cbor.decodeFirstSync(buffer);
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
  parseCBOR,
  extractAndValidateNonce,
  validateAttestation,
};

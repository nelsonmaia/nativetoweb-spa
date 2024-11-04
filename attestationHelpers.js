const forge = require('node-forge');
const crypto = require('crypto');
const cbor = require('cbor');

// Load Apple Root Certificate (PEM format)
const APPLE_ROOT_CERT_PEM = process.env.APPLE_ROOT_CERT; // Ensure the cert is set as an environment variable or load directly

// Helper to convert PEM to DER format
function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, '');
  return Buffer.from(base64, 'base64');
}

// Function to verify the certificate chain using node-forge and crypto
function verifyCertificateChain(certChain) {
  try {
    const rootCert = forge.pki.certificateFromPem(APPLE_ROOT_CERT_PEM);
    const chain = certChain.map((cert, index) => {
      try {
        console.log(`Parsing certificate ${index}`);
        const parsedCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(cert.toString('binary')));
        console.log(`Certificate ${index} successfully parsed`);
        return parsedCert;
      } catch (err) {
        console.error(`Failed to parse certificate ${index}:`, err);
        throw err;
      }
    });

    // Verify the chain using crypto for final check
    for (let i = 0; i < chain.length - 1; i++) {
      const currentCert = chain[i];
      const nextCert = chain[i + 1];
      const currentPublicKey = forge.pki.publicKeyToPem(currentCert.publicKey);
      const nextPemCert = forge.pki.certificateToPem(nextCert);
      const isVerified = crypto.verify(
        null,
        Buffer.from(nextPemCert),
        {
          key: currentPublicKey,
          format: 'pem',
          type: 'spki',
        },
        Buffer.from(nextPemCert)
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

// Function to decode CBOR and extract data
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
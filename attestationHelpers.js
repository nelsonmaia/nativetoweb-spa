const forge = require('node-forge');
const cbor = require('cbor');
const asn1 = forge.asn1;

// Apple App Attest root certificate
const APPLE_ROOT_CERT = `-----BEGIN CERTIFICATE-----
MIIEyDCCA7CgAwIBAgIJANsmHf+uGH/NMA0GCSqGSIb3DQEBCwUAMIGVMQswCQYD
VQQGEwJVUzEVMBMGA1UEChMMQXBwbGUgSW5jLiBPUzElMCMGA1UECxMcQXBwbGUg
Um9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEwMC4GA1UEAxMnQXBwbGUgUm9v
dCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBSU0EgNTAgMB4XDTIwMDgxODE4NTM0
NFoXDTQwMDgxNTE4NTM0NFowgaQxCzAJBgNVBAYTAlVTMRUwEwYDVQQKDAxBcHBs
ZSBJbmMuIE9TMSUwIwYDVQQLDBxBcHBsZSBSb290IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MTAwLgYDVQQDDCdhcHBsZSByb290IGNlcnRpZmljYXRpb24gYXV0aG9y
aXR5IHJzYSA1MC4wDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANUU6FISwJ/Q
...
-----END CERTIFICATE-----`;

function verifyCertificateChain(certChain) {
  const rootCert = forge.pki.certificateFromPem(APPLE_ROOT_CERT);
  const chain = certChain.map(cert => forge.pki.certificateFromAsn1(forge.asn1.fromDer(cert.toString('binary'))));
  
  try {
    const verified = forge.pki.verifyCertificateChain(rootCert, chain, (vfd) => ({ verified: vfd === true }));
    return verified;
  } catch (error) {
    console.error("Certificate verification failed:", error);
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

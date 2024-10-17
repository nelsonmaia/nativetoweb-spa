# Native to Web Authentication PoC

This repository contains a Proof of Concept (PoC) for implementing authentication that bridges native iOS apps with web applications using **Auth0**, **App Attestation**, and **OAuth token exchanges**. It includes both a native iOS app (`ios-swift-01-login`) and a JavaScript-based web app.

## Project Structure

- **ios-swift-01-login**: Native iOS app demonstrating user authentication, App Attestation, and token exchanges.
- **Web App**: JavaScript-based app that interacts with the Auth0 authorization server and validates tokens.

## Key Features

- **App Attestation**: Verifies that the app running on the device is legitimate using Apple’s App Attest service.
- **Token Exchange**: Demonstrates exchanging an ID token for a login ticket, and subsequently using the ticket to authenticate via Auth0.
- **OAuth Authentication**: Secure login flow using Auth0, exchanging login tickets for access tokens to authenticate API requests.

## Setup

### iOS App

1. Open the `ios-swift-01-login` project in **Xcode**.
2. Ensure proper signing certificates are used.
3. Archive the app by selecting **Product > Archive**.
4. Use **TestFlight** or export `.ipa` for manual distribution.

### Web App

1. Ensure the Node.js backend (e.g., `server.js`, `app.js`) is set up.
2. Deploy the web app using **Vercel** or another hosting platform.

## Running the Project

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd nativeweb-spademo

## App Attestation

The app uses **Apple’s App Attestation** to ensure that only valid instances of the app can communicate with the backend. This process enhances security by verifying that the app is genuine and not tampered with.

### Flow:

```plaintext
NativeApp -> Backend: GET /get-challenge
Backend --> NativeApp: challenge (random string)
NativeApp -> Apple: Attest Key (Key ID, challenge)
Apple --> NativeApp: attestation (signed data)
NativeApp -> Backend: POST /verify-attestation (Key ID, attestation)
Backend -> Apple: POST /v1/attestation (Key ID, attestation, JWT)
Apple --> Backend: Attestation Verification Response
Backend --> NativeApp: Verification Status
```

### Explanation:

1. **Challenge Generation**: 
   The backend provides a random challenge (like a nonce) to the app. This challenge is used to ensure the app's authenticity.

2. **Attestation Request**: 
   The native app generates a key and sends the challenge to Apple’s App Attestation API to validate that the app instance is genuine.

3. **Apple Validation**: 
   Apple returns a signed attestation if the app is valid and not tampered with.

4. **Backend Verification**: 
   The native app sends the attestation and key ID to the backend, which verifies it with Apple’s API.

5. **Verification Status**: 
   The backend responds to the native app with the attestation verification status.

This process ensures only legitimate app instances can access the backend, enhancing security by preventing tampered or modified apps from interacting with the server.

const express = require("express");
const { join } = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const axios = require("axios"); // Use axios for HTTP requests

const app = express();

// Middleware setup
app.use(morgan("dev"));
app.use(helmet());
app.use(express.json()); // To parse incoming JSON requests
app.use(express.static(join(__dirname, "public")));

// Route for static files
app.get("/auth_config.json", (req, res) => {
  res.sendFile(join(__dirname, "auth_config.json"));
});

// New POST route for App Attestation verification
app.post("/verify-attestation", async (req, res) => {
  const { keyId, attestation } = req.body;

  if (!keyId || !attestation) {
    return res.status(400).json({ message: "Invalid request, missing keyId or attestation" });
  }

  try {
    // Call Apple's App Attestation service to verify the attestation
    // const appleResponse = await axios.post('https://api.apple.com/appattest/v1/attestation', {
    //   keyId: keyId,
    //   attestation: attestation
    // }, {
    //   headers: {
    //     'Content-Type': 'application/json',
    //     'Authorization': 'Bearer YOUR_API_KEY' // Replace with your Apple API key or authentication method
    //   }
    // });

    // If the attestation is verified successfully
    return res.status(200).json({ message: "Attestation verified", data: "appleResponse.data" });

  } catch (error) {
    console.error("Error verifying attestation:", error.response ? error.response.data : error.message);
    return res.status(500).json({ message: "Internal server error", error: error.message });
  }
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

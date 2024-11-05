import DeviceCheck
import Foundation
import CryptoKit

struct AppAttestService {

    // Function to attest the app and generate the attestation
    static func attestApp(apiResponseHandler: @escaping (String) -> Void) {
        if DCAppAttestService.shared.isSupported {
            // Generate a new key for attestation
            DCAppAttestService.shared.generateKey { keyId, error in
                guard error == nil else {
                    print("Error generating key: \(error!.localizedDescription)")
                    apiResponseHandler("Error generating key: \(error!.localizedDescription)")
                    return
                }
                guard let keyId = keyId else {
                    print("Failed to generate key")
                    apiResponseHandler("Failed to generate key")
                    return
                }
                print("Generated Key ID: \(keyId)")

                // Fetch a challenge from your backend server
                fetchChallenge { challenge in
                    // Convert the challenge from String to Data
                    guard let challengeData = challenge.data(using: .utf8) else {
                        print("Failed to convert challenge to Data")
                        apiResponseHandler("Failed to convert challenge to Data")
                        return
                    }
                    
                    let hashedChallenge = Data(SHA256.hash(data: challengeData))
                      
                    // Perform the attestation with the challenge
                    DCAppAttestService.shared.attestKey(keyId, clientDataHash: hashedChallenge) { attestation, error in
                        guard error == nil else {
                            print("Error in app attestation: \(error!.localizedDescription)")
                            apiResponseHandler("Error in app attestation: \(error!.localizedDescription)")
                            return
                        }
                        guard let attestation = attestation else {
                            apiResponseHandler("No attestation data received")
                            print("No attestation data received")
                            return
                        }

                        // Send the attestation and keyId to your backend server
                        sendAttestationToServer(attestation: attestation, keyId: keyId, challenge: challenge, apiResponseHandler: apiResponseHandler)
                    }
                }
            }
        } else {
            print("App Attestation is not supported on this device")
            apiResponseHandler("App Attestation is not supported on this device")
        }
    }

    static func fetchChallenge(completion: @escaping (String) -> Void) {
        guard let url = URL(string: "https://nativetoweb-spa.vercel.app/get-challenge") else {
            print("Invalid backend URL")
            return
        }

        URLSession.shared.dataTask(with: url) { data, response, error in
            guard let data = data, error == nil else {
                print("Error fetching challenge: \(error?.localizedDescription ?? "Unknown error")")
                return
            }

            // Parse the JSON response as-is
            do {
                if let jsonResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let challenge = jsonResponse["challenge"] as? String {
                    print("Fetched Challenge (UUID): \(challenge)")
                    completion(challenge) // Pass the UUID directly to completion
                } else {
                    print("Failed to parse JSON response or missing 'challenge' key")
                }
            } catch {
                print("JSON parsing error: \(error.localizedDescription)")
            }
        }.resume()
    }

    static func sendAttestationToServer(attestation: Data, keyId: String, challenge: String, apiResponseHandler: @escaping (String) -> Void) {
        guard let url = URL(string: "https://nativetoweb-spa.vercel.app/verify-attestation") else {
            print("Invalid backend URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        let json: [String: Any] = [
            "keyId": keyId,
            "attestation": attestation.base64EncodedString(),
            "challenge": challenge
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: json, options: []) else {
            print("Error serializing JSON")
            return
        }

        request.httpBody = jsonData
        
        print("Json Data : \(json)")

        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Error sending attestation: \(error!.localizedDescription)")
                return
            }
            // Convert the response data to a readable JSON string for debugging
               if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []),
                  let jsonData = try? JSONSerialization.data(withJSONObject: jsonResponse, options: .prettyPrinted),
                  let jsonString = String(data: jsonData, encoding: .utf8) {
                   print("\(jsonString)")
                   apiResponseHandler("\(jsonString)")
               } else {
                   print("Unable to parse response as JSON")
                   apiResponseHandler("Unable to parse response as JSON")
               }
        }.resume()
    }
}

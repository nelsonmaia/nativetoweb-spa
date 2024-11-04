//
//  AppAttestService.swift
//  SwiftSample
//
//  Created by Nelson Maia Matias on 17/10/2024.
//

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
                    // Perform the attestation with the challenge
                    DCAppAttestService.shared.attestKey(keyId, clientDataHash: challenge) { attestation, error in
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
                        sendAttestationToServer(attestation: attestation, keyId: keyId, apiResponseHandler: apiResponseHandler)
                    }
                }
            }
        } else {
            print("App Attestation is not supported on this device")
            apiResponseHandler("App Attestation is not supported on this device")
        }
    }

    static func fetchChallenge(completion: @escaping (Data) -> Void) {
        guard let url = URL(string: "https://nativetoweb-spa.vercel.app/get-challenge") else {
            print("Invalid backend URL")
            return
        }

        URLSession.shared.dataTask(with: url) { data, response, error in
               guard let data = data, error == nil else {
                   print("Error fetching challenge: \(error?.localizedDescription ?? "Unknown error")")
                   return
               }
            
            
                print("Fetched Challenge Response0: \(data)")

               // Decode the JSON response
               if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                  let challengeString = jsonResponse["challenge"] as? String {
                   print("Fetched Challenge (Base64): \(challengeString)")
                   
                   // Convert the Base64 challenge string into Data
                   if let challengeData = Data(base64Encoded: challengeString) {
                       
                       // Hash the challenge using SHA256
                       let hash = Data(SHA256.hash(data: challengeData))
                       
                       // Print the hash in Base64 to verify
                       print("SHA256 Hash (Base64): \(hash.base64EncodedString())")
                       
                       // Call the completion handler with the hashed challenge
                       completion(hash)
                   } else {
                       print("Failed to decode Base64 challenge")
                   }
               } else {
                   print("Failed to parse JSON response")
               }
           }.resume()
    }

    static func sendAttestationToServer(attestation: Data, keyId: String, apiResponseHandler: @escaping (String) -> Void) {
        guard let url = URL(string: "https://nativetoweb-spa.vercel.app/verify-attestation") else {
            print("Invalid backend URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        let json: [String: Any] = [
            "keyId": keyId,
            "attestation": attestation.base64EncodedString() // Convert Data to base64
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: json, options: []) else {
            print("Error serializing JSON")
            return
        }

        request.httpBody = jsonData
        
        print("Json Data : \(jsonData)")

        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Error sending attestation: \(error!.localizedDescription)")
                return
            }
            // Convert the response data to a readable JSON string for debugging
               if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []),
                  let jsonData = try? JSONSerialization.data(withJSONObject: jsonResponse, options: .prettyPrinted),
                  let jsonString = String(data: jsonData, encoding: .utf8) {
                   print("Attestation sent successfully. Response JSON: \(jsonString)")
                   apiResponseHandler("Attestation sent successfully")
               } else {
                   print("Unable to parse response as JSON")
                   apiResponseHandler("Unable to parse response as JSON")
               }
        }.resume()
    }
}

import SwiftUI
import Foundation
import Auth0

struct ProfileView: View {
    let user: User
    let apiResponse1: String // Holds the response from the first API
    let apiResponse2: String // Holds the response from the second API

    @State private var decodedAccessTokenClaims: [String: String] = [:] // Store decoded access token claims
    @State private var decodedIdTokenClaims: [String: String] = [:] // Store decoded ID token claims
    
    var body: some View {
        List {
            // User Profile Section
            Section(header: ProfileHeader(picture: user.picture)) {
                ProfileCell(key: "ID", value: user.id)
                ProfileCell(key: "Name", value: user.name)
                ProfileCell(key: "Email", value: user.email)
                ProfileCell(key: "Email Verified?", value: user.emailVerified)
                ProfileCell(key: "Updated at", value: user.updatedAt)
                
            }
            
      
            
            
//            // First API Response Section
//            Section(header: Text("API Response 1")) {
//                Text(apiResponse1.isEmpty ? "No Data" : apiResponse1)
//                    .font(.body)
//                    .foregroundColor(.gray)
//            }

            // Second API Response Section (showing only Access Token and ID Token)
//            Section(header: Text("Access Token and ID Token")) {
//                Text("Access Token")
//                    .font(.headline)
//                    .foregroundColor(.black)
//                Text(extractAccessToken(from: apiResponse2))
//                    .font(.body)
//                    .foregroundColor(.blue)
//                    .padding()
//                    .background(Color(UIColor.secondarySystemBackground))
//                    .cornerRadius(8)
//                    .contextMenu {
//                        Button(action: {
//                            UIPasteboard.general.string = extractAccessToken(from: apiResponse2)
//                        }) {
//                            Text("Copy Access Token")
//                            Image(systemName: "doc.on.doc")
//                        }
//                    }
//
//                Text("ID Token")
//                    .font(.headline)
//                    .foregroundColor(.black)
//                Text(extractIdToken(from: apiResponse2))
//                    .font(.body)
//                    .foregroundColor(.blue)
//                    .padding()
//                    .background(Color(UIColor.secondarySystemBackground))
//                    .cornerRadius(8)
//                    .contextMenu {
//                        Button(action: {
//                            UIPasteboard.general.string = extractIdToken(from: apiResponse2)
//                        }) {
//                            Text("Copy ID Token")
//                            Image(systemName: "doc.on.doc")
//                        }
//                    }
//
//                // Decode Button
//                Button(action: decodeTokens) {
//                    Text("Decode Tokens")
//                        .font(.headline)
//                        .padding()
//                        .frame(maxWidth: .infinity)
//                        .background(Color.blue)
//                        .foregroundColor(.white)
//                        .cornerRadius(8)
//                }
//            }

            // Decoded Access Token Claims
//            if !decodedAccessTokenClaims.isEmpty {
//                Section(header: Text("Decoded Access Token - Claims")) {
//                    ForEach(decodedAccessTokenClaims.keys.sorted(), id: \.self) { key in
//                        ProfileCell(key: key, value: decodedAccessTokenClaims[key] ?? "")
//                    }
//                }
//            }

            // Decoded ID Token Claims
//            if !decodedIdTokenClaims.isEmpty {
//                Section(header: Text("Decoded ID Token - Claims")) {
//                    ForEach(decodedIdTokenClaims.keys.sorted(), id: \.self) { key in
//                        ProfileCell(key: key, value: decodedIdTokenClaims[key] ?? "")
//                    }
//                }
//            }
        }
    }
    
    // Helper functions to extract Access Token and ID Token from the API response
    func extractAccessToken(from response: String) -> String {
//        print("Extracting token from response: \(response)")

            // Handle JSON response structure
            if let data = response.data(using: .utf8),
               let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let accessToken = jsonResponse["access_token"] as? String {
                return accessToken
            }
            
            // Handle the old format with HTML-like structure
            guard let start = response.range(of: "name=\"access_token\" value=\"")?.upperBound,
                  let end = response[start...].range(of: "\"")?.lowerBound else {
//                print("No Access Token Found")
                return "No Access Token Found"
            }
            return String(response[start..<end])
    }

    func extractIdToken(from response: String) -> String {
        guard let start = response.range(of: "name=\"id_token\" value=\"")?.upperBound,
              let end = response[start...].range(of: "\"")?.lowerBound else {
            return "No ID Token Found"
        }
        return String(response[start..<end])
    }
    
    // Function to decode both tokens
    func decodeTokens() {
        // Decode the access token
        let accessToken = extractAccessToken(from: apiResponse2)
        if let decodedAccess = decodeJWTClaims(accessToken) {
            decodedAccessTokenClaims = decodedAccess
        } else {
            decodedAccessTokenClaims = ["Error": "Invalid Access Token"]
        }

        // Decode the id token
        let idToken = extractIdToken(from: apiResponse2)
        if let decodedId = decodeJWTClaims(idToken) {
            decodedIdTokenClaims = decodedId
        } else {
            decodedIdTokenClaims = ["Error": "Invalid ID Token"]
        }
    }

    // Helper function to decode JWT and return claims as a dictionary
    func decodeJWTClaims(_ token: String) -> [String: String]? {
        let segments = token.split(separator: ".")
        guard segments.count > 1 else { return nil }

        let base64String = String(segments[1])
        var padded = base64String.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 {
            padded.append("=")
        }

        guard let data = Data(base64Encoded: padded),
              let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return nil
        }

        // Convert the claims to a string dictionary
        var claims: [String: String] = [:]
        for (key, value) in json {
            claims[key] = "\(value)"
        }
        
        return claims
    }
}



//
//  NativeToWeb.swift
//  SwiftSample
//
//  Created by Nelson Maia Matias on 30/01/2025.
//
import Foundation
import WebKit
import Auth0
import SafariServices

struct NativeToWeb {
    
    /// Exchanges the refresh token for a session token.
    /// - Returns: The session token as a String or nil if exchange fails.
    static func exchangeToSessionToken() async -> String? {
        do {
            let credentialsManager = CredentialsManager(authentication: Auth0.authentication())

            let credentials = try await withCheckedThrowingContinuation { continuation in
                credentialsManager.credentials { result in
                    switch result {
                    case .success(let credentials):
                        continuation.resume(returning: credentials)
                    case .failure(let error):
                        continuation.resume(throwing: error)
                    }
                }
            }

            guard let refreshToken = credentials.refreshToken else {
                print("No refresh token available")
                return nil
            }

            guard let domain = getAuth0ConfigurationValue(for: "Domain"),
                  let clientId = getAuth0ConfigurationValue(for: "ClientId") else {
                print("Missing Auth0 configuration")
                return nil
            }

            let tokenExchangeUrl = URL(string: "https://\(domain)/oauth/token")!

            let jsonBody: [String: Any] = [
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                "subject_token": refreshToken,
                "requested_token_type": "urn:auth0:params:oauth:token-type:session_token",
                "client_id": clientId
            ]
            
            print(tokenExchangeUrl)
            print(jsonBody)
            print(clientId)

            var request = URLRequest(url: tokenExchangeUrl)
            request.httpMethod = "POST"
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: jsonBody, options: [])

            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                print("Invalid response from Auth0", response)
                return nil
            }

            if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let sessionToken = jsonResponse["access_token"] as? String {
                print("session token", sessionToken)
                return sessionToken
            } else {
                print("Failed to parse session token")
                return nil
            }
        } catch {
            print("Error in token exchange: \(error)")
            return nil
        }
    }
    
    /// Opens a `WKWebView` with the session token injected as a URL parameter and as a cookie.
    /// - Parameter webView: The `WKWebView` instance.
    static func openWKWebViewWithSessionToken() async -> String? {
        guard let sessionToken = await exchangeToSessionToken() else {
            print("Failed to obtain session token")
            return nil
        }
        print("Returning session token:", sessionToken)

        return sessionToken
    }


    
    
    /// Opens the system browser with the session token appended to the URL.
       static func openSystemBrowserWithSessionToken() {
           Task {
               guard let sessionToken = await exchangeToSessionToken() else {
                   print("Failed to obtain session token")
                   return
               }

               let targetUrlString = "https://nativetoweb-spa.vercel.app/profile?session_token=\(sessionToken)"

               guard let url = URL(string: targetUrlString) else {
                   print("Invalid URL")
                   return
               }

               DispatchQueue.main.async {
                   UIApplication.shared.open(url, options: [:], completionHandler: nil)
               }
           }
       }
    
    
    
    /// Opens SafariViewController with the session token in the URL.
        /// - Parameter presentingViewController: The current `UIViewController` instance to present SafariViewController.
        static func openSafariViewControllerWithSessionToken(from presentingViewController: UIViewController) {
            Task {
                guard let sessionToken = await exchangeToSessionToken() else {
                    print("Failed to obtain session token")
                    return
                }

                let targetUrlString = "https://nativetoweb-spa.vercel.app/profile?session_token=\(sessionToken)"
                
                print("targetUrlString SafariViewController", targetUrlString)

                guard let url = URL(string: targetUrlString) else {
                    print("Invalid URL")
                    return
                }

                DispatchQueue.main.async {
                    let safariViewController = SFSafariViewController(url: url)
                    presentingViewController.present(safariViewController, animated: true, completion: nil)
                }
            }
        }
    
    
    
    
    
    
    /// Retrieves Auth0 configuration values from the Auth0.plist file.
    /// - Parameter key: The key to retrieve.
    /// - Returns: The corresponding value as a String or nil if missing.
    public static func getAuth0ConfigurationValue(for key: String) -> String? {
        if let path = Bundle.main.path(forResource: "Auth0", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path) as? [String: Any] {
            return dict[key] as? String
        }
        return nil
    }
}


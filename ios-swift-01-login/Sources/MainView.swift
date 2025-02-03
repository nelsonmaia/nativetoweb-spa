import SwiftUI
import WebKit
import Auth0
import SafariServices // Import SafariServices for SafariViewController
import DeviceCheck
import Foundation


struct MainView: View {
    @State var user: User?
    @State var idToken: String = "" // Store the ID token from Auth0 login
    @State var apiResponse1: String = "" // Holds the first API response
    @State var apiResponse2: String = "" // Holds the second API response
    @State var cookies: String = "" // Stores cookies for the second request
    @State var loginTicket: String = "" // Stores login_ticket from the first response
    @State var coId: String = "" // Stores co_id from the first response
    @State var showWebView: Bool = false // State to control WebView display
    @State var sessionToken: String = "" 
    @State var showSafariView: Bool = false // State to control SafariView display
    @State var callbackURL: String = "https://customwebsso.vercel.app"
    @State var auth0ClientAssertion = ""
    @State private var webViewUrl: String? = nil
    @State var ntwWebView: Bool = false // State to control WebView display


    var body: some View {
        if let user = self.user {
            VStack {
                ProfileView(user: user, apiResponse1: apiResponse1, apiResponse2: apiResponse2)
                
                Button("NTW in System Browser") {
                    NativeToWeb.openSystemBrowserWithSessionToken()
                }
                
                Button("NTW in SafariViewController") {
                    if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                       let rootViewController = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController {
                        NativeToWeb.openSafariViewControllerWithSessionToken(from: rootViewController)
                    }
                }
                
                
                
//                Button("NTW WKWebView") {
//                    Task {
//                        if let url = await NativeToWeb.openWKWebViewWithSessionToken() {
//                            print("📌 Received URL in Button: \(url)")
//                            DispatchQueue.main.async {
//                                webViewUrl = url
//                                showWebView = true
//                            }
//                        } else {
//                            print("❌ Failed to get session token.")
//                        }
//                    }
//                }
//
//                .sheet(isPresented: $showWebView) {
//                        Text("📌 Inside sheet: webViewUrl = \(webViewUrl ?? "nil")") // Debugging
//
//                    
//                        if let urlString = webViewUrl {
//                            WebView(urlString: urlString)
//                        }else {
//                            Text("❌ webViewUrl is nil")
//                        }
//                }
                
                Button("NTW WKWebView") {
                    Task {
                        if let url = await NativeToWeb.openWKWebViewWithSessionToken() {
                            print("📌 Received URL: \(url)")
                            DispatchQueue.main.async {
                                webViewUrl = url
                                sessionToken = (url.components(separatedBy: "session_token=").last != nil) // Extract token
                                ntwWebView = true
                            }
                        } else {
                            print("❌ Failed to get session token.")
                        }
                    }
                }
                .sheet(isPresented: $ntwWebView) {
                    if let urlString = webViewUrl, let token = sessionToken {
                        WebView(urlString: urlString, sessionToken: token)
                    } else {
                        Text("❌ webViewUrl or sessionToken is nil")
                    }
                }

                
                
                Button("Get new access token") {
                    Task {
                           await getNewAccessTokenUsingAuth0SDK()
                       }
                }
                
                Button("Attest App") {
                    AppAttestService.attestApp { response in
                        self.apiResponse1 = response
                        
                        // Parse response to capture the AUth0 JTW for authetnication if it exists
                        if let data = response.data(using: .utf8),
                           let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                           let auth0Token = jsonResponse["auth0Token"] as? String {
                            
                            self.auth0ClientAssertion = auth0Token
                            print("Captured auth0ClientAssertion: \(auth0Token)")
                        } else {
                            print("auth0Token not found in response")
                        }
                    }
                }

                // New button to exchange the ID token using the token exchange API
                Button("Exchange Token") {
                    exchangeToken()
                }

                // New button to open WebView with cookies
                Button("WebView") {
                    showWebView = true
                }
//                .sheet(isPresented: $showWebView) {
//                    WebView(urlString: "https://nelson.jp.auth0.com/authorize?response_mode=fragment&response_type=token%20id_token&client_id=6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh&redirect_uri=https://jwt.io/%23&audience=https://nelson.api.com&scope=email%20profile%20openid%20offline_access%20read:test&state=somestatevalue&nonce=nonce&realm=Username-Password-Authentication&login_ticket=\(loginTicket)", cookies: cookies)
//                }
                .sheet(isPresented: $showWebView) {
                    WebView(urlString: "https://nativetoweb-spa.vercel.app/profile?v=1&login_token=\(loginTicket)")
                }

                // New button to open the same URL in SafariViewController
                Button("Open in Safari") {
                    print("https://nativetoweb-spa.vercel.app/profile?v=1&login_token=\(loginTicket)")
                    showSafariView = true
                }
//                .sheet(isPresented: $showSafariView) {
//                    SafariView(url: URL(string: "https://nelson.jp.auth0.com/authorize?response_mode=fragment&response_type=token%20id_token&client_id=6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh&redirect_uri=\(callbackURL)&audience=https://nelson.api.com&scope=email%20profile%20openid%20offline_access%20read:test&state=somestatevalue&nonce=nonce&realm=Username-Password-Authentication&login_ticket=\(loginTicket)")!)
//                }
//                .sheet(isPresented: $showSafariView) {
//                    SafariView(url: URL(string: "https://n2w.test-aws-wise-mongoose-7953.auth0c.com/authorize?response_mode=fragment&response_type=token%20id_token&client_id=17REeSmQCj5N23KC1zkFfFtM6fsnzgMT&redirect_uri=\(callbackURL)&audience=https://expenses-api&scope=email%20profile%20openid%20offline_access%20read:test&state=somestatevalue&nonce=nonce&login_token=\(loginTicket)")!)
//                }
                .sheet(isPresented: $showSafariView) {
                    SafariView(url: URL(string: "https://nativetoweb-spa.vercel.app/profile?v=1&login_token=\(loginTicket)")!)
                }
                
                // New button to open the same URL in SafariViewController
                Button("Open without Login Token") {
                    showSafariView = true
                    print("opening https://customwebsso.vercel.app/")
                }
                .sheet(isPresented: $showSafariView) {
                    
                    SafariView(url: URL(string: "https://customwebsso.vercel.app/")!)
                }

                // New button to reset cookies and responses
                Button("Reset Values") {
                    resetValues()
                }

                Button("Logout", action: self.logout)
            }
        } else {
            VStack {
                HeroView()
                Button("Login", action: self.login)
            }
        }
    }
    
    
    func credentials() async throws -> Credentials {
           let credentialsManager = CredentialsManager(authentication: Auth0.authentication())
           
           return try await withCheckedThrowingContinuation { continuation in
               credentialsManager.credentials { result in
                   switch result {
                   case .success(let credentials):
                       continuation.resume(returning: credentials)
                       break

                   case .failure(let reason):
                       continuation.resume(throwing: reason)
                       break
                   }
               }
           }
       }
    
    
    
    func getNewAccessTokenUsingAuth0SDK() async  {
        
        
        do {
            let credentials = try await credentials();
            
            print(credentials.accessToken)
            print("Refresh token: \(credentials.refreshToken ?? "")");

            
            print("Refresh token: \(credentials.refreshToken ?? "")")
            
        } catch {
               // Handle the error
               print("Failed to renew access token: \(error.localizedDescription)")
               self.apiResponse1 = "Error: \(error.localizedDescription)"
           }
            
        
    }

    // Function to reset cookies and responses
    func resetValues() {
        cookies = ""
        apiResponse1 = ""
        apiResponse2 = ""
        loginTicket = ""
        coId = ""
        auth0ClientAssertion = "js djaksndjkasndjkasd"
        // idToken = ""
        print("Values have been reset.")
    }

    // DEPRECATED - INITIAL TESTING WITH CROSS
    func fetchInitialData() {
        let urlString = "https://nelson.jp.auth0.com/co/authenticate"
        print("Calling URL: \(urlString) at \(getCurrentTime())")
        
        guard let url = URL(string: urlString) else {
            print("Invalid URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("http://localhost:3001", forHTTPHeaderField: "Origin")
        request.addValue("http://localhost:3001/cross_origin", forHTTPHeaderField: "Referer")

        let jsonData: [String: Any] = [
            "credential_type": "http://auth0.com/oauth/grant-type/password-realm",
            "client_id": "6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh",
            "username": "user@example.org",
            "password": "Auth0Dem0!",
            "realm": "Username-Password-Authentication"
        ]

        guard let httpBody = try? JSONSerialization.data(withJSONObject: jsonData, options: []) else {
            print("Invalid JSON data")
            return
        }
        request.httpBody = httpBody

        // Perform the first request
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Error in first request: \(error)")
                return
            }

            guard let data = data,
                  let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
                print("Invalid response or data")
                return
            }

            // Extract cookies from the response headers
            if let httpResponse = response as? HTTPURLResponse,
               let setCookie = httpResponse.allHeaderFields["Set-Cookie"] as? String {
                self.cookies = setCookie // Save cookies to use in the next request
            }

            // Extract login_ticket and co_id
            if let loginTicket = jsonResponse["login_ticket"] as? String,
               let coId = jsonResponse["co_id"] as? String {
                self.loginTicket = loginTicket
                self.callbackURL = "https://jwt.io/"
                self.coId = coId
            }

            // Update UI with the first API response
            DispatchQueue.main.async {
                self.apiResponse1 = String(data: data, encoding: .utf8) ?? "No Data"
            }

        }.resume()
    }

    func fetchAuthorizeData() {
        guard !loginTicket.isEmpty else {
            print("login_ticket not available")
            return
        }

        let urlString = "https://nelson.jp.auth0.com/authorize?response_mode=form_post&response_type=token%20id_token&client_id=6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh&redirect_uri=http://localhost:3001/cross_origin&audience=https://nelson.api.com&scope=email%20profile%20openid%20offline_access%20read:test&state=somestatevalue&nonce=nonce&realm=Username-Password-Authentication&login_ticket=\(loginTicket)"
        print("Calling URL: \(urlString) at \(getCurrentTime())")
        
        guard let url = URL(string: urlString) else {
            print("Invalid authorize URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.addValue("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", forHTTPHeaderField: "Accept")
        request.addValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", forHTTPHeaderField: "User-Agent")
        request.addValue(cookies, forHTTPHeaderField: "Cookie") // Use cookies from the first request
        request.addValue("http://localhost:3001", forHTTPHeaderField: "Origin")
        request.addValue("http://localhost:3001/cross_origin", forHTTPHeaderField: "Referer")

        // Perform the second request
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Error in second request: \(error)")
                return
            }

            guard let data = data else {
                print("No data in second request")
                return
            }

            // Update UI with the second API response
            DispatchQueue.main.async {
                self.apiResponse2 = String(data: data, encoding: .utf8) ?? "No Data"
            }

        }.resume()
    }

    // Helper function to read values from Auth0.plist
    func getAuth0ConfigurationValue(for key: String) -> String? {
        if let path = Bundle.main.path(forResource: "Auth0", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path) as? [String: Any] {
            return dict[key] as? String
        }
        return nil
    }
    
   // PoC Token Exchange with custom Auth0 code
    func exchangeToken() {
        guard !idToken.isEmpty else {
            DispatchQueue.main.async {
                self.apiResponse1 = "ID token not available for token exchange."
                
            }
            print("ID token not available for token exchange.")
            return
        }
        
        guard let domain = getAuth0ConfigurationValue(for: "Domain") else {
               print("Domain not found in Auth0.plist")
               return
           }
        
        guard let clientId = getAuth0ConfigurationValue(for: "ClientId") else {
            print("ClientId not found in Auth0.plist")
            return
        }

        let urlString = "https://\(domain)/oauth/token"
           print("Calling URL: \(urlString) at \(getCurrentTime())")

        guard let url = URL(string: urlString) else {
            print("Invalid URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        
        let jsonData: [String: Any] = [
                       "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                       "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                       "subject_token": idToken,
                       "client_id": "6XCtoG9akcdiZf54myfQGv9dTDoqm1Uh",
                       "client_assertion" : auth0ClientAssertion,
                       "client_assertion_type" : "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
               ]
        
        print("\(jsonData)")

        guard let httpBody = try? JSONSerialization.data(withJSONObject: jsonData, options: []) else {
            print("Invalid JSON data")
            return
        }
        request.httpBody = httpBody

        // Perform the token exchange request
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Error in token exchange request: \(error)")
                return
            }

            guard let data = data else {
                print("No data in token exchange response")
                return
            }
            
            // Update UI with the second API response
            DispatchQueue.main.async {
                self.apiResponse2 = String(data: data, encoding: .utf8) ?? "No Data"
            }

            // Log the raw response for debugging
            if let rawResponse = String(data: data, encoding: .utf8) {
                print("Raw Response: \(rawResponse)")
                self.apiResponse1 = rawResponse
            }

            // Try to parse the JSON response to extract the access token
            if let jsonResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let loginToken = jsonResponse["login_token"] as? String {
                print("Login Token: \(loginToken)")
                
                if let loginTicket = jsonResponse["login_token"] as? String {
                    self.loginTicket = loginTicket
//                    self.callbackURL = "https://jwt.io/%23"
                    self.callbackURL = "https://customwebsso.vercel.app/"
                }

                // Update the first API response with the access token
                DispatchQueue.main.async {
                    self.apiResponse1 = "Login Token: \(loginToken)"
                    
                }
                
            } else {
                print("Failed to parse access token from response.")
            }
            
            

        }.resume()
    }



    func login() {
        
        let credentialsManager = CredentialsManager(authentication: Auth0.authentication())
        
       let crend2Manger = CredentialsManager(authentication: Auth0.authentication())
        
        Auth0
            .webAuth()
            .audience("https://nelson.api.com")
            .scope("openid profile email offline_access")
//            .provider(WebAuthentication.safariProvider())
            .start { result in
                switch result {
                case .success(let credentials):
                    self.user = User(from: credentials.idToken)
                    self.idToken = credentials.idToken // Store the ID token
                    self.apiResponse1 = credentials.accessToken
                    print("Refresh token: \(credentials.refreshToken ?? "")")
                    let _ = credentialsManager.store(credentials: credentials)
                    
                case .failure(let error):
                    print("Failed with: \(error)")
                }
            }
    }

    func logout() {
        
        let credentialsManager = CredentialsManager(authentication: Auth0.authentication())

        Auth0
            .webAuth()
            .clearSession { result in
                switch result {
                case .success:
                    self.user = nil
                    self.idToken = "" // Clear the ID token
                    credentialsManager.clear() // Clear stored credentials
                                print("Logged out and cleared credentials.")
                case .failure(let error):
                    print("Failed with: \(error)")
                }
            }
    }
    
    
   

    // Helper function to get the current time
    func getCurrentTime() -> String {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        formatter.dateStyle = .long
        return formatter.string(from: Date())
    }
}


// WebView Component to handle displaying a webpage with cookies
struct WebView: UIViewRepresentable {
    let urlString: String
    let sessionToken: String? // Inject session token from outside

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()

        // Inject cookie before loading the URL
        if let sessionToken = sessionToken {
            let cookie = HTTPCookie(properties: [
                .domain: "jp.auth0.com",
                .path: "/",
                .name: "session_token",
                .value: sessionToken,
                .secure: true,
                .expires: Date(timeIntervalSinceNow: 3600)
            ])
            
            print("Cookies to inject", cookie)

            if let cookie = cookie {
                webView.configuration.websiteDataStore.httpCookieStore.setCookie(cookie)
            }
        }

        // Load the requested URL
        if let url = URL(string: urlString) {
            webView.load(URLRequest(url: url))
        }

        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // No updates needed
    }
}





// SafariView Component for opening URLs in Safari
struct SafariView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: UIViewControllerRepresentableContext<SafariView>) -> SFSafariViewController {
        return SFSafariViewController(url: url)
    }

    func updateUIViewController(_ uiViewController: SFSafariViewController, context: UIViewControllerRepresentableContext<SafariView>) {
        // Nothing to update here
    }
}

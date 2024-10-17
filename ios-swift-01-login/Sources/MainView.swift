import SwiftUI
import WebKit
import Auth0
import SafariServices // Import SafariServices for SafariViewController
import DeviceCheck


struct MainView: View {
    @State var user: User?
    @State var idToken: String = "" // Store the ID token from Auth0 login
    @State var apiResponse1: String = "" // Holds the first API response
    @State var apiResponse2: String = "" // Holds the second API response
    @State var cookies: String = "" // Stores cookies for the second request
    @State var loginTicket: String = "" // Stores login_ticket from the first response
    @State var coId: String = "" // Stores co_id from the first response
    @State var showWebView: Bool = false // State to control WebView display
    @State var showSafariView: Bool = false // State to control SafariView display
    @State var callbackURL: String = "https://customwebsso.vercel.app" // Stores login_ticket from the first response

    var body: some View {
        if let user = self.user {
            VStack {
                ProfileView(user: user, apiResponse1: apiResponse1, apiResponse2: apiResponse2)
                
                Button("Attest App") {
                    AppAttestService.attestApp { response in
                                            self.apiResponse1 = response
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

    // Function to reset cookies and responses
    func resetValues() {
        cookies = ""
        apiResponse1 = ""
        apiResponse2 = ""
        loginTicket = ""
        coId = ""
        idToken = ""
        print("Values have been reset.")
    }

    // Step 1: Perform the initial authentication request
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

    // Step 2: Perform the authorize request using saved cookies and login_ticket
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

    // Step 3: Token Exchange POST request using credentials.idToken
    func exchangeToken() {
        guard !idToken.isEmpty else {
            DispatchQueue.main.async {
                self.apiResponse1 = "ID token not available for token exchange."
                
            }
            print("ID token not available for token exchange.")
            return
        }

        let urlString = "https://n2w.test-aws-wise-mongoose-7953.auth0c.com/oauth/token"
        print("Calling URL: \(urlString) at \(getCurrentTime())")

        guard let url = URL(string: urlString) else {
            print("Invalid URL")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

//        let jsonData: [String: Any] = [
//            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
//            "subject_token_type": "http://acme.com/migration",
//            "subject_token": idToken, // Use the idToken obtained from Auth0 login
//            "client_id": "MWi2qtMbd9bQgZq1Ck7iPc6mWIJ8WMZ5",
//            "audience": "https://nelson.api.com"
////            "scope": "openid email profile"
//        ]
        
        let jsonData: [String: Any] = [
                   "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                   "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                   "subject_token": idToken, // Use the idToken obtained from Auth0 login
                   "client_id": "MWi2qtMbd9bQgZq1Ck7iPc6mWIJ8WMZ5",
               ]

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
        Auth0
            .webAuth()
            .start { result in
                switch result {
                case .success(let credentials):
                    self.user = User(from: credentials.idToken)
                    self.idToken = credentials.idToken // Store the ID token
                    self.apiResponse1 = idToken;
                case .failure(let error):
                    print("Failed with: \(error)")
                }
            }
    }

    func logout() {
        Auth0
            .webAuth()
            .clearSession { result in
                switch result {
                case .success:
                    self.user = nil
                    self.idToken = "" // Clear the ID token
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
//    let cookies: String
    
    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        if let url = URL(string: urlString) {
            var request = URLRequest(url: url)
            
            // Set the cookies in the request headers
            
//                request.addValue(cookies, forHTTPHeaderField: "Cookie")
            
            
            webView.load(request)
        }
        return webView
    }
    
    func updateUIView(_ uiView: WKWebView, context: Context) {
        // Nothing to update here
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

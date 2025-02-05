import Auth0
import DeviceCheck
import Foundation
import SafariServices  // Import SafariServices for SafariViewController
import SwiftUI
import WebKit

struct MainView: View {
    @State var user: User?
    @State var idToken: String = ""  // Store the ID token from Auth0 login
    @State var apiResponse1: String = ""  // Holds the first API response
    @State var apiResponse2: String = ""  // Holds the second API response
    @State var cookies: String = ""  // Stores cookies for the second request
    @State var loginTicket: String = ""  // Stores login_ticket from the first response
    @State var coId: String = ""  // Stores co_id from the first response
    @State var showWebView: Bool = false  // State to control WebView display
    @State var sessionToken: String? = nil
    @State var showSafariView: Bool = false  // State to control SafariView display
    @State var callbackURL: String = "https://customwebsso.vercel.app"
    @State var auth0ClientAssertion = ""
    @State private var webViewUrl: String? = nil
    @State var ntwWebView: Bool = false  // State to control WebView display
    @State var ntwEnabled: Bool = false

    var body: some View {
        if let user = self.user {
            VStack {
                ProfileView(
                    user: user, apiResponse1: apiResponse1,
                    apiResponse2: apiResponse2)

                //                Button("My Web Application ") {
                //                    NativeToWeb.openSystemBrowserWithSessionToken()
                //                }

                Section(header: Text("Native to Web SSO")) {

                    HStack {
                                Spacer()
                                Toggle("Enable NTW SSO", isOn: $ntwEnabled)
                                    .labelsHidden() // Hides default label
                                    .toggleStyle(SwitchToggleStyle(tint: .blue)) // Custom toggle style
                                    .padding(.vertical, 5) // Adjust spacing
                                Text("Enable")
                                    .font(.headline)
                                    .foregroundColor(.primary)
                                Spacer()
                            }

                    Button("View My Rewards Website") {
                        if ntwEnabled {
                            // NTW SSO enabled: Retrieve session token and open SafariViewController
                            if let scene = UIApplication.shared.connectedScenes
                                .first as? UIWindowScene,
                                let rootViewController = scene.windows.first(
                                    where: { $0.isKeyWindow })?
                                    .rootViewController
                            {
                                NativeToWeb
                                    .openSafariViewControllerWithSessionToken(
                                        from: rootViewController)
                            }
                        } else {
                            // NTW SSO disabled: Open the same SafariViewController without session token
                            let targetUrlString =
                                "https://nativetoweb-spa.vercel.app/profile"
                            if let url = URL(string: targetUrlString),
                                let scene = UIApplication.shared.connectedScenes
                                    .first as? UIWindowScene,
                                let rootViewController = scene.windows.first(
                                    where: { $0.isKeyWindow })?
                                    .rootViewController
                            {
                                let safariViewController =
                                    SFSafariViewController(url: url)
                                rootViewController.present(
                                    safariViewController, animated: true,
                                    completion: nil)
                            }
                        }
                    }
                    
                    Button("Get Session Token") {
                            Task {
                                if let token = await NativeToWeb.openWKWebViewWithSessionToken() {
                                    print("📌 Retrieved Session Token: \(token)")
                                    webViewUrl = "https://nativetoweb-spa.vercel.app/profile"
                                    DispatchQueue.main.async {
                                        sessionToken = token
                                    }
                                } else {
                                    print("❌ Failed to retrieve session token.")
                                }
                            }
                        }
                    
                    Button("Open WebView with Cookie") {
                        Task {
                            if let token = sessionToken, !token.isEmpty {
                                print("📌 Using existing session token: \(token)")
                                
                                    webViewUrl = "https://nativetoweb-spa.vercel.app/profile"
                                    showWebView = true
                                
                            } else {
                                print("🔄 Retrieving new session token...")
                                if let newToken = await NativeToWeb.openWKWebViewWithSessionToken() {
                                    print("📌 Retrieved new session token: \(newToken)")
                                    DispatchQueue.main.async {
                                        sessionToken = newToken
                                        webViewUrl = "https://nativetoweb-spa.vercel.app/profile"
                                        showWebView = true
                                    }
                                } else {
                                    print("❌ Failed to retrieve session token.")
                                }
                            }
                        }
                    }

                       
                       // WebView Sheet
                       .sheet(isPresented: $showWebView) {
                           
                           if let urlString = webViewUrl, let token = sessionToken {
                               WebView(urlString: urlString, sessionToken: token)
                           } else {
                               Text("❌ webViewUrl or sessionToken is nil")
                           }
                       }
                        
                        // Display the Retrieved Session Token
                        if let token = sessionToken, !token.isEmpty {
                            Text("Session Token: \(token)")
                                .font(.subheadline)
                                .foregroundColor(.gray)
                                .padding(.top, 5)
                                .lineLimit(1)
                                .truncationMode(.middle) // Avoids UI breaking with long tokens
                        }
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

   
    func login() {

        let credentialsManager = CredentialsManager(
            authentication: Auth0.authentication())

        let crend2Manger = CredentialsManager(
            authentication: Auth0.authentication())

        Auth0
            .webAuth()
            .audience("https://nelson.api.com")
            .scope("openid profile email offline_access")
            //            .provider(WebAuthentication.safariProvider())
            .start { result in
                switch result {
                case .success(let credentials):
                    self.user = User(from: credentials.idToken)
                    self.idToken = credentials.idToken  // Store the ID token
                    self.apiResponse1 = credentials.accessToken
                    print("Refresh token: \(credentials.refreshToken ?? "")")
                    let _ = credentialsManager.store(credentials: credentials)

                case .failure(let error):
                    print("Failed with: \(error)")
                }
            }
    }

    func logout() {

        let credentialsManager = CredentialsManager(
            authentication: Auth0.authentication())

        Auth0
            .webAuth()
            .clearSession { result in
                switch result {
                case .success:
                    self.user = nil
                    self.idToken = ""  // Clear the ID token
                    credentialsManager.clear()  // Clear stored credentials
                    print("Logged out and cleared credentials.")
                case .failure(let error):
                    print("Failed with: \(error)")
                }
            }
    }

  
}

// WebView Component to handle displaying a webpage with cookies
struct WebView: UIViewRepresentable {
    let urlString: String
    let sessionToken: String?  // Inject session token from outside

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()

        // Inject cookie before loading the URL
        if let sessionToken = sessionToken {
            let cookie = HTTPCookie(properties: [
                    .domain: "testing.test-aws-thick-panther-1344.auth0c.com",
                    .path: "/",
                    .name: "session_token",
                    .value: sessionToken,
                    .secure: true,
                    .expires: Date(timeIntervalSinceNow: 3600),
                ])

            print("Cookies to inject", cookie)

            if let cookie = cookie {
                webView.configuration.websiteDataStore.httpCookieStore
                    .setCookie(cookie)
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

    func makeUIViewController(
        context: UIViewControllerRepresentableContext<SafariView>
    ) -> SFSafariViewController {
        return SFSafariViewController(url: url)
    }

    func updateUIViewController(
        _ uiViewController: SFSafariViewController,
        context: UIViewControllerRepresentableContext<SafariView>
    ) {
        // Nothing to update here
    }
}

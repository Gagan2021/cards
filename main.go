package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"image"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fogleman/gg"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

func init() {
	// Load environment variables first
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, environment variables will be used")
	}

	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Now read the secret key after loading .env
	secretKeyStr := strings.TrimSpace(os.Getenv("SECRET_KEY"))
	log.Printf("SECRET_KEY is '%s' (length: %d)", secretKeyStr, len(secretKeyStr))
}

var (
	redisClient *redis.Client
	ctx         = context.Background()
	fbMatcher   *IPMatcher // Added Facebook IP matcher

	loginAttempts   = make(map[string]*loginAttempt)
	loginAttemptsMu sync.Mutex
)

// ----- New Handlers for Telegram Bot Integration & Admin Panel -----

// Global storage for allowed Telegram ChatIDs (in production persist these securely)
var (
	allowedChatIDs   = make(map[string]bool)
	allowedChatIDsMu sync.Mutex
)

type loginAttempt struct {
	Count       int
	LastAttempt time.Time
}

const (
	loginAttemptWindow = 1 * time.Minute
	maxLoginAttempts   = 5
)

// ----------------------------------
// Existing types and functions...
// ----------------------------------

// Updated types to support both IPv4 and IPv6.
type CIDRBlock struct {
	network net.IP // already masked IP
	maskLen int    // mask length
	isIPv4  bool   // true if IPv4, false if IPv6
}

type IPMatcher struct {
	cidrs []CIDRBlock
}

// NewMatcher creates a new IP matcher from a list of CIDR strings.
func NewMatcher(cidrList []string) *IPMatcher {
	m := &IPMatcher{}
	for _, cidr := range cidrList {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Error parsing CIDR %s: %v", cidr, err)
			continue
		}
		ones, bits := ipNet.Mask.Size()
		isIPv4 := bits == 32
		// Store the network IP masked with the provided mask.
		m.cidrs = append(m.cidrs, CIDRBlock{
			network: ip.Mask(ipNet.Mask),
			maskLen: ones,
			isIPv4:  isIPv4,
		})
	}
	return m
}

// Match checks if a given IP (IPv4 or IPv6) belongs to any of the CIDRs.
func (m *IPMatcher) Match(ipStr string) bool {
	// If the header contains a list (comma-separated), take the first value.
	parts := strings.Split(ipStr, ",")
	ipStr = strings.TrimSpace(parts[0])

	// Use net.SplitHostPort for cases where the IP might be in "[IPv6]:port" format.
	if strings.HasPrefix(ipStr, "[") {
		host, _, err := net.SplitHostPort(ipStr)
		if err == nil {
			ipStr = host
		}
	} else if strings.Count(ipStr, ".") == 3 && strings.Contains(ipStr, ":") {
		// Likely IPv4 with port, so split on colon.
		ipStr = strings.Split(ipStr, ":")[0]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range m.cidrs {
		if block.isIPv4 {
			if ip.To4() != nil && ip.Mask(net.CIDRMask(block.maskLen, 32)).Equal(block.network) {
				return true
			}
		} else {
			if ip.To16() != nil && ip.Mask(net.CIDRMask(block.maskLen, 128)).Equal(block.network) {
				return true
			}
		}
	}
	return false
}

// Facebook CIDRs
var facebookCIDRs = []string{
	"31.13.24.0/21", "31.13.64.0/18", "31.13.88.0/21", "31.13.96.0/19",
	"31.13.128.0/17", "45.64.40.0/22", "66.220.0.0/16", "69.63.176.0/20",
	"69.171.0.0/16", "74.119.76.0/22", "102.132.96.0/20", "103.4.96.0/22",
	"129.134.0.0/16", "157.240.0.0/16", "173.252.64.0/18", "173.252.88.0/21",
	"173.252.96.0/19", "173.252.128.0/17", "179.60.192.0/22", "185.60.216.0/22",
	"185.89.216.0/22", "204.15.20.0/22", "209.237.244.0/23", "209.237.246.0/23",
	"209.237.248.0/23", "209.237.250.0/23", "131.108.0.0/22", "162.125.0.0/22",
	"199.201.64.0/22",
	// New IPv6 blocks:
	"2a03:2880::/29", "2620:0:1c00::/40", "2401:db00::/32",
}

// Initialize random with a seed
func init() {
	rand.Seed(time.Now().UnixNano())
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, environment variables will be used")
	}
}

// Characters for short URL generation
const shortURLChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate a random short code
func generateShortCode(length int) string {
	code := make([]byte, length)
	for i := range code {
		code[i] = shortURLChars[rand.Intn(len(shortURLChars))]
	}
	return string(code)
}

// Create a short URL for a long URL
func createShortURL(longURL string) (string, error) {
	shortCode, err := redisClient.Get(ctx, "url:"+longURL).Result()
	if err == nil && shortCode != "" {
		return shortCode, nil
	}

	shortCode = generateShortCode(6)
	exists, err := redisClient.Exists(ctx, "short:"+shortCode).Result()
	if err != nil {
		return "", fmt.Errorf("redis error: %v", err)
	}

	for exists > 0 {
		shortCode = generateShortCode(6)
		exists, err = redisClient.Exists(ctx, "short:"+shortCode).Result()
		if err != nil {
			return "", fmt.Errorf("redis error: %v", err)
		}
	}

	pipe := redisClient.Pipeline()
	pipe.Set(ctx, "short:"+shortCode, longURL, 30*24*time.Hour)
	pipe.Set(ctx, "url:"+longURL, shortCode, 30*24*time.Hour)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to save short URL: %v", err)
	}

	return shortCode, nil
}

// ----------------------------
// New Authentication Functions
// ----------------------------

// Simple login credentials
const validUsername = "adminHUBE"
const validPassword = "AchaaAdminHaiTu@1122"

// Render login page form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// If already logged-in, redirect to dashboard
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == "authenticated" {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - realadlabs.in</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 50px; }
        form { max-width: 300px; margin: auto; padding: 20px; background: #fff; border-radius: 4px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background: #3498db; color: #fff; border: 0; }
    </style>
</head>
<body>
    <h2 style="text-align:center;">Login</h2>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, html)
		return
	}

	// POST: process login with rate limiting
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	ip := getClientIP(r)
	loginAttemptsMu.Lock()
	attempt, exists := loginAttempts[ip]
	if !exists || time.Since(attempt.LastAttempt) > loginAttemptWindow {
		attempt = &loginAttempt{Count: 0, LastAttempt: time.Now()}
		loginAttempts[ip] = attempt
	}
	attempt.LastAttempt = time.Now()
	if attempt.Count >= maxLoginAttempts {
		loginAttemptsMu.Unlock()
		http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}
	attempt.Count++
	loginAttemptsMu.Unlock()

	username := r.FormValue("username")
	password := r.FormValue("password")
	if subtle.ConstantTimeCompare([]byte(username), []byte(validUsername)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(validPassword)) == 1 {
		// Successful login: reset rate limit for this IP
		loginAttemptsMu.Lock()
		delete(loginAttempts, ip)
		loginAttemptsMu.Unlock()
		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session",
			Value:   "authenticated",
			Expires: time.Now().Add(1 * time.Hour),
			Path:    "/",
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// Protected dashboard handler with the social card form
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value != "authenticated" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - realadlabs.in</title>
    <style>
        body { font-family: Arial, sans-serif; background: #fdfdfd; padding: 20px; max-width: 800px; margin: auto; color: #333; }
        h1 { text-align: center; color: #2c3e50; }
        form { margin-top: 30px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 15px; background-color: #3498db; border: none; border-radius: 4px; color: #fff; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #2980b9; }
        .logout { text-align: right; margin-top: -10px; }
        .logout a { color: #e74c3c; text-decoration: none; font-weight: bold; }
        .logout a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="logout"><a href="/logout">Logout</a></div>
    <h1>Dashboard</h1>
    <p>Welcome! Use the form below to create your social media card securely.</p>
    <form method="POST" action="/create-card">
        <div class="form-group">
            <label for="siteUrl">Site URL <span style="color:#e74c3c;">*</span></label>
            <input type="text" id="siteUrl" name="siteUrl" placeholder="https://example.com" required>
        </div>
        <div class="form-group">
            <label for="imageUrl">Image URL <span style="color:#e74c3c;">*</span></label>
            <input type="text" id="imageUrl" name="imageUrl" placeholder="https://example.com/image.jpg" required>
        </div>
        <div class="form-group">
            <label for="title">Title (Optional)</label>
            <input type="text" id="title" name="title" placeholder="Your title here">
        </div>
        <div class="form-group">
            <label for="displayUrl">Display URL (Optional)</label>
            <input type="text" id="displayUrl" name="displayUrl" placeholder="https://display-url.com">
        </div>
        <div class="form-group" style="text-align:center;">
            <button type="submit">Create Card</button>
        </div>
    </form>
    <p style="text-align:center;"><a href="/">Back to Home</a></p>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// SEO-optimized landing page handler
func landingPageHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="keywords" content="social media card generator, shortlink generator, attach link with image, clickable image, smart redirection">
    <meta name="description" content="Discover a revolutionary platform that enhances your online engagement with seamless social media card creation and shortlink generation at realadlabs.in.">
    <meta name="author" content="realadlabs.in">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>realadlabs.in – Enhance Your Social Presence</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fafafa; padding: 20px; }
        .container { max-width: 800px; margin: auto; text-align: center; }
        h1 { color: #2c3e50; font-size: 2.5rem; }
        h2 { color: #34495e; }
        p { color: #555; line-height: 1.6; }
        a { color: #3498db; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .features { margin-top: 30px; text-align: left; }
        .features li { margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>realadlabs.in</h1>
        <p>Experience a cutting‑edge online tool that helps you create visually engaging social media cards and streamlined shortlinks. Our platform harnesses advanced redirection and media attachment technology—all while keeping the intricate processes completely hidden.</p>
        <ul class="features">
            <li>Optimized social media previews</li>
            <li>Smart shortlink generation for effortless sharing</li>
            <li>Seamless integration with your website’s content</li>
            <li>High performance and secure processing</li>
        </ul>
        <p><a href="/login">Login to Get Started</a></p>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// --- Global Statistics for redirections ---
type LinkStats struct {
	FacebookBots                int
	FacebookIPHits              int
	RealHumanHits               int
	TotalDisplayURLRedirections int
	TotalSiteURLRedirections    int
}

var (
	stats   = &LinkStats{}
	statsMu sync.Mutex
)

// ----------------------------------
// Existing Server Functions (unchanged)
// ----------------------------------

func getClientIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func isBotOrEmulated(userAgent string) bool {
	fbAppIdentifiers := []string{"FBAV", "FBAN", "FB_IAB", "FBIOS", "Instagram", "messenger"}
	userAgent = strings.ToLower(userAgent)
	for _, fbApp := range fbAppIdentifiers {
		if strings.Contains(userAgent, strings.ToLower(fbApp)) {
			return false
		}
	}
	botAgents := []string{"facebookexternalhit", "metainspector", "twitterbot"}
	for _, bot := range botAgents {
		if strings.Contains(userAgent, strings.ToLower(bot)) {
			return true
		}
	}
	return false
}

func isFacebookIP(ip string) bool {
	return fbMatcher.Match(ip)
}

func generateHash(siteUrl, imageUrl, title, displayUrl string) string {
	data := siteUrl + imageUrl + title + displayUrl
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

func generateCard(siteUrl, imageUrl, title, displayUrl string) (string, error) {
	hash := generateHash(siteUrl, imageUrl, title, displayUrl)
	filename := filepath.Join("cards", hash+".png")
	if redisClient != nil {
		cachedPath, err := redisClient.Get(ctx, hash).Result()
		if err == nil && cachedPath != "" {
			if _, err := os.Stat(cachedPath); err == nil {
				return cachedPath, nil
			}
		}
	}
	if _, err := os.Stat(filename); err == nil {
		if redisClient != nil {
			redisClient.Set(ctx, hash, filename, 24*time.Hour)
		}
		return filename, nil
	}
	resp, err := http.Get(imageUrl)
	if err != nil {
		return "", fmt.Errorf("image fetch nahi hua: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("image fetch failed with status: %s", resp.Status)
	}
	img, _, err := image.Decode(resp.Body)
	if err != nil {
		return "", fmt.Errorf("image decode error: %v", err)
	}
	bounds := img.Bounds()
	origWidth := float64(bounds.Dx())
	origHeight := float64(bounds.Dy())
	maxWidth := 1200.0
	maxHeight := 630.0
	var newWidth, newHeight float64
	ratio := origWidth / origHeight
	if ratio > (maxWidth / maxHeight) {
		newWidth = maxWidth
		newHeight = maxWidth / ratio
	} else {
		newHeight = maxHeight
		newWidth = maxHeight * ratio
	}
	dc := gg.NewContext(int(newWidth), int(newHeight))
	dc.SetRGB(0.94, 0.94, 0.94)
	dc.Clear()
	dc.DrawImage(img, 0, 0)
	if title != "" {
		dc.SetRGB(0.2, 0.2, 0.2)
		// Commented out custom font loading; using default font
		// fontPath := filepath.Join("fonts", "arial.ttf")
		// if err := dc.LoadFontFace(fontPath, 40); err != nil {
		// 	log.Printf("Warning: Cannot load font (%s). Using default font. Error: %v", fontPath, err)
		// }
		dc.DrawStringAnchored(title, newWidth/2, origHeight+50, 0.5, 0.5)
	}
	dc.SetRGB(0.4, 0.4, 0.4)
	// Commented out custom font loading; using default font
	// fontPath = filepath.Join("fonts", "arial.ttf")
	// if err := dc.LoadFontFace(fontPath, 30); err != nil {
	// 	log.Printf("Warning: Cannot load font (%s). Using default font. Error: %v", fontPath, err)
	// }
	urlToDisplay := displayUrl
	if urlToDisplay == "" {
		urlToDisplay = siteUrl
	}
	dc.DrawStringAnchored(urlToDisplay, newWidth/2, newHeight-50, 0.5, 0.5)
	if err := dc.SavePNG(filename); err != nil {
		return "", fmt.Errorf("image save nahi hua: %v", err)
	}
	if redisClient != nil {
		err := redisClient.Set(ctx, hash, filename, 24*time.Hour).Err()
		if err != nil {
			log.Printf("Redis cache set failed: %v", err)
		}
	}
	return filename, nil
}

func isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func generateCardHandler(w http.ResponseWriter, r *http.Request) {
	encryptedData := r.URL.Query().Get("data")
	if encryptedData == "" {
		http.Error(w, "Missing data parameter", http.StatusBadRequest)
		return
	}
	secretKeyStr := strings.TrimSpace(os.Getenv("SECRET_KEY"))
	log.Printf("In generateCardHandler, SECRET_KEY is '%s' (length: %d)", secretKeyStr, len(secretKeyStr))
	if len(secretKeyStr) != 16 && len(secretKeyStr) != 24 && len(secretKeyStr) != 32 {
		http.Error(w, "Invalid encryption key configuration", http.StatusInternalServerError)
		return
	}
	decryptedJSON, err := Decrypt(encryptedData, []byte(secretKeyStr))
	if err != nil {
		http.Error(w, "Error decrypting data", http.StatusInternalServerError)
		return
	}
	var params CardParams
	err = json.Unmarshal([]byte(decryptedJSON), &params)
	if err != nil {
		http.Error(w, "Failed to parse decrypted parameters", http.StatusInternalServerError)
		return
	}

	// Generate the card image
	filename, err := generateCard(params.SiteUrl, params.ImageUrl, params.Title, params.DisplayUrl)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating card: %v", err), http.StatusInternalServerError)
		return
	}

	// Construct the URL for the generated image
	imagePath := "/cards/" + filepath.Base(filename)

	// Render an HTML page that displays the card image
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Social Media Card</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f9f9f9; text-align: center; padding: 20px; }
        .card-img { max-width: 100%%; height: auto; border: 1px solid #ddd; padding: 10px; background: #fff; }
    </style>
</head>
<body>
    <h1>Your Social Media Card</h1>
    <img class="card-img" src="%s" alt="Social Media Card">
</body>
</html>`, imagePath)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// In shortURLHandler, instead of simply redirecting to the stored longURL,
// check if a final display URL is stored and if the requester is a bot.
func shortURLHandler(w http.ResponseWriter, r *http.Request) {
	shortCode := strings.TrimPrefix(r.URL.Path, "/s/")
	if shortCode == "" {
		http.Error(w, "Short code is required", http.StatusBadRequest)
		return
	}
	storedURL, err := redisClient.Get(ctx, "short:"+shortCode).Result()
	if err == redis.Nil {
		http.Error(w, "Short URL not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("Redis error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse the stored URL.
	parsedURL, err := url.Parse(storedURL)
	if err != nil {
		http.Error(w, "Internal error parsing stored URL", http.StatusInternalServerError)
		return
	}

	// The stored URL must have a "data" parameter.
	encryptedData := parsedURL.Query().Get("data")
	if encryptedData == "" {
		http.Error(w, "Missing encrypted data", http.StatusInternalServerError)
		return
	}

	// Decrypt the data to retrieve card parameters.
	secretKeyStr := strings.TrimSpace(os.Getenv("SECRET_KEY"))
	if len(secretKeyStr) != 16 && len(secretKeyStr) != 24 && len(secretKeyStr) != 32 {
		http.Error(w, "Invalid encryption key configuration", http.StatusInternalServerError)
		return
	}
	decryptedJSON, err := Decrypt(encryptedData, []byte(secretKeyStr))
	if err != nil {
		http.Error(w, "Error decrypting data", http.StatusInternalServerError)
		return
	}
	var params CardParams
	err = json.Unmarshal([]byte(decryptedJSON), &params)
	if err != nil {
		http.Error(w, "Failed to parse decrypted parameters", http.StatusInternalServerError)
		return
	}

	// Decide final redirection based on both user-agent and client IP.
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	clientIP := getClientIP(r)
	var finalRedirect string

	statsMu.Lock()
	// If user agent indicates a bot OR the client IP is from Facebook, then redirect to displayUrl (if available).
	if (isBotOrEmulated(userAgent) || isFacebookIP(clientIP)) && params.DisplayUrl != "" {
		// Record separate stats if needed.
		if isBotOrEmulated(userAgent) {
			stats.FacebookBots++
		}
		if isFacebookIP(clientIP) {
			stats.FacebookIPHits++
		}
		stats.TotalDisplayURLRedirections++
		finalRedirect = params.DisplayUrl
	} else if params.SiteUrl != "" {
		stats.RealHumanHits++
		stats.TotalSiteURLRedirections++
		finalRedirect = params.SiteUrl
	} else {
		// Fallback to /generate-card if neither provided.
		finalRedirect = "http://" + r.Host + "/generate-card?" + parsedURL.RawQuery
	}
	statsMu.Unlock()

	log.Printf("Redirecting to final URL: %s (clientIP: %s, userAgent: %s)", finalRedirect, clientIP, userAgent)
	http.Redirect(w, r, finalRedirect, http.StatusFound)
}

func shortenURLHandler(w http.ResponseWriter, r *http.Request) {
	longURL := r.URL.Query().Get("url")
	if longURL == "" {
		http.Error(w, "URL parameter is required", http.StatusBadRequest)
		return
	}
	if redisClient == nil {
		http.Error(w, "URL shortening service is unavailable", http.StatusServiceUnavailable)
		return
	}
	shortCode, err := createShortURL(longURL)
	if err != nil {
		log.Printf("Error creating short URL: %v", err)
		http.Error(w, "Failed to create short URL", http.StatusInternalServerError)
		return
	}
	// Use the configured domain name: realadlabs.in
	host := "realadlabs.in"
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	shortURL := fmt.Sprintf("%s://%s/s/%s", scheme, host, shortCode)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"short_url": "%s"}`, shortURL)
}

func createRequiredDirectories() {
	dirs := []string{"cards", "fonts"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("%s directory create nahi hua: %v", dir, err)
		}
	}
	fontPath := filepath.Join("fonts", "arial.ttf")
	if _, err := os.Stat(fontPath); os.IsNotExist(err) {
		log.Printf("Warning: Font file %s not found. Please add this file for proper text rendering.", fontPath)
	}
}

func setupRedis() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "redis:6379"
	}
	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Printf("Warning: Redis connection failed: %v. Continuing without Redis caching.", err)
	} else {
		log.Println("Redis connection successful")
	}
}

func main() {
	// Initialize Facebook IP matcher, create directories, setup Redis, etc.
	fbMatcher = NewMatcher(facebookCIDRs)
	createRequiredDirectories()
	setupRedis()

	// Start the Telegram Bot in a separate goroutine
	go startTelegramBot()

	// Existing HTTP routes registration
	http.HandleFunc("/", landingPageHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/create-card", createCardHandler)
	http.HandleFunc("/generate-card", generateCardHandler)
	http.HandleFunc("/preview", previewHandler)
	http.HandleFunc("/s/", shortURLHandler)
	http.HandleFunc("/shorten", shortenURLHandler)
	http.Handle("/fonts/", http.StripPrefix("/fonts/", http.FileServer(http.Dir("fonts"))))
	http.Handle("/cards/", http.StripPrefix("/cards/", http.FileServer(http.Dir("cards"))))
	http.HandleFunc("/logout", logoutHandler)

	// New routes for Telegram bot integration & admin panel
	http.HandleFunc("/admin", adminPanelHandler)
	http.HandleFunc("/admin/add", adminAddHandler)
	// Bot panel route: users access via /bot?chat_id=YOUR_CHAT_ID
	http.HandleFunc("/bot", botPanelHandler)
	// Dummy bot option handlers
	http.HandleFunc("/bot/create-link", botCreateLinkHandler)
	http.HandleFunc("/bot/manage-link", botManageLinkHandler)
	http.HandleFunc("/bot/link-stats", botLinkStatsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Server chal raha hai http://localhost:" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// New handler to process card creation securely in the backend
func createCardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	siteUrl := r.FormValue("siteUrl")
	imageUrl := r.FormValue("imageUrl")
	title := r.FormValue("title")
	displayUrl := r.FormValue("displayUrl")
	// Validate essential URLs
	if siteUrl == "" || imageUrl == "" || !isValidURL(siteUrl) || !isValidURL(imageUrl) || (displayUrl != "" && !isValidURL(displayUrl)) {
		http.Error(w, "Invalid input – ensure required URLs are correct", http.StatusBadRequest)
		return
	}

	// Generate the card; the process remains secure on the server
	filename, err := generateCard(siteUrl, imageUrl, title, displayUrl)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating card: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare the card parameters
	params := CardParams{
		SiteUrl:    siteUrl,
		ImageUrl:   imageUrl,
		Title:      title,
		DisplayUrl: displayUrl,
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Get your secret key from an environment variable (it must be 16, 24, or 32 bytes)
	secretKeyStr := os.Getenv("SECRET_KEY")
	if len(secretKeyStr) != 16 && len(secretKeyStr) != 24 && len(secretKeyStr) != 32 {
		http.Error(w, "Invalid encryption key configuration", http.StatusInternalServerError)
		return
	}
	encryptedData, err := Encrypt(string(paramsJSON), []byte(secretKeyStr))
	if err != nil {
		http.Error(w, "Error encrypting data", http.StatusInternalServerError)
		return
	}

	baseURL := "http://" + r.Host
	// Instead of appending plaintext query parameters, we now send them as
	// a single "data" parameter.
	cardUrl := fmt.Sprintf("%s/generate-card?data=%s", baseURL, url.QueryEscape(encryptedData))
	shortCode, err := createShortURL(cardUrl)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating short URL: %v", err), http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	shortURL := fmt.Sprintf("%s://%s/s/%s", scheme, "realadlabs.in", shortCode)

	// Render a results page without exposing any processing logic
	resultHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Card Generated - realadlabs.in</title>
    <style>
       body { font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; text-align: center; }
       .card-img { max-width: 100%%; height: auto; border: 1px solid #ddd; padding: 10px; background: #fff; }
       a { color: #3498db; text-decoration: none; }
       a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Your Card is Ready</h1>
    <div>
       <img class="card-img" src="/cards/%s" alt="Social Media Card">
    </div>
    <p>Share this URL: <a href="%s">%s</a></p>
    <p><a href="/dashboard">Create another card</a></p>
</body>
</html>`, filepath.Base(filename), shortURL, shortURL)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, resultHTML)
}

// New logoutHandler to clear session cookie and redirect to landing page.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:    "session",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// adminPanelHandler shows a form so that authenticated admin can add a Telegram ChatID.
func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	// Require authentication
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value != "authenticated" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - realadlabs.in</title>
    <style>
        body { font-family: Arial, sans-serif; background: #fdfdfd; padding: 20px; max-width: 800px; margin: auto; color: #333; }
        h1 { text-align: center; }
        form { max-width: 400px; margin: auto; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 15px; background: #3498db; color: #fff; border: 0; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .logout { text-align: right; margin-bottom: 10px; }
        .logout a { color: #e74c3c; text-decoration: none; font-weight: bold; }
        .logout a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="logout"><a href="/logout">Logout</a></div>
    <h1>Admin Panel</h1>
    <p>Add a Telegram ChatID to grant bot access:</p>
    <form method="POST" action="/admin/add">
        <input type="text" name="chat_id" placeholder="Telegram ChatID" required>
        <button type="submit">Add ChatID</button>
    </form>
    <hr>
    <h3>Currently Allowed ChatIDs:</h3>
    <ul>`
	allowedChatIDsMu.Lock()
	for id := range allowedChatIDs {
		html += "<li>" + id + "</li>"
	}
	allowedChatIDsMu.Unlock()
	html += `</ul>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// adminAddHandler processes the form submission to add a new allowed Telegram ChatID.
func adminAddHandler(w http.ResponseWriter, r *http.Request) {
	// Require authentication
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value != "authenticated" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	chatID := r.FormValue("chat_id")
	if chatID == "" {
		http.Error(w, "ChatID required", http.StatusBadRequest)
		return
	}
	allowedChatIDsMu.Lock()
	allowedChatIDs[chatID] = true
	allowedChatIDsMu.Unlock()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// botPanelHandler provides a dedicated panel with options for Telegram bot–enabled users.
// The bot (using your BOT_TOKEN stored in an environment variable) can simply pass the user ChatID (as query parameter).
func botPanelHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		http.Error(w, "chat_id query parameter required", http.StatusBadRequest)
		return
	}
	allowedChatIDsMu.Lock()
	allowed := allowedChatIDs[chatID]
	allowedChatIDsMu.Unlock()
	if !allowed {
		http.Error(w, "Access denied. Please contact admin.", http.StatusForbidden)
		return
	}
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bot Panel - realadlabs.in</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; max-width: 800px; margin: auto; color: #333; }
        h1 { text-align: center; }
        ul { list-style: none; padding: 0; }
        ul li { background: #fff; margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        a { text-decoration: none; color: #3498db; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Telegram Bot Panel</h1>
    <p>Welcome! Use the options below:</p>
    <ul>
        <li><a href="/bot/create-link?chat_id=` + chatID + `">Create Link</a></li>
        <li><a href="/bot/manage-link?chat_id=` + chatID + `">Manage Link</a></li>
        <li><a href="/bot/link-stats?chat_id=` + chatID + `">Link Stats</a></li>
    </ul>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// Dummy bot panel handlers (to be enhanced as needed)
func botCreateLinkHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	fmt.Fprintf(w, "Here you will be able to create a link. (chat_id: %s)", chatID)
}

func botManageLinkHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	fmt.Fprintf(w, "Here you will be able to manage your links. (chat_id: %s)", chatID)
}

func botLinkStatsHandler(w http.ResponseWriter, r *http.Request) {
	// chatID := r.URL.Query().Get("chat_id")
	// Build a simple table as a text message
	statsMu.Lock()
	table := fmt.Sprintf(`Link Redirection Statistics:
---------------------------------------
Facebook Bots Hit:                %d
Facebook IP Hits:                 %d
Real Human Hits:                  %d
Total DisplayURL Redirections:    %d
Total SiteURL Redirections:       %d
---------------------------------------`,
		stats.FacebookBots,
		stats.FacebookIPHits,
		stats.RealHumanHits,
		stats.TotalDisplayURLRedirections,
		stats.TotalSiteURLRedirections)
	statsMu.Unlock()

	// Instead of redirecting, just return the stats text in the response.
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", table)
}

func previewHandler(w http.ResponseWriter, r *http.Request) {
	// You can later implement preview logic here if needed.
	fmt.Fprintln(w, "Preview not implemented.")
}

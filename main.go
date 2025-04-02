package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultPort      = "443"
	defaultRedisAddr = "redis:6379"
	recordTTL        = 30 * time.Minute
	certDir          = "/app/certs"
	userPrefix       = "user:" // Prefix for user keys in Redis
)

type BeaconServer struct {
	redisClient *redis.Client
}

type BeaconRequest struct {
	DeviceID string `json:"device_id"`
	LocalIP  string `json:"local_ip"`
}

type LookupResponse struct {
	DeviceID  string `json:"device_id"`
	LocalIP   string `json:"local_ip"`
	ExpiresIn int64  `json:"expires_in"`
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AddUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	AdminKey string `json:"admin_key"` // Simple admin key for adding users
}

func NewBeaconServer(redisAddr, redisPassword string) (*BeaconServer, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPassword,
		DB:           0,
		PoolSize:     100,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})

	// Retry connection with backoff
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if _, err := client.Ping(ctx).Result(); err == nil {
			return &BeaconServer{redisClient: client}, nil
		}

		log.Printf("Redis connection attempt %d/5 failed", i+1)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to Redis after 5 attempts")
}

func (s *BeaconServer) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BeaconRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" || req.LocalIP == "" {
		http.Error(w, "Both device_id and local_ip are required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("device:%s", req.DeviceID)

	err := s.redisClient.Set(ctx, key, req.LocalIP, recordTTL).Err()
	if err != nil {
		log.Printf("Failed to set Redis key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Beacon updated for device %s", req.DeviceID)
}

func (s *BeaconServer) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		http.Error(w, "device_id parameter is required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("device:%s", deviceID)

	pipe := s.redisClient.Pipeline()
	getCmd := pipe.Get(ctx, key)
	ttlCmd := pipe.TTL(ctx, key)
	_, err := pipe.Exec(ctx)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			http.Error(w, "Device not found", http.StatusNotFound)
			return
		}
		log.Printf("Redis error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	localIP, err := getCmd.Result()
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	expiresIn := ttlCmd.Val().Milliseconds() / 1000

	response := LookupResponse{
		DeviceID:  deviceID,
		LocalIP:   localIP,
		ExpiresIn: expiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *BeaconServer) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Both username and password are required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	userKey := fmt.Sprintf("%s%s", userPrefix, creds.Username)

	storedPassword, err := s.redisClient.Get(ctx, userKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		} else {
			log.Printf("Redis error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if storedPassword != creds.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Authentication successful",
	})
}

func (s *BeaconServer) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AddUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Both username and password are required", http.StatusBadRequest)
		return
	}

	// Simple admin key check (in production, use proper authentication)
	if req.AdminKey != os.Getenv("ADMIN_KEY") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	userKey := fmt.Sprintf("%s%s", userPrefix, req.Username)

	// Check if user already exists
	exists, err := s.redisClient.Exists(ctx, userKey).Result()
	if err != nil {
		log.Printf("Redis error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Add new user
	err = s.redisClient.Set(ctx, userKey, req.Password, 0).Err() // 0 means no expiration
	if err != nil {
		log.Printf("Failed to set user in Redis: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "User added successfully",
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func loadTLSCertificates() (tls.Certificate, error) {
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = certDir + "/fullchain.pem"
	}

	keyFile := os.Getenv("TLS_KEY_FILE")
	if keyFile == "" {
		keyFile = certDir + "/privkey.pem"
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS certificates: %w", err)
	}
	return cert, nil
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func startRedirectServer() {
	redirectServer := &http.Server{
		Addr:         ":80",
		Handler:      http.HandlerFunc(redirectToHTTPS),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("Starting HTTP redirect server on :80")
	if err := redirectServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("HTTP redirect server error: %v", err)
	}
}

func main() {
	// Configure Redis connection
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = defaultRedisAddr
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	// Initialize Redis connection with retries
	var server *BeaconServer
	var err error
	for i := 0; i < 5; i++ {
		server, err = NewBeaconServer(redisAddr, redisPassword)
		if err == nil {
			break
		}
		log.Printf("Waiting for Redis... Attempt %d/5: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	if err != nil {
		log.Fatalf("Could not connect to Redis after 5 attempts: %v", err)
	}

	// Load TLS certificates
	cert, err := loadTLSCertificates()
	if err != nil {
		log.Fatalf("TLS certificate error: %v", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Set up routes
	router := http.NewServeMux()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Beacon server is Up and Running... 🚀")
	})
	router.HandleFunc("/beacon", server.handleBeacon)
	router.HandleFunc("/lookup", server.handleLookup)
	router.HandleFunc("/api/auth", server.handleAuthenticate)
	router.HandleFunc("/api/users", server.handleAddUser)

	// Configure HTTP server
	httpServer := &http.Server{
		Addr:         ":" + defaultPort,
		Handler:      securityHeaders(router),
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP redirect server
	go startRedirectServer()

	log.Printf("Starting HTTPS server on :%s", defaultPort)
	if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}
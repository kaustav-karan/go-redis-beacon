package main

import (
	"context"
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
	defaultPort     = "8080"
	defaultRedisAddr = "localhost:6379"
	recordTTL       = 30 * time.Minute
)

type BeaconServer struct {
	redisClient *redis.Client
}

type BeaconRequest struct {
	DeviceID string `json:"device_id"`
	LocalIP  string `json:"local_ip"`
}

type LookupResponse struct {
	DeviceID string `json:"device_id"`
	LocalIP  string `json:"local_ip"`
	ExpiresIn int64  `json:"expires_in"`
}

func NewBeaconServer(redisAddr, redisPassword string) *BeaconServer {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword, // Use the provided password
		DB:       0,            // use default DB
		PoolSize: 100,          // connection pool size
	})

	// Verify the connection works
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Ping(ctx).Result(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	return &BeaconServer{
		redisClient: client,
	}
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

	// Set the IP with expiration (or update existing)
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

	// Pipeline the get and TTL commands for efficiency
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

	expiresIn := ttlCmd.Val().Milliseconds() / 1000 // convert to seconds

	response := LookupResponse{
		DeviceID: deviceID,
		LocalIP:  localIP,
		ExpiresIn: expiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = defaultRedisAddr
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	server := NewBeaconServer(redisAddr, redisPassword)

	// Check Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	http.HandleFunc("/beacon", server.handleBeacon)
	http.HandleFunc("/lookup", server.handleLookup)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	log.Printf("Starting beacon server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

const dbFile = "totally_not_my_privateKeys.db"

type KeyPair struct {
	Kid        int
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	ExpiresAt  time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

var db *sql.DB

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Schema matching grader expectations
	createTableSQL := `CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func serializePrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return privateKeyPEM, nil
}

func deserializePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func savePrivateKey(key *rsa.PrivateKey, expiresAt time.Time) error {
	privPEM, err := serializePrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to serialize key: %w", err)
	}

	_, err = db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		privPEM, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert key: %w", err)
	}

	return nil
}

func loadPrivateKey(expired bool) (*KeyPair, error) {
	now := time.Now().Unix()
	var query string

	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY kid LIMIT 1"
	} else {
		query = "SELECT kid, key, exp FROM keys WHERE exp >= ? ORDER BY kid LIMIT 1"
	}

	var kid int
	var keyData []byte
	var exp int64

	err := db.QueryRow(query, now).Scan(&kid, &keyData, &exp)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	privateKey, err := deserializePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key: %w", err)
	}

	return &KeyPair{
		Kid:        kid,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

func loadValidKeys() ([]*KeyPair, error) {
	now := time.Now().Unix()

	rows, err := db.Query("SELECT kid, key, exp FROM keys WHERE exp >= ?", now)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	var keys []*KeyPair
	for rows.Next() {
		var kid int
		var keyData []byte
		var exp int64

		if err := rows.Scan(&kid, &keyData, &exp); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		privateKey, err := deserializePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize key: %w", err)
		}

		keys = append(keys, &KeyPair{
			Kid:        kid,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			ExpiresAt:  time.Unix(exp, 0),
		})
	}

	return keys, nil
}

func (kp *KeyPair) toJWK() JWK {
	n := base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes())
	return JWK{
		Kty: "RSA",
		Kid: fmt.Sprintf("%d", kp.Kid),
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys, err := loadValidKeys()
	if err != nil {
		log.Printf("Error loading valid keys: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var jwks []JWK
	for _, key := range keys {
		jwks = append(jwks, key.toJWK())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: jwks})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") != ""

	keyPair, err := loadPrivateKey(expired)
	if err != nil {
		log.Printf("Error loading key (expired=%v): %v", expired, err)
		http.Error(w, "No keys available", http.StatusInternalServerError)
		return
	}

	var exp int64
	if expired {
		exp = keyPair.ExpiresAt.Unix()
	} else {
		exp = time.Now().Add(time.Hour).Unix()
	}

	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": exp,
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fmt.Sprintf("%d", keyPair.Kid)

	tokenString, err := token.SignedString(keyPair.PrivateKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func generateInitialKeys() error {
	// Check if keys already exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing keys: %w", err)
	}

	// Only generate if no keys exist
	if count > 0 {
		log.Printf("Database already contains %d key(s), skipping generation", count)
		return nil
	}

	log.Println("Generating initial keys...")

	expiredKey, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate expired key: %w", err)
	}
	if err := savePrivateKey(expiredKey, time.Now().Add(-time.Hour)); err != nil {
		return fmt.Errorf("failed to save expired key: %w", err)
	}
	log.Println("Generated expired key")

	validKey, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate valid key: %w", err)
	}
	if err := savePrivateKey(validKey, time.Now().Add(24*time.Hour)); err != nil {
		return fmt.Errorf("failed to save valid key: %w", err)
	}
	log.Println("Generated valid key")

	return nil
}

func main() {
	// Check if database file exists
	if _, err := os.Stat(dbFile); err == nil {
		log.Printf("Database file '%s' already exists", dbFile)
	}

	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	if err := generateInitialKeys(); err != nil {
		log.Fatal("Failed to generate initial keys:", err)
	}

	// Verify keys were created
	var validCount, expiredCount int
	now := time.Now().Unix()
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp >= ?", now).Scan(&validCount)
	db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp < ?", now).Scan(&expiredCount)
	log.Printf("Database contains %d valid key(s) and %d expired key(s)", validCount, expiredCount)

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

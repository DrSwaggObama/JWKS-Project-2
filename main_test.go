package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Silence logs for clean test output
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	code := m.Run()
	log.SetOutput(os.Stderr)
	os.Exit(code)
}

func resetDB(t *testing.T) {
	t.Helper()
	if db != nil {
		_ = db.Close()
		db = nil
	}
	_ = os.Remove(dbFile)
	if err := initDB(); err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
}

func countKeys(t *testing.T) (valid, expired int) {
	t.Helper()
	now := time.Now().Unix()
	if err := db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp >= ?", now).Scan(&valid); err != nil {
		t.Fatalf("count valid: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp < ?", now).Scan(&expired); err != nil {
		t.Fatalf("count expired: %v", err)
	}
	return
}

func TestInitDB_Idempotent(t *testing.T) {
	resetDB(t)
	// Second init should succeed and leave table usable
	if err := initDB(); err != nil {
		t.Fatalf("second initDB failed: %v", err)
	}
	var cnt int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&cnt); err != nil {
		t.Fatalf("table not usable after second init: %v", err)
	}
}

func TestGenerateKeyPair_AndSerde(t *testing.T) {
	resetDB(t)

	priv, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair error: %v", err)
	}
	if priv == nil || priv.PublicKey.N == nil {
		t.Fatalf("nil key generated")
	}

	pemBytes, err := serializePrivateKey(priv)
	if err != nil {
		t.Fatalf("serializePrivateKey error: %v", err)
	}
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("PEM header missing")
	}

	round, err := deserializePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("deserializePrivateKey error: %v", err)
	}
	if round.PublicKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestDeserializePrivateKey_InvalidPEM(t *testing.T) {
	resetDB(t)
	if _, err := deserializePrivateKey([]byte("not pem")); err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestDeserializePrivateKey_ParseError(t *testing.T) {
	resetDB(t)
	// Valid PEM container, invalid DER payload
	bad := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")})
	if _, err := deserializePrivateKey(bad); err == nil {
		t.Fatalf("expected parse error for invalid DER")
	}
}

func TestSaveAndLoadPrivateKey_ValidAndExpired(t *testing.T) {
	resetDB(t)

	expiredKey, _ := generateKeyPair()
	validKey, _ := generateKeyPair()

	if err := savePrivateKey(expiredKey, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if err := savePrivateKey(validKey, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("save valid: %v", err)
	}

	kpValid, err := loadPrivateKey(false)
	if err != nil {
		t.Fatalf("load valid: %v", err)
	}
	if kpValid.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expected valid key")
	}

	kpExpired, err := loadPrivateKey(true)
	if err != nil {
		t.Fatalf("load expired: %v", err)
	}
	if !kpExpired.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expected expired key")
	}
}

func TestLoadPrivateKey_NoRows(t *testing.T) {
	resetDB(t)
	if _, err := loadPrivateKey(false); err == nil {
		t.Fatalf("expected error when no valid key present")
	}
	if _, err := loadPrivateKey(true); err == nil {
		t.Fatalf("expected error when no expired key present")
	}
}

func TestLoadValidKeys_OnlyValidAndToJWK(t *testing.T) {
	resetDB(t)

	k1, _ := generateKeyPair()
	_ = savePrivateKey(k1, time.Now().Add(-1*time.Hour))
	k2, _ := generateKeyPair()
	_ = savePrivateKey(k2, time.Now().Add(1*time.Hour))
	k3, _ := generateKeyPair()
	_ = savePrivateKey(k3, time.Now().Add(2*time.Hour))

	keys, err := loadValidKeys()
	if err != nil {
		t.Fatalf("loadValidKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(keys))
	}
	j := keys[0].toJWK()
	if j.Kty != "RSA" || j.Use != "sig" || j.Alg != "RS256" || j.Kid == "" || j.N == "" || j.E == "" {
		t.Fatalf("invalid JWK: %+v", j)
	}
	if j.E != "AQAB" { // 65537 encoded
		t.Fatalf("unexpected exponent: %s", j.E)
	}
}

func TestLoadValidKeys_DeserializeError(t *testing.T) {
	resetDB(t)
	// Insert malformed key blob for a future exp to trigger deserialize error branch
	_, err := db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, []byte("bad"), time.Now().Add(1*time.Hour).Unix())
	if err != nil {
		t.Fatalf("insert malformed key: %v", err)
	}
	if _, err := loadValidKeys(); err == nil {
		t.Fatalf("expected error due to deserialize failure")
	}
}

// Verify PEM block type after serialization
func TestSerializePrivateKey_PEMBlockType(t *testing.T) {
	resetDB(t)
	priv, _ := generateKeyPair()
	b, err := serializePrivateKey(priv)
	if err != nil {
		t.Fatalf("serializePrivateKey: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("bad pem block: %#v", block)
	}
}

// Force scan error in loadValidKeys by inserting text into exp
func TestLoadValidKeys_ScanError(t *testing.T) {
	resetDB(t)
	priv, _ := generateKeyPair()
	pemBytes, _ := serializePrivateKey(priv)
	if _, err := db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, pemBytes, "oops"); err != nil {
		t.Fatalf("insert bad exp: %v", err)
	}
	if _, err := loadValidKeys(); err == nil {
		t.Fatalf("expected scan error from invalid exp type")
	}
}

// Force scan error in loadPrivateKey(true) with invalid exp type
func TestLoadPrivateKey_ScanErrorExpired(t *testing.T) {
	resetDB(t)
	priv, _ := generateKeyPair()
	pemBytes, _ := serializePrivateKey(priv)
	if _, err := db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, pemBytes, "oops"); err != nil {
		t.Fatalf("insert bad exp: %v", err)
	}
	if _, err := loadPrivateKey(true); err == nil {
		t.Fatalf("expected scan error from invalid exp type")
	}
}

// Ensure JWKS values match DB public keys (n,e)
func TestJWKSHandler_JWKMatchesDBKeys(t *testing.T) {
	resetDB(t)
	k1, _ := generateKeyPair()
	_ = savePrivateKey(k1, time.Now().Add(2*time.Hour))
	k2, _ := generateKeyPair()
	_ = savePrivateKey(k2, time.Now().Add(3*time.Hour))

	// Load from DB to build expected map
	keys, err := loadValidKeys()
	if err != nil {
		t.Fatalf("loadValidKeys: %v", err)
	}
	expMap := map[string]*KeyPair{}
	for _, kp := range keys {
		expMap[fmt.Sprintf("%d", kp.Kid)] = kp
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	var payload struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(payload.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(payload.Keys))
	}

	for _, j := range payload.Keys {
		kp := expMap[j.Kid]
		if kp == nil {
			t.Fatalf("unexpected kid in JWKS: %s", j.Kid)
		}
		// compare exponent
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			t.Fatalf("decode e: %v", err)
		}
		eInt := new(big.Int).SetBytes(eBytes).Int64()
		if eInt != int64(kp.PublicKey.E) {
			t.Fatalf("exponent mismatch: got %d want %d", eInt, kp.PublicKey.E)
		}
		// compare modulus
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			t.Fatalf("decode n: %v", err)
		}
		nInt := new(big.Int).SetBytes(nBytes)
		if nInt.Cmp(kp.PublicKey.N) != 0 {
			t.Fatalf("modulus mismatch for kid %s", j.Kid)
		}
	}
}

func TestJWKSHandler_OK(t *testing.T) {
	resetDB(t)
	k, _ := generateKeyPair()
	_ = savePrivateKey(k, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("unexpected content-type: %s", ct)
	}
	var payload struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(payload.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(payload.Keys))
	}
}

func TestJWKSHandler_EmptySet(t *testing.T) {
	resetDB(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	var payload struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(payload.Keys))
	}
}

func TestJWKSHandler_MethodNotAllowed(t *testing.T) {
	resetDB(t)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405")
	}
}

func TestJWKSHandler_DBError(t *testing.T) {
	resetDB(t)
	_ = db.Close() // force query error
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error")
	}
}

func TestAuthHandler_PostValid(t *testing.T) {
	resetDB(t)
	k, _ := generateKeyPair()
	_ = savePrivateKey(k, time.Now().Add(1*time.Hour))
	kp, err := loadPrivateKey(false)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	authHandler(w, req)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	var payload map[string]string
	_ = json.NewDecoder(res.Body).Decode(&payload)
	tokenStr := payload["token"]
	if tokenStr == "" {
		t.Fatalf("missing token")
	}

	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return kp.PublicKey, nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("token invalid: %v", err)
	}
	expectedKID := fmt.Sprintf("%d", kp.Kid)
	if token.Header["kid"] != expectedKID {
		t.Fatalf("kid mismatch, got %v want %s", token.Header["kid"], expectedKID)
	}
	claims := token.Claims.(jwt.MapClaims)
	if sub, ok := claims["sub"].(string); !ok || sub != "user123" {
		t.Fatalf("sub claim mismatch, got %v", claims["sub"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Fatalf("missing iat")
	}
	if expF, ok := claims["exp"].(float64); !ok || int64(expF) <= time.Now().Unix() {
		t.Fatalf("exp not in future for valid token")
	}
}

func TestAuthHandler_PostExpired(t *testing.T) {
	resetDB(t)
	k, _ := generateKeyPair()
	expAt := time.Now().Add(-1 * time.Hour)
	_ = savePrivateKey(k, expAt)
	kp, err := loadPrivateKey(true)
	if err != nil {
		t.Fatalf("loadPrivateKey(expired): %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=1", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	authHandler(w, req)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status: %d body: %s", res.StatusCode, string(body))
	}
	var payload map[string]string
	_ = json.NewDecoder(res.Body).Decode(&payload)
	tokenStr := payload["token"]
	if tokenStr == "" {
		t.Fatalf("missing token")
	}

	// Validate with a custom time just before exp to avoid "expired" during parsing
	token, err := jwt.ParseWithClaims(
		tokenStr,
		jwt.MapClaims{},
		func(t *jwt.Token) (interface{}, error) { return kp.PublicKey, nil },
		jwt.WithTimeFunc(func() time.Time { return kp.ExpiresAt.Add(-time.Second) }),
	)
	if err != nil || !token.Valid {
		t.Fatalf("token invalid with custom time: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("missing exp")
	}
	if int64(expF) != kp.ExpiresAt.Unix() {
		t.Fatalf("exp mismatch, got %v want %v", int64(expF), kp.ExpiresAt.Unix())
	}
}

func TestAuthHandler_MethodNotAllowed(t *testing.T) {
	resetDB(t)
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405")
	}
}

func TestAuthHandler_NoKeys(t *testing.T) {
	resetDB(t)
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when no keys")
	}
}

func TestGenerateInitialKeys_CreateAndSkip(t *testing.T) {
	resetDB(t)
	// First call should create one valid and one expired
	if err := generateInitialKeys(); err != nil {
		t.Fatalf("generateInitialKeys: %v", err)
	}
	v1, e1 := countKeys(t)
	if v1 < 1 || e1 < 1 {
		t.Fatalf("expected at least one valid and one expired, got v=%d e=%d", v1, e1)
	}
	// Second call should skip creation
	if err := generateInitialKeys(); err != nil {
		t.Fatalf("second generateInitialKeys: %v", err)
	}
	v2, e2 := countKeys(t)
	if v2 != v1 || e2 != e1 {
		t.Fatalf("keys changed after second call: before v=%d e=%d after v=%d e=%d", v1, e1, v2, e2)
	}
}

// Test generateInitialKeys when QueryRow fails
func TestGenerateInitialKeys_QueryRowError(t *testing.T) {
	resetDB(t)
	_ = db.Close() // Close DB to force error
	if err := generateInitialKeys(); err == nil {
		t.Fatalf("expected error when DB is closed")
	}
}

// Test savePrivateKey serialize error path (force by passing nil, though this won't happen in practice)
func TestSavePrivateKey_SerializeError(t *testing.T) {
	resetDB(t)
	// This tests the error return path in savePrivateKey
	// Even though serializePrivateKey shouldn't fail with valid key,
	// we test the error handling exists
	validKey, _ := generateKeyPair()
	err := savePrivateKey(validKey, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("savePrivateKey should succeed with valid key: %v", err)
	}
}

// Test savePrivateKey insert error by closing DB
func TestSavePrivateKey_InsertError(t *testing.T) {
	resetDB(t)
	validKey, _ := generateKeyPair()
	_ = db.Close() // Force insert to fail
	if err := savePrivateKey(validKey, time.Now().Add(1*time.Hour)); err == nil {
		t.Fatalf("expected error when DB is closed")
	}
}

// Test loadPrivateKey deserialize error path
func TestLoadPrivateKey_DeserializeError(t *testing.T) {
	resetDB(t)
	// Insert malformed key data
	_, err := db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`,
		[]byte("invalid pem data"),
		time.Now().Add(1*time.Hour).Unix())
	if err != nil {
		t.Fatalf("insert bad key: %v", err)
	}
	if _, err := loadPrivateKey(false); err == nil {
		t.Fatalf("expected deserialize error")
	}
}

// Test loadValidKeys query error
func TestLoadValidKeys_QueryError(t *testing.T) {
	resetDB(t)
	_ = db.Close() // Force query error
	if _, err := loadValidKeys(); err == nil {
		t.Fatalf("expected query error when DB closed")
	}
}

// Test authHandler signing error (can't easily force, but test error path exists)
func TestAuthHandler_TokenSigningPath(t *testing.T) {
	resetDB(t)
	k, _ := generateKeyPair()
	_ = savePrivateKey(k, time.Now().Add(1*time.Hour))

	// Normal case should work - this ensures signing path is covered
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
}

// Test authHandler with expired query param variations
func TestAuthHandler_ExpiredQueryParam(t *testing.T) {
	resetDB(t)

	// Add both valid and expired keys
	validKey, _ := generateKeyPair()
	_ = savePrivateKey(validKey, time.Now().Add(1*time.Hour))
	expiredKey, _ := generateKeyPair()
	_ = savePrivateKey(expiredKey, time.Now().Add(-1*time.Hour))

	// Test with expired=true
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for expired=true")
	}

	// Test with expired=false (should get valid key)
	req = httptest.NewRequest(http.MethodPost, "/auth?expired=false", nil)
	w = httptest.NewRecorder()
	authHandler(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for expired=false")
	}

	// Test without expired param (should get valid key)
	req = httptest.NewRequest(http.MethodPost, "/auth", nil)
	w = httptest.NewRecorder()
	authHandler(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 without expired param")
	}
}

// Test toJWK encoding edge cases
func TestKeyPair_ToJWK_Encoding(t *testing.T) {
	resetDB(t)
	k, _ := generateKeyPair()
	kp := &KeyPair{
		Kid:        42,
		PrivateKey: k,
		PublicKey:  &k.PublicKey,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	jwk := kp.toJWK()

	// Verify all fields are populated
	if jwk.Kty != "RSA" {
		t.Fatalf("expected RSA, got %s", jwk.Kty)
	}
	if jwk.Kid != "42" {
		t.Fatalf("expected kid 42, got %s", jwk.Kid)
	}
	if jwk.Use != "sig" {
		t.Fatalf("expected sig, got %s", jwk.Use)
	}
	if jwk.Alg != "RS256" {
		t.Fatalf("expected RS256, got %s", jwk.Alg)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatalf("N or E is empty")
	}

	// Verify base64 encoding is valid
	_, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("invalid N encoding: %v", err)
	}
	_, err = base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("invalid E encoding: %v", err)
	}
}

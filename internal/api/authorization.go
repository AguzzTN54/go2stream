package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// HMAC secret key for signing the JWT token
// var SECRET_KEY = []byte("EntahApaYangMerasukimuHinggaKauTegaMenghianatikuYangTulusMencintaimu")

func getSecret()([]byte, string) {
	SECRET_KEY := os.Getenv("SECRET_KEY")
	if SECRET_KEY == "" {
		SECRET_KEY = "IKISECRET"
	}

	BYTE_KEY := []byte(SECRET_KEY)
	PERMANENT_KEY := os.Getenv("PERMANENT_KEY")
	
	return BYTE_KEY, PERMANENT_KEY
}


// generateToken creates a token: "<timestamp>.<signature>"
func generateToken() string {
	expiration := time.Now().Add(6 * time.Hour).Unix() // 6 hours expiration
	timestamp := strconv.FormatInt(expiration, 10)

	SECRET_KEY, _ := getSecret()
	h := hmac.New(sha256.New, SECRET_KEY)
	h.Write([]byte(timestamp))

	signature := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", timestamp, signature)
}

// verifyToken checks timestamp and signature
func verifyToken(token string) bool {
	SECRET_KEY, PERMANENT_KEY := getSecret()
	if token == PERMANENT_KEY {
		return true
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	timestamp, sig := parts[0], parts[1]

	// Check expiration
	expUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}

	// Validate signature
	h := hmac.New(sha256.New, SECRET_KEY)
	h.Write([]byte(timestamp))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(sig))
}

// TokenHandler
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	token := generateToken()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, token)))
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow GET requests without token
		// if r.Method == http.MethodGet {
		// 	next(w, r)
		// 	return
		// }

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if !verifyToken(token) {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
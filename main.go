package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/square/go-jose/v3"
)

const (
	JWTAddExpiry = 365 * 24 * time.Hour
)

func main() {
	// Generate RSA key pair
	rsaKey, err := NewRSAKey()
	if err != nil {
		log.Fatalf("failed to generate rsa key: %v", err)
	}

	// Generate JWK
	jwk := newJSONWebKey(&rsaKey.PublicKey)

	// Generate JWKS and embed JWK
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{*jwk},
	}
	data, err := json.Marshal(jwks)
	if err != nil {
		log.Fatalf("failed to convert to jwks: %v", err)
	}
	fmt.Println("JWKS:", jwks, "")

	// Generate JWT for testing
	jwt, err := newJWT("sam@example.com", rsaKey, time.Now().Add(JWTAddExpiry))
	if err != nil {
		log.Fatalf("failed to generate to jwt: %v", err)
	}

	fmt.Println("JWT:", jwt, "")

	// Parse JWKS - Read the RSA public key off of JWKS
	var parsedJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(data, &parsedJWKS); err != nil {
		log.Fatalf("failed to parse jwks")
	}
	if len(parsedJWKS.Keys) == 0 {
		log.Fatalf("no keys in jwks")
	}
	parsedJWK := parsedJWKS.Keys[0]
	parsedRSAKey, ok := parsedJWK.Key.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("type cast failed")
	}

	// Validate JWT with JWK
	claims, err := parseJWT(jwt, parsedRSAKey)
	if err != nil {
		log.Fatalf("failed to parse to jwt: %v", err)
	}

	fmt.Println("User's email:", claims.Email)
}

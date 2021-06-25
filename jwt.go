package main

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

const (
	JWTIssuer = "Acme"  // The issuer of JWT
)

var (
	ErrInvalidJWT error = fmt.Errorf("invalid jwt")
)

type UserClaims struct {
	jwt.Claims
	Email string `json:"email"`
}

func newJWT(email string, priKey *rsa.PrivateKey, expireAt time.Time) (string, error) {
	claims := UserClaims{
		Email: email,
		Claims: jwt.Claims{
			Issuer: JWTIssuer,
			Expiry: jwt.NewNumericDate(expireAt),
		},
	}
	opts := jose.SignerOptions{}
	opts.WithType("JWT")

	signKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       priKey,
	}

	signer, err := jose.NewSigner(signKey, &opts)
	if err != nil {
		return "", err
	}

	return jwt.Signed(signer).
		Claims(claims).
		CompactSerialize()
}

func parseJWT(signedJWT string, pubKey *rsa.PublicKey) (*UserClaims, error) {
	token, err := jwt.ParseSigned(signedJWT)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt")
	}

	claims := new(UserClaims)
	if err := token.Claims(pubKey, claims); err != nil {
		return nil, fmt.Errorf("invalid jwt")
	}

	err = claims.Validate(jwt.Expected{
		Issuer: JWTIssuer,
		Time:   time.Now(),
	})
	if err != nil {
		if err == jwt.ErrExpired {
			return nil, ErrInvalidJWT
		}

		return nil, ErrInvalidJWT
	}

	return claims, nil
}

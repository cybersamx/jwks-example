package main

import (
	"crypto/rsa"

	"github.com/square/go-jose/v3"
)

func newJSONWebKey(pubKey *rsa.PublicKey) *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       pubKey,
		Algorithm: "RS256",
		Use:       "sig",
	}
}

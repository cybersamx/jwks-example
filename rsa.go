package main

import (
	"crypto/rand"
	"crypto/rsa"
)

const (
	KeyBitSize = 2048
)

func NewRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, KeyBitSize)
}

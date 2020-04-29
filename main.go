package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	crt := mustLoadCert("./crt/server.crt")
	key := mustLoadKey("./crt/server.key")

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"nbf":  time.Now().Unix(),
		"exp":  time.Now().Add(2 * time.Hour).Unix(),
		"role": []string{"reader", "writer"},
		"uuid": "12345678-1234-5678-1234-567812345678",
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return crt.PublicKey, nil
	})
	if err != nil {
		panic(err)
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		fmt.Println("token: ", tokenString)
		fmt.Println("claims: ", claims)
	} else {
		fmt.Println("wups")
	}
}

func mustLoadCert(f string) *x509.Certificate {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		panic("block is nil")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return cert
}

func mustLoadKey(f string) *rsa.PrivateKey {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		panic("block is nil")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

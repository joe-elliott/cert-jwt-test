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
	rootCert := mustLoadCert("./crt/root.crt")
	fmt.Println(rootCert.Subject.CommonName)

	rootKey := mustLoadKey("./crt/root.key")
	fmt.Println(rootKey.Size())

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Now().Unix(),
	})

	tokenString, err := token.SignedString(rootKey)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return rootCert.PublicKey, nil
	})
	if err != nil {
		panic(err)
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
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

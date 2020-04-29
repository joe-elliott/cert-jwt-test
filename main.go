package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	rootCert := mustLoadCert("./crt/root.crt")
	fmt.Println(rootCert.Subject.CommonName)

	rootKey := mustLoadKey("./crt/root.key")
	fmt.Println(rootKey.Size())
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

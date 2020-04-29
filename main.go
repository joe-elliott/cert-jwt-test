package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	rootCert := mustLoadCert("./crt/root.crt")
	fmt.Println(rootCert.Subject.CommonName)
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

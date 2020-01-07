package main

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	"bou.ke/monkey"
)

var (
	oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func isSecp256k1(oid asn1.ObjectIdentifier) bool {
	if len(oid) != len(oidSecp256k1) {
		return false
	}

	for i := 0; i < len(oidSecp256k1); i++ {
		if oid[i] != oidSecp256k1[i] {
			return false
		}
	}

	return true
}

func isCurveP521(oid asn1.ObjectIdentifier) bool {
	if len(oid) != len(oidCurveP521) {
		return false
	}

	for i := 0; i < len(oidCurveP521); i++ {
		if oid[i] != oidCurveP521[i] {
			return false
		}
	}

	return true
}

func main() {
	pool := x509.NewCertPool()
	caCertPath := "./sdk/ca.crt"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		fmt.Println("ReadFile err:", err)
		return
	}
	pool.AppendCertsFromPEM(caCrt)

	var equalGuard *monkey.PatchGuard
	equalGuard = monkey.Patch(asn1.ObjectIdentifier.Equal, func(left, right asn1.ObjectIdentifier) bool {
		equalGuard.Unpatch()
		defer equalGuard.Restore()

		if isSecp256k1(left) && isCurveP521(right) {
			return true
		}
		return left.Equal(right)
	})

	InitSecp256k1()

	monkey.Patch(elliptic.P521, func() elliptic.Curve {
		return secp256k1
	})

	var unmarshalGuard *monkey.PatchGuard
	unmarshalGuard = monkey.Patch(elliptic.Unmarshal, func(curve elliptic.Curve, data []byte) (x, y *big.Int) {
		unmarshalGuard.Unpatch()
		defer unmarshalGuard.Restore()

		if curve == elliptic.P521() {
			byteLen := (secp256k1.BitSize + 7) >> 3
			if len(data) != 1+2*byteLen {
				return
			}
			if data[0] != 4 { // uncompressed form
				return
			}
			p := secp256k1.P
			x = new(big.Int).SetBytes(data[1 : 1+byteLen])
			y = new(big.Int).SetBytes(data[1+byteLen:])
			if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
				return nil, nil
			}

			if !secp256k1.IsOnCurve(x, y) {
				return nil, nil
			}

			return
		}

		return elliptic.Unmarshal(curve, data)
	})

	cliCrt, err := tls.LoadX509KeyPair("./sdk/sdk.crt", "./sdk/sdk.key")
	if err != nil {
		fmt.Println("Load key pair err:", err)
		return
	}

	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{cliCrt},
		InsecureSkipVerify: true,
	}

	cipherSuites := make([]uint16, 0, 1)
	cipherSuites = append(cipherSuites, 0xc02b)

	curvePreferences := make([]tls.CurveID, 0, 1)
	curvePreferences = append(curvePreferences, 0x16)

	conf.CipherSuites = cipherSuites
	conf.CurvePreferences = curvePreferences

	conn, err := tls.Dial("tcp", "127.0.0.1:20200", conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	n, err := conn.Write([]byte("hello\n"))
	if err != nil {
		log.Println(n, err)
		return
	}
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}
	println(string(buf[:n]))

	/*
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cliCrt},
			},
		}
		client := &http.Client{Transport: tr}
		client.

		resp, err := client.Get("https://127.0.0.1:8081")
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
	*/

	/*
		cert, err := tls.LoadX509KeyPair("client.pem", "client.key")
		if err != nil {
			log.Println(err)
			return
		}
		certBytes, err := ioutil.ReadFile("client.pem")
		if err != nil {
			panic("Unable to read cert.pem")
		}
		clientCertPool := x509.NewCertPool()
		ok := clientCertPool.AppendCertsFromPEM(certBytes)
		if !ok {
			panic("failed to parse root certificate")
		}
		conf := &tls.Config{
			RootCAs:            clientCertPool,
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}
		conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		n, err := conn.Write([]byte("hello\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
		buf := make([]byte, 100)
		n, err = conn.Read(buf)
		if err != nil {
			log.Println(n, err)
			return
		}
		println(string(buf[:n]))
	*/
}

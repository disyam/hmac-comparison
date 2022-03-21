package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

type Row struct {
	Data      []byte
	Signature []byte
}

var (
	rows   []*Row
	secret []byte
)

func seed(count int) {
	for i := 0; i < count; i++ {
		rows = append(rows, &Row{Data: []byte(fmt.Sprint(i))})
	}
}

func signSHA2() {
	key := secret
	for _, row := range rows {
		h := hmac.New(sha256.New, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		row.Signature = signature
		key = signature
	}
}

func checkSHA2() (err error) {
	key := secret
	for _, row := range rows {
		h := hmac.New(sha256.New, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		if !bytes.Equal(row.Signature, signature) {
			err = fmt.Errorf("data %s NOT MATCH", row.Data)
		}
		key = signature
	}
	return
}

func runSHA2(count int) (duration time.Duration, err error) {
	seed(count)
	start := time.Now()
	signSHA2()
	err = checkSHA2()
	if err != nil {
		return
	}
	end := time.Now()
	duration = end.Sub(start)
	fmt.Println("SHA-2:", duration)
	return
}

func signSHA3() {
	key := secret
	for _, row := range rows {
		h := hmac.New(sha3.New256, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		row.Signature = signature
		key = signature
	}
}

func checkSHA3() (err error) {
	key := secret
	for _, row := range rows {
		h := hmac.New(sha3.New256, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		if !bytes.Equal(row.Signature, signature) {
			err = fmt.Errorf("data %s NOT MATCH", row.Data)
		}
		key = signature
	}
	return
}

func runSHA3(count int) (duration time.Duration, err error) {
	seed(count)
	start := time.Now()
	signSHA3()
	err = checkSHA3()
	if err != nil {
		return
	}
	end := time.Now()
	duration = end.Sub(start)
	fmt.Println("SHA-3:", duration)
	return
}

func signBLAKE3() {
	key := secret
	for _, row := range rows {
		h := blake3.New(32, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		row.Signature = signature
		key = signature
	}
}

func checkBLAKE3() (err error) {
	key := secret
	for _, row := range rows {
		h := blake3.New(32, key)
		h.Write(row.Data)
		signature := h.Sum(nil)
		if !bytes.Equal(row.Signature, signature) {
			err = fmt.Errorf("data %s NOT MATCH", row.Data)
		}
		key = signature
	}
	return
}

func runBLAKE3(count int) (duration time.Duration, err error) {
	seed(count)
	start := time.Now()
	signBLAKE3()
	err = checkBLAKE3()
	if err != nil {
		return
	}
	end := time.Now()
	duration = end.Sub(start)
	fmt.Println("BLAKE3:", duration)
	return
}

func main() {
	var err error
	secret = make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		log.Fatalln(err)
	}
	count := 1000000
	fmt.Printf("benchmark %d data with 256 bit signature\n", count)
	rows = []*Row{}
	var sha2Duration time.Duration
	sha2Duration, err = runSHA2(count)
	if err != nil {
		log.Fatalln(err)
	}
	rows = []*Row{}
	var sha3Duration time.Duration
	sha3Duration, err = runSHA3(count)
	if err != nil {
		log.Fatalln(err)
	}
	rows = []*Row{}
	var blake3Duration time.Duration
	blake3Duration, err = runBLAKE3(count)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\nBLAKE3 is %.2fx faster than SHA-2\n", float64(sha2Duration.Milliseconds())/float64(blake3Duration.Milliseconds()))
	fmt.Printf("BLAKE3 is %.2fx faster than SHA-3", float64(sha3Duration.Milliseconds())/float64(blake3Duration.Milliseconds()))
}

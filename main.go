package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Request struct {
	Data string `json:"data"`
}
type Response struct {
	Data string `json:"data"`
}

func main() {
	// privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	router := mux.NewRouter()

	router.HandleFunc("/encrypt", Encrypt).Methods("POST")
	router.HandleFunc("/decrypt", Decrypt).Methods("POST")

	log.Fatal(http.ListenAndServe(":8777", router))
}

func CheckError(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	CheckError(err)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	CheckError(err)
	fmt.Println("Plaintext:", string(plaintext))
	return string(plaintext)
}

func Encrypt(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Encrypt...")

	w.Header().Set("Content-Type", "application/json")
	var data Request
	_ = json.NewDecoder(r.Body).Decode(&data)

	kt, _ := ioutil.ReadFile("t.key")
	block, _ := pem.Decode(kt)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	publicKey := privateKey.PublicKey
	CheckError(err)
	// vars := mux.Vars(r)
	// key := vars["text"]

	fmt.Println("PUB KEY : ", publicKey)

	encryptedMessage := RSA_OAEP_Encrypt(data.Data, publicKey)
	fmt.Println("Plaint Text:", data.Data)
	fmt.Println("Encrypt Text:", encryptedMessage)
	res := Response{Data: encryptedMessage}

	json.NewEncoder(w).Encode(res)
}

func Decrypt(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Decrypt...")

	w.Header().Set("Content-Type", "application/json")
	var data Request
	_ = json.NewDecoder(r.Body).Decode(&data)

	kt, _ := ioutil.ReadFile("t.key")
	block, _ := pem.Decode(kt)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	publicKey := privateKey.PublicKey
	CheckError(err)
	// vars := mux.Vars(r)
	// key := vars["text"]

	fmt.Println("PUB KEY : ", publicKey)

	decript := RSA_OAEP_Decrypt(data.Data, *privateKey)

	fmt.Println("Plaint Text:", data.Data)
	fmt.Println("Decript Text:", decript)

	res := Response{Data: decript}

	json.NewEncoder(w).Encode(res)
}

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	address := "secret1ja0hcwvy76grqkpgwznxukgd7t8a8anmmx05pp"

	var priv [32]byte
	rand.Read(priv[:]) //nolint:errcheck

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	consensusPubString := "79++5YOHfm0SwhlpUDClv7cuCjq9xBZlWqSjDJWkRG8="

	consensusPubBytes, err := base64.StdEncoding.DecodeString(
		consensusPubString,
	)
	if err != nil {
		panic(err)
	}

	sharedSecret, err := curve25519.X25519(priv[:], consensusPubBytes)

	fmt.Println("shared", sharedSecret)
	fmt.Println("nonce", nonce)

	var hkdfSalt = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x4b, 0xea, 0xd8, 0xdf, 0x69, 0x99,
		0x08, 0x52, 0xc2, 0x02, 0xdb, 0x0e, 0x00, 0x97,
		0xc1, 0xa1, 0x2e, 0xa6, 0x37, 0xd7, 0xe9, 0x6d,
	}

	if err != nil {
		panic(err)
	}

	hkdfReader := hkdf.New(
		sha256.New,
		append(sharedSecret, nonce...),
		hkdfSalt,
		[]byte{},
	)

	encryptionKey := make([]byte, 32)
	_, err = io.ReadFull(hkdfReader, encryptionKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("encryptionKey", encryptionKey)

	fmt.Println(len(encryptionKey))
	cipher, err := miscreant.NewAESCMACSIV(encryptionKey)

	if err != nil {
		panic(err)
	}

	codeHash := "2ad4ed2a4a45fd6de3daca9541ba82c26bb66c76d1c3540de39b509abd26538e"
	message := "{\"list_a_m_m_pairs\":{\"pagination\":{\"start\":0,\"limit\":30}}}"

	plaintext := codeHash + message

	ciphertext, err := cipher.Seal(nil, []byte(plaintext), []byte{})
	fmt.Println("ciphertext", ciphertext)
	encrypted := append(nonce, append(pub[:], ciphertext...)...)
	fmt.Println(encrypted)

	query := base64.StdEncoding.EncodeToString(encrypted)
	fmt.Println("query", query)
	query = url.QueryEscape(query)
	fmt.Println(query)

	url := fmt.Sprintf("%s/compute/v1beta1/query/%s?query=%s",
		"https://lcd.mainnet.secretsaturn.net",
		address,
		query,
	)
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}

	fmt.Printf(res.Status)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(body))

	var jsonData map[string]interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		panic(err)
	}

	// Extract 'data' from the JSON.
	resultdata, ok := jsonData["data"]
	if !ok {
		panic(err)
	}

	resultdataBytes, err := base64.StdEncoding.DecodeString(resultdata.(string))
	if err != nil {
		panic(err)
	}

	decryptedBytes, err := cipher.Open(nil, resultdataBytes, []byte{})
	if err != nil {
		panic(err)
	}

	// Decode base64 string to get the original byte slice.
	decodedBytes, err := base64.StdEncoding.DecodeString(string(decryptedBytes))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decodedBytes))

}

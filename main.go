package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	// SavePublicAndPrivateKeyToFile()
	privateKey, _ := ReadPrivateKeyFromFile("./private_key.pem")
	// EncryptedData(&privateKey.PublicKey)
	cipher, _ := ReadPublicKeyFromFile("./public_key.pem")
	str := DecryptedByPrivateKey(privateKey, cipher)
	fmt.Println("String:", str)
}

func SavePublicAndPrivateKeyToFile() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	publicKey := &privateKey.PublicKey

	//Save private key to file
	privateKeyFile, err := os.Create("./private_key.pem")
	if err != nil {
		fmt.Println("Failed to create private key file")
		return
	}

	defer privateKeyFile.Close()

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(privateKeyFile, privateKeyBlock)
	if err != nil {
		fmt.Println("Failed to write private key file")
		return
	}

	fmt.Println("Private key ne:", string(privateKeyBlock.Bytes))

	//Save public key to file
	publicKeyFile, err := os.Create("./public_key.pem")
	if err != nil {
		fmt.Println("Failed to create public key file")
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("Failed to marshal public key", err)
		return
	}

	defer publicKeyFile.Close()

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	err = pem.Encode(publicKeyFile, publicKeyBlock)
	if err != nil {
		fmt.Println("Failed to write public key file:", err)
		return
	}

	fmt.Println("Save public and private key successfully")
}

func ReadPrivateKeyFromFile(fileName string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Failed to open private key file")
		return nil, err
	}

	defer privateKeyFile.Close()

	privateKeyBytes, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		fmt.Println("Failed to read private key file:", err)
		return nil, err
	}

	//extract private key form pem data
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Failed to decode private key PEM")
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("failed to parse private key:", err)
		return nil, err
	}

	fmt.Println("Private Key:", privateKey)
	return privateKey, nil
}

func ReadPublicKeyFromFile(fileName string) ([]byte, error) {
	publicKeyFile, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Failed to open public key file:", err)
	}

	defer publicKeyFile.Close()

	publicKeyBytes, err := ioutil.ReadAll(publicKeyFile)
	if err != nil {
		fmt.Println("Failed to read public key file:", err)
		return nil, err
	}

	//extract public key from pem data
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		fmt.Println("Failed to decode public key:", err)
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return nil, err
	}

	rsaPubKey := publicKey.(*rsa.PublicKey)
	data := []byte("Hello")

	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, data, nil)
	if err != nil {
		fmt.Println("Failed to encrypt data")
		return nil, err
	}

	fmt.Println("Cipher Text:", cipherText)

	cipherTextString := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println("Cipher Text String:", cipherTextString)

	//decode cipher text string to byte
	decodeCipher, _ := base64.StdEncoding.DecodeString(cipherTextString)
	fmt.Println("Decode cipher:", decodeCipher)

	fmt.Println("Public key:", publicKey)
	return decodeCipher, nil

}

func EncryptedData(publicKey *rsa.PublicKey) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte("Hello"), nil)
	if err != nil {
		fmt.Println("Failed to encrypt data:", err)
		return nil, err
	}

	//encode to base64 string
	cipherTextString := base64.StdEncoding.EncodeToString(cipherText)

	//decode to []byte
	byteCipher, _ := base64.StdEncoding.DecodeString(cipherTextString)
	fmt.Println("Encrypted Data:", cipherTextString)
	fmt.Println("Byte code:", byteCipher)
	return byteCipher, nil
}

func DecryptedByPrivateKey(privateKey *rsa.PrivateKey, cipherText []byte) string {
	plaintText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		fmt.Println("Failed to decrypt:", err)
		return ""
	}

	return string(plaintText)
}

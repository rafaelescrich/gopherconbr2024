package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/sha3"
)

// Função para gerar um hash criptográfico
func GerarHash() {
	s := "GopherconBR é o melhor evento de Go do MUNDO!"
	fmt.Println("\n==================== Hash Criptográfico ====================")
	fmt.Println("Texto a ser hasheado:", s)

	md5Hash := md5.Sum([]byte(s))
	sha2_256Hash := sha256.Sum256([]byte(s))
	sha3_256Hash := sha3.Sum256([]byte(s))

	fmt.Printf("MD5:       %x\n", md5Hash)
	fmt.Printf("SHA2-256:  %x\n", sha2_256Hash)
	fmt.Printf("SHA3-256:  %x\n", sha3_256Hash)
	fmt.Println("===========================================================\n")
}

// Funções para criptografia simétrica
func CifrarSimetrica(key, plaintext, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	return aesgcm.Seal(nil, nonce, plaintext, nil)
}

func DecifrarSimetrica(key, ciphertext, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return plaintext
}

// Funções para criptografia assimétrica com RSA
func GerarParDeChavesRSA() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return privKey, &privKey.PublicKey
}

func CifrarAssimetricaRSA(pubKey *rsa.PublicKey, plaintext []byte) []byte {
	label := []byte("") // Label para OAEP, geralmente vazio
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, label)
	if err != nil {
		log.Fatalf("Erro ao cifrar com RSA: %s", err)
	}
	return ciphertext
}

func DecifrarAssimetricaRSA(privKey *rsa.PrivateKey, ciphertext []byte) []byte {
	label := []byte("") // Label para OAEP, geralmente vazio
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, label)
	if err != nil {
		log.Fatalf("Erro ao decifrar com RSA: %s", err)
	}
	return plaintext
}

func AssinarRSA(privKey *rsa.PrivateKey, message []byte) []byte {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Erro ao assinar com RSA: %s", err)
	}
	return signature
}

func VerificarAssinaturaRSA(pubKey *rsa.PublicKey, message, signature []byte) bool {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}

// Funções para criptografia e assinatura com Ed25519
func GerarParDeChavesEd25519() (ed25519.PublicKey, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pubKey, privKey
}

func AssinarEd25519(privKey ed25519.PrivateKey, message []byte) []byte {
	signature := ed25519.Sign(privKey, message)
	return signature
}

func VerificarAssinaturaEd25519(pubKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

func main() {
	// Hash criptográfico
	GerarHash()

	// Criptografia simétrica
	key := []byte("GOPHER24GOPHER24GOPHER24GOPHER24") // Chave de 32 bytes para AES-256
	plaintext := []byte("Este é o texto plano a ser cifrado com a chave simétrica")
	nonce := []byte("GOGOGOGOGOGO") // Nonce fixo para demonstração
	ciphertext := CifrarSimetrica(key, plaintext, nonce)
	fmt.Println("================= Criptografia Simétrica =================")
	fmt.Printf("Texto plano: %s\n", string(plaintext))
	fmt.Printf("Texto cifrado: %x\n", ciphertext)

	decryptedText := DecifrarSimetrica(key, ciphertext, nonce)
	fmt.Printf("Texto decifrado: %s\n", string(decryptedText))
	fmt.Println("==========================================================\n")

	// Criptografia e assinatura com RSA
	privKeyRSA, pubKeyRSA := GerarParDeChavesRSA()
	fmt.Println("================= Criptografia Assimétrica com RSA =================")
	messageRSA := []byte("Mensagem para cifragem e assinatura RSA.")
	ciphertextRSA := CifrarAssimetricaRSA(pubKeyRSA, messageRSA)
	fmt.Printf("Texto para cifragem com RSA: %s\n", string(messageRSA))
	fmt.Printf("Texto cifrado com RSA: %x\n", ciphertextRSA)

	decryptedTextRSA := DecifrarAssimetricaRSA(privKeyRSA, ciphertextRSA)
	fmt.Printf("Texto decifrado com RSA: %s\n", string(decryptedTextRSA))

	signatureRSA := AssinarRSA(privKeyRSA, messageRSA)
	fmt.Printf("Texto para assinatura RSA: %x\n", messageRSA)
	fmt.Printf("Assinatura RSA: %x\n", signatureRSA)

	verificationResultRSA := VerificarAssinaturaRSA(pubKeyRSA, messageRSA, signatureRSA)
	fmt.Printf("Verificação de assinatura RSA: %t\n", verificationResultRSA)
	fmt.Println("======================================================================\n")

	// Criptografia e assinatura com Ed25519
	pubKeyEd25519, privKeyEd25519 := GerarParDeChavesEd25519()
	fmt.Println("================= Criptografia e Assinatura com Ed25519 =================")
	messageEd25519 := []byte("Mensagem de teste para assinatura e verificação Ed25519.")
	signatureEd25519 := AssinarEd25519(privKeyEd25519, messageEd25519)
	fmt.Printf("Texto para assinatura Ed25519: %x\n", messageEd25519)
	fmt.Printf("Assinatura Ed25519: %x\n", signatureEd25519)

	verificationResultEd25519 := VerificarAssinaturaEd25519(pubKeyEd25519, messageEd25519, signatureEd25519)
	fmt.Printf("Verificação de assinatura Ed25519: %t\n", verificationResultEd25519)
	fmt.Println("=============================================================================\n")
}

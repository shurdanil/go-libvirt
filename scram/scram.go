package scram

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"crypto/hmac"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

func pbkdf2Sum(password, salt []byte, i int) []byte {
	return pbkdf2.Key(password, salt, i, PBKDF2Length, sha1.New)
}

func hmacSum(key, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func sha1Sum(message []byte) []byte {
	mac := sha1.New()
	mac.Write(message)
	return mac.Sum(nil)
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		fmt.Println("Warning: xor lengths are differing...", a, b)
	}

	count := len(a)
	if len(b) < count {
		count = len(b)
	}

	out := make([]byte, count)
	for i := 0; i < count; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func toBase64(src []byte) []byte {
	out := base64.StdEncoding.EncodeToString(src)
	return []byte(out)
}

func fromBase64(src []byte) []byte {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	l, _ := base64.StdEncoding.Decode(dst, src)
	return dst[:l]
}

func normalize(in []byte) []byte {
	return in
}

func clientFirstMessageBare(cName, cNonce []byte) (out []byte) {
	out = []byte("n=")
	out = append(out, cName...)
	out = append(out, ",r="...)
	out = append(out, cNonce...)
	return
}

func ClientFirstMessage(cName, cNonce []byte) (out []byte) {
	out = []byte("n,,")
	out = append(out, clientFirstMessageBare(cName, cNonce)...)
	return
}

func serverFirstMessage(sNonce, sSalt, cNonce, cName []byte, iterations int) (out []byte) {
	nonce := append(cNonce, sNonce...)

	out = append(out, "r="...)
	out = append(out, nonce...)
	out = append(out, ",s="...)
	out = append(out, sSalt...)
	out = append(out, ",i="...)
	out = append(out, strconv.Itoa(iterations)...)

	return
}

func clientFinalMessageWithoutProof(cHeader, cNonce, sNonce []byte) (out []byte) {
	nonce := append(cNonce, sNonce...)

	out = []byte("c=")
	out = append(out, cHeader...)
	out = append(out, ",r="...)
	out = append(out, nonce...)
	return
}

func AuthMessage(cName, cNonce, sNonce, sSalt, cHeader []byte, iterations int) (out []byte) {
	out = clientFirstMessageBare(cName, cNonce)
	out = append(out, ","...)
	out = append(out, serverFirstMessage(sNonce, sSalt, cNonce, cName, iterations)...)
	out = append(out, ","...)
	out = append(out, clientFinalMessageWithoutProof(cHeader, cNonce, sNonce)...)
	return
}

func ClientFinalMessage(cName, cPass, cNonce, sNonce, sSalt, cHeader []byte, iterations int) (out []byte) {
	authMessage := AuthMessage(cName, cNonce, sNonce, sSalt, cHeader, iterations)

	saltedPassword := pbkdf2Sum(normalize(cPass), fromBase64(sSalt), iterations)

	clientKey := hmacSum(saltedPassword, []byte("Client Key"))
	storedKey := sha1Sum(clientKey)
	clientSignature := hmacSum(storedKey, authMessage)

	clientProof := xor(clientKey, clientSignature)

	out = clientFinalMessageWithoutProof(cHeader, cNonce, sNonce)
	out = append(out, ",p="...)
	out = append(out, toBase64(clientProof)...)

	return
}

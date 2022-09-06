package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var secretKey = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56}
var initVector = []byte{0xcb, 0xce, 0xcb, 0xcd, 0xcb, 0xce, 0xcb, 0xcd, 0xcb, 0xce, 0xcb, 0xcd, 0xcb, 0xce, 0xcb, 0xcd}

// Encrypt encrypt with aes256-cbc
func Encrypt(inputStr string) (string, error) {
	input := []byte(inputStr)
	input = pad(input)
	c, err := aes.NewCipher(secretKey)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	encrypter := cipher.NewCBCEncrypter(c, initVector)
	data := make([]byte, len(input))
	copy(data, input)
	encrypter.CryptBlocks(data, data)

	return strings.ToUpper(hex.EncodeToString(data)), nil
}

// test
// Decrypt decrypt with aes256-cbc
func Decrypt(inputStr string) (string, error) {
	input, err := hex.DecodeString(inputStr)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	c, err := aes.NewCipher(secretKey)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	decrypter := cipher.NewCBCDecrypter(c, initVector)
	data := make([]byte, len(input))
	copy(data, input)
	decrypter.CryptBlocks(data, data)

	data, err = unpad(data)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return string(data), nil
}

func pad(buf []byte) []byte {
	bufLen := len(buf)
	padLen := aes.BlockSize - (bufLen % aes.BlockSize)
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(buf, padText...)
}

func unpad(buf []byte) ([]byte, error) {
	bufLen := len(buf)
	if bufLen == 0 {
		return nil, errors.New("invalid padding size")
	}

	pad := buf[bufLen-1]
	padLen := int(pad)
	if padLen > bufLen || padLen > aes.BlockSize {
		return nil, errors.New("invalid padding size")
	}

	for _, v := range buf[bufLen-padLen : bufLen-1] {
		if v != pad {
			return nil, errors.New("invalid padding")
		}
	}

	return buf[:bufLen-padLen], nil
}

func main() {

}

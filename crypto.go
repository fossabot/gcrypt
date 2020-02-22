/*
 * MIT License
 *
 * Copyright (c) 2020. Shaurya
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package gcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
)

const (
	passwordSaltBytes = 32
	passwordHashBytes = 64
)

func aesEncrypt(k, v string) ([]byte, error) {
	Hash := [32]byte(sha256xX(k, 2))
	block, _ := aes.NewCipher(Hash[:])
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte("error"), errors.New("error")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err1 := io.ReadFull(rand.Reader, nonce); err1 != nil {
		err1 := errors.New("error")
		return []byte("error"), err1
	}
	vData := []byte(v)
	encryptedData := gcm.Seal(nonce, nonce, vData, nil)
	return encryptedData, nil
}

func aesDecrypt(k string, v []byte) (string, error) {
	Hash := [32]byte(sha256xX(k, 2))
	block, err := aes.NewCipher(Hash[:])
	if err != nil {
		return "error:", errors.New("error")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "error:", errors.New("error")
	}
	nonceSize := gcm.NonceSize()
	nonce, encryptedData := v[:nonceSize], v[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "error:", errors.New("error")
	}
	return string(decryptedData), nil
}

func sCrypt(password string) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.New("error")
	}

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, passwordHashBytes)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(key), nil
}

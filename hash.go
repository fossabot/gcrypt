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
	goSha256 "crypto/sha256"
	goSha512 "crypto/sha512"
	goHex "encoding/hex"
	"errors"
	goRipemd160 "golang.org/x/crypto/ripemd160"
)

// Hash
var (
	Hash [32]byte
)

// sha 256 32 byte
func sha256(s string) [32]byte {
	return goSha256.Sum256([]byte(s))
}

func sha256xX(s string, x int) [32]byte {
	input := []byte(s)
	sum := x
	for i := 0; i < x; i++ {
		H := goSha256.Sum256([]byte(input))

		Hash = H
		sum += i
	}
	return Hash
}

// sha 512 returns 64 byte
func sha512(s string) [64]byte {
	return goSha512.Sum512([]byte(s))
}

// RIPEMD160Hash ...
func RIPEMD160Hash(data []byte) []byte {
	first := goSha256.Sum256(data)
	hasher := goRipemd160.New()
	hasher.Write(first[:])
	hash := hasher.Sum(nil)
	return hash[:]
}

func hash2Str(s string) ([]byte, error) {
	decoded, err := goHex.DecodeString(s)
	if err != nil {
		return nil, errors.New("unable to decode")
	}
	return decoded, nil
}

func str2Hash(s []byte) string {
	encoded := goHex.EncodeToString(s)
	return encoded
}

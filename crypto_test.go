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
	"fmt"
	"testing"
)

func TestAesEncryption(t *testing.T) {
	encryptedData, err := aesEncrypt("gcrypt", "gcrypt testing.")
	if err != nil {
		t.Fail()
	}

	encryptedData1, err1 := aesEncrypt("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", "gcrypt testing.")
	fmt.Println(err1)

	decryptedData, err2 := aesDecrypt("gcrypt", encryptedData)
	if err2 != nil {
		t.Fail()
	}

	_, err3 := aesDecrypt("gcrypt", encryptedData1)
	Expected1 := "error"
	if err3.Error() != Expected1 {
		t.Fail()
	}

	if decryptedData != "gcrypt testing." {
		t.Fail()
	}

}

func TestScrypt(t *testing.T) {
	key, err := sCrypt("gcrypt")
	if err != nil {
		t.Fail()
	}

	fmt.Println(key)

}

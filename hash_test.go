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
	"strconv"
	"testing"
)

func TestSha256(t *testing.T) {
	a := sha256("gcrypt")

	b := sha256("gcrypt")

	s, err := fmt.Printf("%x", b)

	if err != nil {
		t.Fail()
	}

	if a != b {
		t.Fail()
	}
	fmt.Println(s)

}

func TestSha512(t *testing.T) {
	a := sha512("gcrypt")

	b := sha512("gcrypt")

	s, err := fmt.Printf("%x", b)

	if err != nil {
		t.Fail()
	}

	if a != b {
		t.Fail()
	}
	fmt.Println(s)

}

func TestSha256xX(t *testing.T) {
	a := sha256xX("gcrypt", 256)

	b := sha256xX("gcrypt", 256)

	s, err := fmt.Printf("%x", a)

	if err != nil {
		t.Fail()
	}

	if a != b {
		t.Fail()
	}

	fmt.Println(s)

}

func TestRIPEMD160Hash(t *testing.T) {
	input := sha256("gcrypt")

	a := RIPEMD160Hash(input[:])
	b := RIPEMD160Hash(input[:])

	s, err := fmt.Printf("%x", a)

	if err != nil {
		t.Fail()
	}

	if len(a) != len(b) {
		t.Fail()
	}

	for i := range a {
		if a[i] != a[i] {
			t.Fail()
		}
	}

	fmt.Println(s)
}

func TestHash2Str(t *testing.T) {
	input := sha256("gcrypt")
	s, err := fmt.Printf("%x", input)
	if err != nil {
		t.Fail()
	}
	str := strconv.Itoa(s)
	a, err := hash2Str(string(str))
	if err != nil {
		t.Fail()
	}
	b, err := hash2Str(string(str))
	if err != nil {
		t.Fail()
	}
	val, err := hash2Str("q")
	Expected := "unable to decode"
	if err.Error() != Expected && val != nil {
		t.Fail()
	}
	if len(a) != len(b) {
		t.Fail()
	}

}

func TestStr2Hash(t *testing.T) {
	input := sha256("gcrypt")
	r := str2Hash(input[:])

	fmt.Println(r)
}


/*
 * Copyright (c) 2017 AlexRuzin (stan.ruzin@gmail.com)
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
package crypto

import (
    "testing"
    "io"
    "crypto/rand"
    "crypto/md5"
)

/* The AES test was disabled since it needs to be completed */
func fTestCryptoRandomKeyAES(t *testing.T) {
    //plaintext := make([]byte, 4094)
    plaintext := make([]byte, 4)
    if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
        t.Errorf("ERROR: Failed to generate random pad")
        t.FailNow()
    }
    plaintext_sum := md5.Sum(plaintext)

    ciphertext, err := AES128CBC_Encrypt(plaintext, nil)
    if err != 0 {
        t.Errorf("ERROR: Encryption failure")
        t.FailNow()
    }

    decrypted, err := AES128CBC_Decrypt(ciphertext, nil)
    if err != 0 {
        t.Errorf("ERROR: Decryption failure")
        t.FailNow()
    }

    decrypted_sum := md5.Sum(decrypted)
    if testEq(decrypted_sum, plaintext_sum) != true {
        t.Errorf("ERROR: checksum failure")
        t.FailNow()
    }
}

func TestCryptoRC4_4byte_RKEY(t *testing.T) {
    /*
     * Test the RC4 cipher by generating a random key, and encrypting 4 bytes of data
     */
    plaintext := make([]byte, 4)
    if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
        t.Errorf("ERROR: Failed to generate random pad")
        t.FailNow()
    }
    plaintext_sum := md5.Sum(plaintext)

    ciphertext, err := RC4_Encrypt(plaintext, nil /* Generate a key based on the hostname */)
    if err != nil {
        t.Errorf("ERROR: Failed to encrypt buffer")
        t.FailNow()
    }

    decrypted, err := RC4_Decrypt(ciphertext, nil)
    if err != nil {
        t.Errorf("ERROR: Failed to decrypt buffer")
        t.FailNow()
    }

    decrypted_sum := md5.Sum(decrypted)

    if testEq(decrypted_sum, plaintext_sum) != true {
        t.Errorf("ERROR: Sums do not match for inputs. RC4 failure.")
        t.FailNow()
    }

    t.Logf("PASS: RC4: Random key with 4 bytes")
}

func TestCryptoRC4_1028byte_KEY(t *testing.T) {
    /*
     * Test the RC4 cipher by generating a 1028 byte buffer with a hardcoded key
     */
    var key []byte = []byte("TESTINGRC4")
    plaintext := make([]byte, 1028)
    if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
        t.Errorf("ERROR: Failed to generate random pad")
        t.FailNow()
    }
    plaintext_sum := md5.Sum(plaintext)

    ciphertext, err := RC4_Encrypt(plaintext, &key)
    if err != nil {
        t.Errorf("ERROR: Failed to encrypt buffer")
        t.FailNow()
    }

    decrypted, err := RC4_Decrypt(ciphertext, &key)
    if err != nil {
        t.Errorf("ERROR: Failed to decrypt buffer")
        t.FailNow()
    }

    decrypted_sum := md5.Sum(decrypted)

    if testEq(decrypted_sum, plaintext_sum) != true {
        t.Errorf("ERROR: Sums do not match for inputs. RC4 failure.")
        t.FailNow()
    }

    t.Logf("PASS: RC4: Static key with 1028 pad")
}

func testEq(a, b [16]byte) bool {
    if len(a) != len(b) {
        return false
    }

    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }

    return true
}

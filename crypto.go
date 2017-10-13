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
    "os"
    "crypto/aes"
    "crypto/md5"
    "crypto/rand"
    "io"
    "crypto/cipher"
    "bytes"
    "encoding/gob"
)

const AES_KEY_SEED string = "b1ec0efec8bf032e586ffd4071b79757"
const STATUS_OK int = 0
const STATUS_FAIL int = -1

type aes_header struct {
    plaintext_sum [16]byte
    orig_len uint
    iv [16]byte
}

func AES128CBC_Encrypt(data []byte, input_key *[]byte) ([]byte, int) {
    var key []byte
    if input_key == nil {
        key = generate_hostname_key()
    } else {
        copy(key[:], *input_key)
    }

    iv, _ := gen_iv()
    header := aes_header {
        plaintext_sum: md5.Sum(data),
        orig_len: uint(len(data)),
        iv: iv,
    }

    serialized_header := func (object interface{}) *bytes.Buffer {
        b := new(bytes.Buffer)
        e := gob.NewEncoder(b)
        if err := e.Encode(object); err != nil {
            return nil /* This should be an assertion -- FIXME */
        }
        return b
    } (header)

    pad := make([]byte, len(data) + /* Padding */ (aes.BlockSize - len(data) % aes.BlockSize))
    copy(pad, data)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, STATUS_FAIL
    }

    ciphertext := make([]byte, len(pad))

    mode := cipher.NewCBCEncrypter(block, header.iv[:])
    mode.CryptBlocks(ciphertext[aes.BlockSize:], pad)

    return ciphertext, STATUS_OK
}

func AES128CBC_Decrypt(data []byte, input_key *[]byte) ([]byte, int) {


    ciphertext := make([]byte, len(data))
    copy(ciphertext, data)

    var key []byte
    if input_key == nil {
        key = generate_hostname_key()
    } else {
        copy(key[:], *input_key)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, STATUS_FAIL
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, STATUS_FAIL
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)

    return ciphertext, STATUS_OK
}

func gen_iv() ([16]byte, int) {
    var iv [16]byte
    if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
        return iv, STATUS_FAIL
    }

    return iv, STATUS_OK
}
func generate_hostname_key() []byte {
    host, _ := os.Hostname()
    host += AES_KEY_SEED

    sum := md5.Sum([]byte(host))
    output := make([]byte, aes.BlockSize)
    copy(output, sum[:])

    return output
}

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
package cryptog

import (
    "os"
    "crypto/aes"
    "crypto/md5"
    "crypto/rand"
    "io"
    "crypto/cipher"
    "bytes"
    "encoding/gob"
    "crypto/rc4"
    "crypto/rsa"
    "github.com/AlexRuzin/util"
)

const AES_KEY_SEED string = "b1ec0efec8bf032e586ffd4071b79757"
const STATUS_OK int = 0
const STATUS_FAIL int = -1

type aes_header struct {
    PlaintextSum [16]byte
    OrigLen uint
    IV [16]byte
}

/* The default initialization vector length for a new RC4 stream */
const RC4_IV_LEN uint = 16

func RC4_Decrypt(data []byte, input_key *[]byte) ([]byte, error) {
    if input_key != nil && (len(*input_key) < 1 || len(*input_key) > 256) || len(data) == 0 {
        return nil, util.RetErrStr("Invalid key length")
    }

    var key []byte
    if input_key == nil {
        key = generate_hostname_key()
    } else {
        key = make([]byte, len(*input_key))
        copy(key, *input_key)
    }

    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, util.RetErrStr("Failed to generate RC4 decryption cipher")
    }

    var decrypted []byte = make([]byte, len(data))
    copy(decrypted, data)

    cipher.XORKeyStream(decrypted, decrypted)

    /* Trash the IV */
    var output []byte = make([]byte, len(data) - int(RC4_IV_LEN))
    copy(output, decrypted[RC4_IV_LEN:])

    return output, nil
}

func RC4_Encrypt(data []byte, input_key *[]byte) ([]byte, error) {
    if input_key != nil && (len(*input_key) < 1 || len(*input_key) > 256) || len(data) == 0 {
        return nil, util.RetErrStr("Invalid key length")
    }

    var key []byte
    if input_key == nil{
        key = generate_hostname_key()
    } else {
        key = make([]byte, len(*input_key))
        copy(key, *input_key)
    }

    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, util.RetErrStr("Failed to generate a new RC4 encryption cipher")
    }

    iv, _ := gen_iv()
    encrypted := bytes.Buffer{}
    encrypted.Write(iv[:])
    encrypted.Write(data)

    var output []byte = make([]byte, encrypted.Len())
    copy(output, encrypted.Bytes())

    cipher.XORKeyStream(output, output)

    return output, nil
}

/* FIXME -- The AES functions are not complete */
func AES128CBC_Encrypt(data []byte, input_key *[]byte) ([]byte, int) {
    var key []byte
    if input_key == nil {
        key = generate_hostname_key()
    } else {
        copy(key[:], *input_key)
    }

    iv, _ := gen_iv()
    header := aes_header {
        PlaintextSum: md5.Sum(data),
        OrigLen: uint(len(data)),
        IV: iv,
    }

    serialized_header := func (object interface{}) []byte {
        b := new(bytes.Buffer)
        e := gob.NewEncoder(b)
        if err := e.Encode(object); err != nil {
            return nil /* This should be an assertion -- FIXME */
        }
        return b.Bytes()
    } (header)

    /* Generate the raw stream that contains the header and data */
    raw_buffer := new(bytes.Buffer)
    raw_buffer.Write(serialized_header)
    raw_buffer.Write(data)

    /* Generates the pad. This is just the header + raw data + a ~16 byte pad (if required) */
    pad := make([]byte, raw_buffer.Len() + /* Header + data */ (aes.BlockSize - raw_buffer.Len() % aes.BlockSize))
    copy(pad, data)

    /* Store the IV as the first block of the ciphertext */
    ciphertext := make([]byte, len(iv) + len(pad))
    copy(ciphertext, iv[:])

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, STATUS_FAIL
    }

    mode := cipher.NewCBCEncrypter(block, header.IV[:])
    mode.CryptBlocks(ciphertext[aes.BlockSize:], pad)

    return ciphertext, STATUS_OK
}

/* FIXME -- The AES functions are not complete */
func AES128CBC_Decrypt(data []byte, input_key *[]byte) ([]byte, int) {
    if len(data) % aes.BlockSize != 0 || len(data) < aes.BlockSize {
        return nil, STATUS_FAIL
    }

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

    iv := ciphertext[:aes.BlockSize]

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(ciphertext, ciphertext)

    _, output := func (data []byte) (*aes_header, []byte) {
        m := new(aes_header)
        b := bytes.Buffer{}
        b.Write(data)
        d := gob.NewDecoder(&b)
        err := d.Decode(m)
        if err != nil {
            return nil, nil
        }
        /* FIXME */
        return nil, nil
    } (ciphertext)

    return output, STATUS_OK
}

func gen_iv() ([RC4_IV_LEN]byte, int) {
    var iv [RC4_IV_LEN]byte
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


func GenerateRSAKeyPair(bitsize int) (public []byte, private *rsa.PrivateKey, err error) {
    reader := rand.Reader
    key, err := rsa.GenerateKey(reader, bitsize)
    if err != nil {
        return nil, nil, err
    }

    /* Encode public key */
    public_key, err := func (key *rsa.PublicKey) ([]byte, error) {
        var out = bytes.Buffer{}

        encoder := gob.NewEncoder(&out)
        err := encoder.Encode(key)
        if err != nil {
            return nil, err
        }

        return out.Bytes(), nil
    } (&key.PublicKey)
    if err != nil {
        return nil, nil, err
    }

    return public_key, key, nil
}

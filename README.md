# cryptog
A cryptographic wrapper library for the Go programming language

## Synopsis

Implements the RC4 and AES wrapper libraries.

## RC4 Wrappers

Each of the RC4 wrappers contain an Initialization Vector (IV) and a constant value that will be checked to maintain data integrity.

## `RC4_PrepareKey()`

This method takes any length key and takes a SHA256 sum of it, making it suitable for the RC4 encrypt/decrypt functions.

```go
func RC4_PrepareKey(key []byte) *[]byte // Return an array containing the SHA256 of the input key
```

## `RC4_Encrypt()`

This method uses the following structure:

`[IV][Constant][Data]`

The `IV` is randomized each time, but if the key is the same, then the `Constant` should be the same, otherwise the `RC4_Decrypt()` method will fail.

Please note that if the `input_key` parameter is nil, then the method will generate its own by calling `generateHostnameKey()`, which will be a key based on the hostname of the system. 

```go
const RC4_IV_LEN uint = 16
var RC4_CONSTANT_VALUE = [4]byte{ 0x40, 0xad, 0x4f, 0x22 }

func RC4_Encrypt(data []byte, input_key *[]byte) ([]byte, error)
```

## `RC4_Decrypt()`

The decrypt method removes the `IV` and `Constant` values, but checks that the `Constant` matches `RC4_CONSTANT_VALUE`, otherwise an error will be thrown.

```go
func RC4_Decrypt(data []byte, input_key *[]byte) ([]byte, error)
```

## `generateHostnameKey()`

This method is used to generate a key based on the hostname of the system. An MD5 sum of the host is taken and returned as a `[]byte` vector.

```go
func generateHostnameKey() []byte
```

## AES Wrappers

```
//TODO
```
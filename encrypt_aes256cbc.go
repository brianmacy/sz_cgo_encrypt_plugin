package main

import (
  "fmt"
  "os"
  "encoding/base64"
	"crypto/aes"
	"crypto/cipher"
)

const signatureConst = "AES256CBC_BASE64"
const envKey = "ENCRYPTION_KEY_BASE64"
const envIV = "ENCRYPTION_IV_BASE64"

var keyValue []byte = nil
var ivValue []byte = nil

type MyCryptor struct {
}

var cryptor SzCryptor = SzCryptor{ methods: &MyCryptor{} }

func (cryptor *MyCryptor) initEncryption() error {
  var key64 = os.Getenv(envKey)
  var iv64 = os.Getenv(envIV)

  if len(key64) == 0 {
    return fmt.Errorf("%w: %s not set in environment", EncPluginError, envKey)
  }
  if len(iv64) == 0 {
    return fmt.Errorf("%w: %s not set in environment", EncPluginError, envIV)
  }

  var err error
  keyValue, err = base64.StdEncoding.DecodeString(key64)
  if err != nil {
    return fmt.Errorf("%w: %s not base64 encoded", EncPluginError, envKey)
  }
  if len(keyValue) != 32 {
    return fmt.Errorf("%w: %s must be 32bytes", EncPluginError, envKey)
  }

  ivValue, err = base64.StdEncoding.DecodeString(iv64)
  if err != nil {
    return fmt.Errorf("%w: %s not base64 encoded", EncPluginError, envIV)
  }
  if len(ivValue) != aes.BlockSize {
    return fmt.Errorf("%w: %s must be %d bytes but is %d bytes", EncPluginError, envIV, aes.BlockSize, len(ivValue))
  }


  _, err = aes.NewCipher(keyValue)
  if err != nil {
    return fmt.Errorf("%w: failed aes NewCipher", EncPluginError)
  }

  return nil
}


func (cryptor *MyCryptor) closeEncryption() error {
  keyValue = nil
  ivValue = nil

  return nil
}


func (cryptor *MyCryptor) signatureValue() string {
  return signatureConst;
}

// This could just call encryptDeterministic if it is the same
func (cryptor *MyCryptor) encrypt(rawtext string, maxLen int) (string, error) {
  return cryptor.encryptDeterministic(rawtext, maxLen)
}

func (cryptor *MyCryptor) encryptDeterministic(rawtext string, maxLen int) (string, error) {
  plaintext := []byte(rawtext)
  block, err := aes.NewCipher(keyValue)
  if err != nil {
    return "", fmt.Errorf("%w: failed aes NewCipher", EncPluginError)
  }

	stream := cipher.NewCFBEncrypter(block, ivValue)
  stream.XORKeyStream(plaintext, plaintext)
  encStr := base64.RawStdEncoding.EncodeToString(plaintext)

  if len(encStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }

//  fmt.Fprintf(os.Stderr, "encrypted: input [%s] output [%s]\n", rawtext, encStr)
  return encStr, nil 
}

// This could just call decryptDeterministic if it is the same
func (cryptor *MyCryptor) decrypt(encrypted string, maxLen int) (string, error) {
  return cryptor.decryptDeterministic(encrypted, maxLen)
}

func (cryptor *MyCryptor) decryptDeterministic(encrypted string, maxLen int) (string, error) {
//  fmt.Fprintf(os.Stderr, "decrypting: encrypted [%s]\n", encrypted)
  cipherText, err := base64.RawStdEncoding.DecodeString(encrypted)

  if err != nil {
    return "", fmt.Errorf("%w: Invalid encrypted value", EncPluginError)
  }

  block, err := aes.NewCipher(keyValue)
  if err != nil {
    return "", fmt.Errorf("%w: failed aes NewCipher", EncPluginError)
  }

	stream := cipher.NewCFBDecrypter(block, ivValue)
  stream.XORKeyStream(cipherText,cipherText)

  decStr := string(cipherText)
  if len(decStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }

//  fmt.Fprintf(os.Stderr, "decrypted: input [%s] output [%s]\n", encrypted, decStr)
  return decStr, nil
}


package main

import (
  "errors"
  "fmt"
)

var EncPluginError = errors.New("general encryption plugin error")
var EncPluginBufferTooSmall = fmt.Errorf("%w: buffer too small", EncPluginError)

type EncryptionMethods interface {
  initEncryption() error
  closeEncryption() error
  signatureValue() string
  encrypt(clearText string, maxClearTextLen int) (string, error)
  encryptDeterministic(clearText string, maxClearTextLen int) (string, error)
  decrypt(clearText string, maxClearTextLen int) (string, error)
  decryptDeterministic(clearText string, maxClearTextLen int) (string, error)
}

type SzCryptor struct {
  methods EncryptionMethods
}

// the implementing module should declare
//var cryptor SzCryptor = SzCryptor{ methods: &MyCryptor{} }


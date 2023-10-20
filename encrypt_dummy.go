package main

import (
  "strings"
  "fmt"
)

const signatureConst = "LoVeToHaCk" // dummy test string to encrypt
const encPrefix = "ENC:"
const deterministicEncPrefix = "DETERMINIST_ENC:"

type MyCryptor struct {
}

var cryptor SzCryptor = SzCryptor{ methods: &MyCryptor{} }

func (cryptor *MyCryptor) initEncryption() error {
  //STUB IMPLEMENT
  return nil
}


func (cryptor *MyCryptor) closeEncryption() error {
  //STUB IMPLEMENT
  return nil
}


func (cryptor *MyCryptor) signatureValue() string {
  return signatureConst;
}

// This could just call encryptDeterministic if it is the same
func (cryptor *MyCryptor) encrypt(rawtext string, maxLen int) (string, error) {
  //STUB IMPLEMENT
  encStr := encPrefix+rawtext
  if len(encStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }
  return encStr, nil
}

func (cryptor *MyCryptor) encryptDeterministic(rawtext string, maxLen int) (string, error) {
  //STUB IMPLEMENT
  encStr := deterministicEncPrefix+rawtext
  if len(encStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }
  return encStr, nil 
}

// This could just call decryptDeterministic if it is the same
func (cryptor *MyCryptor) decrypt(encrypted string, maxLen int) (string, error) {
  //STUB IMPLEMENT
  if !strings.HasPrefix(encrypted,encPrefix) {
    return "", fmt.Errorf("%w: Invalid encrypted value", EncPluginError)
  }

  decStr := strings.TrimPrefix(encrypted,encPrefix)
  if len(decStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }
  return decStr, nil
}

func (cryptor *MyCryptor) decryptDeterministic(encrypted string, maxLen int) (string, error) {
  //STUB IMPLEMENT
  if !strings.HasPrefix(encrypted,deterministicEncPrefix) {
    return "", fmt.Errorf("%w: Invalid encrypted value", EncPluginError)
  }

  decStr := strings.TrimPrefix(encrypted,deterministicEncPrefix)
  if len(decStr) > maxLen {
    return "", EncPluginBufferTooSmall
  }
  return decStr, nil
}


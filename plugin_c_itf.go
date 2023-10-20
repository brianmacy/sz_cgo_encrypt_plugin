package main  
/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
  "os"
  "fmt"
  "unsafe"
  "errors"
)


func errorToCode(err error) int {
  if errors.Is(err, EncPluginBufferTooSmall) {
    return -5
  } else {
    return -1
  }
}


//int G2Encryption_InitPlugin(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_InitPlugin
func G2Encryption_InitPlugin(nothing *C.int, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  err := cryptor.methods.initEncryption()

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  return 0
}

//int G2Encryption_ClosePlugin(char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_ClosePlugin
func G2Encryption_ClosePlugin(error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  err := cryptor.methods.closeEncryption()

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  return 0
}

//int G2Encryption_GetSignature(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_GetSignature
func G2Encryption_GetSignature(signature *C.char, maxSignatureSize C.size_t, signatureSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  encStr, err := cryptor.methods.encryptDeterministic(cryptor.methods.signatureValue(), int(maxSignatureSize))

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()

    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  encLen := C.size_t(len(encStr))
  s := C.CString(encStr)
  defer C.free(unsafe.Pointer(s))
  C.memcpy(unsafe.Pointer(signature), unsafe.Pointer(s), encLen)
  *signatureSize = encLen

  return 0
}

//int G2Encryption_ValidateSignatureCompatibility(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_ValidateSignatureCompatibility
func G2Encryption_ValidateSignatureCompatibility(signatureToValidate *C.char, signatureToValidateSize C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {

  encStr, err := cryptor.methods.encryptDeterministic(cryptor.methods.signatureValue(), 100*1024)

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  sigLen:= C.size_t(len(encStr))
  if signatureToValidateSize != sigLen {
    return -1;
  }

  s := C.CString(encStr)
  defer C.free(unsafe.Pointer(s))
  return C.memcmp(unsafe.Pointer(signatureToValidate), unsafe.Pointer(s), sigLen)
}


//int G2Encryption_EncryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_EncryptDataField
func G2Encryption_EncryptDataField(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  encStr, err :=  cryptor.methods.encrypt(C.GoStringN(input, C.int(inputSize)), int(maxResultSize))

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    fmt.Fprintf(os.Stderr, "Encryption Error: input [%s] error [%s]\n", input, errStr)
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  encLen := C.size_t(len(encStr))
  s := C.CString(encStr)
  defer C.free(unsafe.Pointer(s))
  C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), encLen)
  *resultSize = encLen

  return 0
}

//int G2Encryption_DecryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_DecryptDataField
func G2Encryption_DecryptDataField(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  decStr, err :=  cryptor.methods.decrypt(C.GoStringN(input, C.int(inputSize)), int(maxResultSize))

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    fmt.Fprintf(os.Stderr, "Decryption Error: input [%s] error [%s]\n", input, errStr)
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  decLen := C.size_t(len(decStr))
  s := C.CString(decStr)
  defer C.free(unsafe.Pointer(s))
  C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), decLen)
  *resultSize = decLen

  return 0
}


//int G2Encryption_EncryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_EncryptDataFieldDeterministic
func G2Encryption_EncryptDataFieldDeterministic(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  encStr, err :=  cryptor.methods.encryptDeterministic(C.GoStringN(input, C.int(inputSize)), int(maxResultSize))

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  encLen := C.size_t(len(encStr))
  s := C.CString(encStr)
  defer C.free(unsafe.Pointer(s))
  C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), encLen)
  *resultSize = encLen

  return 0
}

//int G2Encryption_DecryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_DecryptDataFieldDeterministic
func G2Encryption_DecryptDataFieldDeterministic(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  decStr, err :=  cryptor.methods.decryptDeterministic(C.GoStringN(input, C.int(inputSize)), int(maxResultSize))

  if err != nil {
    errCode := errorToCode(err)
    errStr := err.Error()
    errLen := C.size_t(len(errStr))
    s := C.CString(errStr)
    defer C.free(unsafe.Pointer(s))
    C.memcpy(unsafe.Pointer(error_msg), unsafe.Pointer(s), errLen)
    *errorSize = errLen
    return C.int(errCode)
  }

  decLen := C.size_t(len(decStr))
  s := C.CString(decStr)
  defer C.free(unsafe.Pointer(s))
  C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), decLen)
  *resultSize = decLen

  return 0
}


func main() { }


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
  "runtime"
  "strings"
)

var _SIGNATURE = "LoVeToHaCk"
var _ENC_PREFIX = "DETERMINIST_ENC:"
var _ENC_PREFIX_LEN = C.size_t(len(_ENC_PREFIX))


//int G2Encryption_InitPlugin(const struct CParameterList* configParams, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_InitPlugin
func G2Encryption_InitPlugin(nothing *C.int, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_InitPlugin\n")
  return 0
}

//int G2Encryption_ClosePlugin(char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_ClosePlugin
func G2Encryption_ClosePlugin(error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_ClosePlugin\n")
  return 0
}

//int G2Encryption_GetSignature(char *signature, const size_t maxSignatureSize, size_t* signatureSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_GetSignature
func G2Encryption_GetSignature(signature *C.char, maxSignatureSize C.size_t, signatureSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_GetSignature\n")
  sigLen:= C.size_t(len(_SIGNATURE))
  if sigLen > maxSignatureSize {
    return -5
  }

 	s := C.CString(_SIGNATURE)
	defer C.free(unsafe.Pointer(s))
	C.memcpy(unsafe.Pointer(signature), unsafe.Pointer(s), sigLen)
  *signatureSize = sigLen
  return 0
}

//int G2Encryption_ValidateSignatureCompatibility(const char *signatureToValidate, const size_t signatureToValidateSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_ValidateSignatureCompatibility
func G2Encryption_ValidateSignatureCompatibility(signatureToValidate *C.char, signatureToValidateSize C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_ValidateSignatureCompatibility\n")

  sigLen:= C.size_t(len(_SIGNATURE))
  if signatureToValidateSize != sigLen {
    return -1;
  }

 	s := C.CString(_SIGNATURE)
	defer C.free(unsafe.Pointer(s))
	return C.memcmp(unsafe.Pointer(signatureToValidate), unsafe.Pointer(s), sigLen)
}


//int G2Encryption_EncryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_EncryptDataField
func G2Encryption_EncryptDataField(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_EncryptDataField\n")
  return G2Encryption_EncryptDataFieldDeterministic(input, inputSize, result, maxResultSize, resultSize, error_msg, maxErrorSize, errorSize);
}

//int G2Encryption_DecryptDataField(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_DecryptDataField
func G2Encryption_DecryptDataField(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  fmt.Fprintf(os.Stderr, "G2Encryption_DecryptDataField\n")
  return G2Encryption_DecryptDataFieldDeterministic(input, inputSize, result, maxResultSize, resultSize, error_msg, maxErrorSize, errorSize);
}


//int G2Encryption_EncryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_EncryptDataFieldDeterministic
func G2Encryption_EncryptDataFieldDeterministic(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  runtime.LockOSThread()
  fmt.Fprintf(os.Stderr, "G2Encryption_EncryptDataFieldDeterministic\n")
  encStr := _ENC_PREFIX + C.GoStringN(input, C.int(inputSize))
  encLen := C.size_t(len(encStr))
  fmt.Fprintf(os.Stderr, "G2Encryption_EncryptDataFieldDeterministic: %s %d/%d\n", encStr, encLen, maxResultSize)

  if encLen > maxResultSize {
    return -5
  }

 	s := C.CString(encStr)
	defer C.free(unsafe.Pointer(s))
	C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), encLen)
  *resultSize = encLen

  return 0
}

//int G2Encryption_DecryptDataFieldDeterministic(const char *input, const size_t inputSize, char *result, const size_t maxResultSize, size_t* resultSize, char *error, const size_t maxErrorSize, size_t* errorSize);
//export G2Encryption_DecryptDataFieldDeterministic
func G2Encryption_DecryptDataFieldDeterministic(input *C.char, inputSize C.size_t, result *C.char, maxResultSize C.size_t, resultSize *C.size_t, error_msg *C.char, maxErrorSize C.size_t, errorSize *C.size_t) C.int {
  runtime.LockOSThread()
  fmt.Fprintf(os.Stderr, "G2Encryption_DecryptDataFieldDeterministic\n")

  decStr := C.GoStringN(input, C.int(inputSize))
  decStr = strings.TrimPrefix(decStr, _ENC_PREFIX);

  decLen := C.size_t(len(decStr))
  fmt.Fprintf(os.Stderr, "G2Encryption_DecryptDataFieldDeterministic: %s %d/%d\n", decStr, decLen, maxResultSize)

  if decLen > maxResultSize {
    return -5
  }

 	s := C.CString(decStr)
	defer C.free(unsafe.Pointer(s))
	C.memcpy(unsafe.Pointer(result), unsafe.Pointer(s), decLen)
  *resultSize = decLen

  return 0
}



func main() { }

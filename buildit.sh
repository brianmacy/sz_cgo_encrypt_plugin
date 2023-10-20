go build -buildmode c-shared -o libsz_cgo_dummy.so encrypt_dummy.go plugin_c_itf.go encrypt_itf.go
go build -buildmode c-shared -o libsz_cgo_aes256cbc.so encrypt_aes256cbc.go plugin_c_itf.go encrypt_itf.go


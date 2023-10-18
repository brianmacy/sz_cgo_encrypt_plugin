# sz_cgo_encrypt_plugin
An attempt at building a Senzing encryption plugin with CGo.  It seems to work and just needs some real encryption code put in it.

```
./buildit.sh
```
I haven't done a real make system.

Then add it to your LD_LIBRARY_PATH and add the appropriate configuration to your Senzing JSON config on your init call.
{"DATA_ENCRYPTION":{"ENCRYPTION_PLUGIN_NAME"="sz_cgo_encrypt_plugin"}}

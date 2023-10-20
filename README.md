# sz_cgo_encrypt_plugin
An attempt at building a Senzing encryption plugin with CGo.  It seems to work and just needs some real encryption code put in it.

```
./buildit.sh
```
I haven't done a real make system.

Then add it to your LD_LIBRARY_PATH and add the appropriate configuration to your Senzing JSON config on your init call.
{"DATA_ENCRYPTION":{"ENCRYPTION_PLUGIN_NAME":"sz_cgo_dummy_plugin"}}

If your encryption returns something that is UTF-8/ASCII encoded then you can make that:
{"DATA_ENCRYPTION":{"ENCRYPTION_PLUGIN_NAME":"sz_cgo_dummy_plugin","BASE64_ENCODING":"N"}}

### To write your own plugin:
 * clone/fork/copy this repository
 * copy encrypt_dummy.go to a sensible name and implement the functions in it
 * change the build so it uses your new file instead of the dummy one and give the output library a sensible name that follows lib*so format
 * change your Senzing configuration based on the new name


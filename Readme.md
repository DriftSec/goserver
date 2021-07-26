

## GoServer
### Alternative to python SimpleHTTPServer for using in red teaming.
 - Dump the full request to view cookies, headers and POST data.
 - Supports File uploads for data exfiltration
 - Supports Basic Auth
 - Supports SSL

### Usage
```
Usage of goserver:
  -addr string
    	Listen address
  -auth string
    	Enable basic auth (-auth user:password)
  -cert string
    	Path to SSL .crt file
  -dir string
    	Working directory (default "./")
  -dump
    	dump full requests
  -key string
    	Path to SSL .key file
  -port string
    	Listen port (default "8000")
  -ssl
    	Enable TLS/SSL, requires -key and -cert
```
##### Example

Listen on 127.0.0.1:3001, with a working directory of /tmp, dump raw requests, and require auth.

```
goserver -addr 127.0.0.1 -port 3001 -dir /tmp -dump -auth user:passwerd
```
![Alt text](./misc/img.png?raw=true "Example")

### Uploads
/loot accepts multipart form file uploads. Files are stored in ./ unless -dir is set.

##### Example
```
curl -F 'file=@/tmp/test.txt' http://user:passwerd@127.0.0.1:3001/loot
```
![Alt text](./misc/im-upload.png?raw=true "Upload")

### Special Parameters
 - POST/GET parameter "base64": will base64 decode the parameters data and display it as normal text (only if using -dump).
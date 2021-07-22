```
Usage of goserver:
  -addr string
    	Listen address
  -dir string
    	Working directory (default "./")
  -dump
    	dump full requests
  -port string
    	Listen port (default "8000")
```
### Example
```
go run main.go -addr 127.0.0.1 -port 3001 -dir /tmp -dump
```

### uploads:
    /loot accepts uploads 
```
    curl -F 'file=@./test.txt' http://127.0.0.1:3001/loot```


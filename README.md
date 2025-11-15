# PORT SCANNER 
### Port Scanner menggunakan Python 

## USAGE :
1. Jalankan Perintah ini 
``python super_scanner.py <host/url> <mode> [start] [end]``

## Available Mode :
-  top        → scan top ports (nmap style)
- full       → scan port 1–65535
- range      → scan port sesuai range
- web        → cek status HTTP & SSL

## Examples :
 - python super_scanner.py google.com top
 - python super_scanner.py example.com full
 - python super_scanner.py test.com range 1 1000
 - python super_scanner.py https://example.com web

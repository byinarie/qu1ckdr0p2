import hashlib
from flask import Flask, send_from_directory
from flask import render_template_string
from tqdm import tqdm
from OpenSSL import crypto
import os
import netifaces as ni
import logging
import click
import configparser
import requests
import subprocess

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

user_home = os.path.expanduser("~")
base_dir = os.path.join(user_home, ".qu1ckdr0p2")
directory = os.path.dirname(os.path.abspath(__file__))

target_directories = ["config", "windows", "linux", "mac"]
other_directories = ["payloads", "certs"]

payloads = os.path.join(user_home, ".qu1ckdr0p2", 'payloads')
cert_dir = os.path.join(user_home, ".qu1ckdr0p2", 'certs')

cert_path = os.path.join(cert_dir, 'cert.pem')
key_path = os.path.join(cert_dir, 'key.pem')
cert = "cert.pem"
privkey = "key.pem"

config = configparser.ConfigParser()
common_ini_path = os.path.join(base_dir, 'config/common.ini')
config = configparser.ConfigParser()
config.read(common_ini_path)
aliases = {}
for section in config.sections():
    for key, value in config.items(section):
        aliases[key.lower()] = os.path.join(base_dir, value)
                
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

def print_server_info(path_to_serve, protocol, ip_address, interface_name, port, filename, cert=None, privkey=None):
    relative_path = os.path.relpath(path_to_serve, start=base_dir)  
    
    click.echo(click.style(f"\n[→] ", fg='green') + click.style("Serving:", fg='yellow') + click.style(f" {relative_path}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("Protocol:", fg='yellow') + click.style(f" {protocol}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("IP address:", fg='yellow') + click.style(f" {ip_address}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("Port:", fg='yellow') + click.style(f" {port}", fg='blue'))    
    click.echo(click.style(f"[→] ", fg='green') + click.style("Interface:", fg='yellow') + click.style(f" {interface_name}", fg='blue'))
    if cert and privkey:
        click.echo(click.style(f"[→] ", fg='green') + click.style("Using cert:", fg='yellow') + click.style(f" {cert}", fg='blue'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Using key:", fg='yellow') + click.style(f" {privkey}", fg='blue'))
    click.echo(click.style(f"[→] ", fg='green') + click.style("CTRL+C to quit\n", fg='yellow'))
    click.echo(click.style(f"\n[→] ", fg='green') + click.style("URL:", fg='yellow') + click.style(f" {protocol}://{ip_address}:{port}/{filename}\n\n", fg='blue'))
    
def serve_files(path_to_serve, http_port=80, https_port=443):
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
    protocol = "http" if http_port else "https"
    
    cert_path, key_path = None, None
    if https_port:
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        
    print_server_info(path_to_serve, protocol, ip_address, interface_name, port, filename, cert_path, key_path)
    
    if http_port:
        app.run(host='0.0.0.0', port=http_port)
    elif https_port:
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        if cert_path and key_path:
            app.run(host='0.0.0.0', port=https_port, ssl_context=(cert_path, key_path))
        else:
            click.echo(click.style(f"\n[!] ", fg='red') + click.style("Could not generate or find SSL certificates.\n", fg='yellow'))

def invoke_serve_by_number(search=None, use=None, http=None, https=None):
    search_results = {alias: path for alias, path in aliases.items() if search.lower() in alias.lower() or search.lower() in path.lower()}
    if use > len(search_results) or use < 1:
        click.echo(click.style(f"\n[!] ", fg='red') + click.style("The number provided with --use is out of range.\n", fg='yellow'))
        return
    
    selected_alias = list(search_results.keys())[use - 1]
    selected_path = search_results[selected_alias]
    
    # Default to HTTPS on port 443 if no port is specified
    if not http and not https:
        https = 443
    
    serve_files(selected_path, http, https)
    
    selected_alias = list(search_results.keys())[use - 1]
    selected_path = search_results[selected_alias]
    serve_files(selected_path, http, https)

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
        click.echo(click.style('[!] ', fg='red') + click.style('Debug mode enabled', fg='red', blink=True, bold=True))
          
@cli.command(context_settings={"help_option_names": ['-h', '--help']})
@click.option('-l', '--list', 'list_flag', is_flag=True, help="List aliases")
@click.option('-s', '--search', type=str, required=False, help="Search query for aliases")
@click.option('-u', '--use', type=int, required=False, help="Use an alias by a dynamic number")
@click.option('-d', '--directory', type=click.Path(exists=True, file_okay=False), help="Serve a directory")
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help="Serve a file")
@click.option('--http', type=int, default=None, help="Use HTTP with a custom port")
@click.option('--https', type=int, default=None, help="Use HTTPS with a custom port")
@click.pass_context
def serve(ctx, list_flag, search, use, directory, file, http, https):
    """Serve files."""          
    if not any([list_flag, search, use, directory, file, http, https]):
        print("No options provided. Displaying help:")
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
        click.echo(click.style(f"\n[!] ", fg='red') + click.style("You must provide a search term along with --use.\n", fg='yellow'))
        return

    if directory:
        if not http and not https:
            https = 443  
        serve_files(directory, http, https)
        return

    if file:
        if not http and not https:
            https = 443  
        serve_files(file, http, https)
        return

def create_directory(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        click.echo(click.style(f"[→] ", fg='green') + click.style("Created directory:", fg='yellow') + click.style(f" {dir_path}", fg='blue'))

def handle_github_auth(api_key):
    if api_key:
        click.echo(click.style(f"[→] Using Github API key for authentication", fg='green'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Using Github API key for authentication", fg='yellow'))
        click.echo(click.style(f"[→] ", fg='green') + click.style("Github API key:", fg='yellow') + click.style(f" {api_key}", fg='blue'))
    else:
        click.echo(click.style(f"[-] ", fg='red') + click.style("No Github API key provided", fg='yellow'))
        click.echo(click.style(f"[-] ", fg='red') + click.style("No Github API key provided", fg='yellow'))
        click.echo(click.style(f"[-] ", fg='red') + click.style("No Github API key provided", fg='yellow'))
        click.echo(click.style(f"[-] ", fg='red') + click.style("No Github API key provided", fg='yellow'))

def handle_directory(directory, headers, check):
    target_path = os.path.join(base_dir, directory)
    target_url = f"https://api.github.com/repos/byinarie/qu1ckdr0p2/contents/qu1ckdr0p2/{directory}"
            
    response = requests.get(target_url, headers=headers)
    if response.status_code != 200:
        click.echo(click.style(f"[-] ", fg='red') + click.style("Failed to fetch directory contents", fg='yellow') + click.style(f" {target_url}", fg='blue') + click.style(f" Status Code: {response.status_code}, Reason: {response.reason}", fg='yellow'))
        return

    files = response.json()
    local_files = list_local_files(target_path)
    
    for file_info in files:
        if file_info['type'] != 'file':
            continue
        file_name = file_info['name']
        file_url = file_info.get('download_url')
        if not file_url:
            click.echo(click.style(f"[-] ", fg='red') + click.style("Download URL not found", fg='yellow') + click.style(f" {file_name}\n\n", fg='blue'))
            continue
        file_path = os.path.join(target_path, file_name)
        if check:
            if file_name not in local_files:
                download_and_save_file(file_url, file_path)
            else:
                with open(file_path, 'rb') as f:
                    existing_content = f.read()
                existing_sha1 = calculate_git_blob_sha1(existing_content)
                expected_sha1 = file_info.get('sha')
                if existing_sha1 != expected_sha1:
                    download_and_save_file(file_url, file_path)
                    click.echo(click.style(f"[→] ", fg='green') + click.style("Updated: ", fg='yellow') + click.style(f" {file_url}\n\n", fg='blue'))
        else:
            download_and_save_file(file_url, file_path)
                
def download_and_save_file(url, file_path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(file_path, 'wb') as f:
            f.write(response.content)
            click.echo(click.style(f"[→] ", fg='green') + click.style("Downloaded", fg='yellow') + click.style(f" {file_path}\n\n", fg='blue'))
    else:
        click.echo(click.style(f"[-] ", fg='red') + click.style("Failed to download", fg='yellow') + click.style(f" {file_path}\n\n", fg='blue'))

def calculate_git_blob_sha1(data):
    content_length = len(data)
    return hashlib.sha1(f'blob {content_length}\0'.encode() + data).hexdigest()

def list_local_files(directory_path):
    return set(os.listdir(directory_path))

def update_self_function():
    try:
        subprocess.run(['pip', 'install', '--upgrade', 'qu1ckdr0p2'], check=True)
        click.echo(click.style(f"[→] ", fg='green') + click.style("Successfully updated qu1ckdr0p2\n\n", fg='blue'))
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"[→] ", fg='red') + click.style("Failed to update {e}\n\n", fg='red'))

def example():
    examples = [
        {
            "command": "serve --search seatbelt",
            "description": "Searches for aliases containing the word 'seatbelt'."
        },
        {
            "command": "serve --search seatbelt -u ",
            "description": "Searches for aliases containing the word 'seatbelt'."
        },
        {
            "command": "serve --search seatbelt -u 3",
            "description": "Uses the 3rd alias from the search results for 'seatbelt'."
        },
        {
            "command": "serve [-f, -d, --search --https 9000",
            "description": "Serves using HTTPS on port 9000."
        },
        {
            "command": "serve --http 8000",
            "description": "Serves using HTTP on port 8000."
        },
        {
            "command": "serve -d /path/to/directory",
            "description": "Serves a directory located at '/path/to/directory'."
        },
        {
            "command": "serve -f /path/to/file",
            "description": "Serves a file located at '/path/to/file'."
        }
    ]
    
    click.echo(click.style(f"[→] ", fg='green') + click.style("Examples:\n", fg='green'))
    for example in examples:
        click.echo(click.style(f"[→] ", fg='green') + click.style("Command:\n  {example['command']}", fg='green'))
        click.echo(click.style(f"[→] Description:\n  {example['description']}", fg='yellow'))
        click.echo(click.style(f"'-' * 50", fg='yellow'))
        
@cli.command()
@click.option('--check', is_flag=True, help='Check and download missing or outdated files.')
@click.option('--skip-config', is_flag=True, help='Skip checking the config directory.')
@click.option('--skip-windows', is_flag=True, help='Skip checking the windows directory.')
@click.option('--skip-linux', is_flag=True, help='Skip checking the linux directory.')
@click.option('--skip-mac', is_flag=True, help='Skip checking the mac directory.')
@click.option('--api-key', help='Github API key for authentication')
@click.option('--update-self', is_flag=True, help='Update the tool using pip.')
@click.option('--update-self-test', is_flag=True, help='Used for dev testing, installs unstable build.')
def init(check, skip_config, skip_windows, skip_linux, skip_mac, api_key, update_self, update_self_test):
    """Configure or update."""
    if update_self:
        subprocess.run(["pip", "install", "--upgrade", "your-package-name"])
    elif update_self_test:
        subprocess.run(["pip", "install", "--index-url", "https://test.pypi.org/legacy/", "--upgrade", "your-package-name-test"])
    else:
        create_directory(base_dir)
    
    skip_directories = []
    if skip_config: skip_directories.append("config")
    if skip_windows: skip_directories.append("windows")
    if skip_linux: skip_directories.append("linux")
    if skip_mac: skip_directories.append("mac")

    all_directories = target_directories + other_directories
    for dir_name in all_directories:
        if dir_name in skip_directories:
            continue
        full_path = os.path.join(base_dir, dir_name)
        create_directory(full_path)
    
    headers = {'Authorization': f'token {api_key}'} if api_key else None
    handle_github_auth(api_key)
    
    for directory in target_directories:
        if directory in skip_directories:
            continue
        handle_directory(directory, headers, check)
                                    
if __name__ == "__main__":
    target_directory = os.path.dirname(os.path.abspath(__file__))   
    cli(obj={})

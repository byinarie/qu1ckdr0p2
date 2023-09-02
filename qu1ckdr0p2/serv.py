import hashlib
from flask import Flask, send_from_directory
from tqdm import tqdm
from OpenSSL import crypto
import os
import netifaces as ni
import logging
import click
import configparser
import requests
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor

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


config = configparser.ConfigParser()
common_ini_path = os.path.join(base_dir, 'config/common.ini')
config.read(common_ini_path)
@click.group()
def cli():
    pass

          
def get_interface_ip(interface):
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip
    except Exception as e:
        return None

def get_serving_ip():
    tun0_ip = get_interface_ip('tun0')
    if tun0_ip:
        return tun0_ip
    eth0_ip = get_interface_ip('eth0')
    if eth0_ip:
        return eth0_ip
    return '0.0.0.0'

@cli.command()
@click.option('--list', 'list_flag', is_flag=True, help="List aliases")
@click.option('--search', type=str, required=False, metavar='TOOL', help="Search query for aliases")
@click.option('-u', '--use', metavar='TOOL USE NUMBER', type=int, help="Use an alias by a dynamic number")
@click.option('-d', '--directory', type=click.Path(exists=True, file_okay=False),help="Serve a directory")
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False),help="Serve a file")
@click.option('--https', type=click.STRING, metavar='HTTPS PORT', default=None, help="Use HTTPS with a custom port")
@click.option('--http', type=click.STRING, metavar='HTTPS PORT', default=None, help="Use HTTP with a custom port")
def serve(search, list_flag, use, directory, file, https, http):
    """Serve a file over HTTP or HTTPS."""
    if list_flag:
        if use:
            invoke_serve_by_number(search, use, https=https is not None, port=int(https) if https else 443)
        else:
            display_aliases(search)
        return

    if use and not search:
        click.echo("The --use option requires --search to be specified.")
        return

    if use and search:
        alias = f"{search}{use}"

    if directory and file:
        click.echo("Please provide either a directory path or a file path, not both.")
        return

    if https:
        if https.isnumeric():
            port = int(https)
        else:
            click.echo("--https should either be a flag or followed by a port number.")
            return
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        ssl_context = (cert_path, key_path)
    elif http:
        if http.isnumeric():
            port = int(http)
        else:
            click.echo("--http should either be a flag or followed by a port number.")
            return
    else:
        port = 443
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        ssl_context = (cert_path, key_path)

def generate_self_signed_cert(cert_dir):
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "CA"
        cert.get_subject().L = "San Francisco"
        cert.get_subject().O = "qu1ckdr0p2"
        cert.get_subject().OU = "qu1ckdr0p2"
        cert.get_subject().CN = "byinarie@deadcell.dev"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)  # Valid for 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(cert_path, 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        with open(key_path, 'wb') as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

            click.echo(click.style(f"[+] ", fg='green') + click.style(f"Certificate and key generated at: ", fg='yellow') + click.style(f"{cert_dir}\n", fg='blue'))
            click.echo(click.style(f"[>] ", fg='green') + click.style(f"Certificate: ", fg='yellow') + click.style(f"{cert_path}", fg='blue'))
            click.echo(click.style(f"[>] ", fg='green') + click.style(f"Key: ", fg='yellow') + click.style(f"{key_path}\n", fg='blue'))


    return cert_path, key_path

def serve_files(path_to_serve, https=True, port=443, ssl_context=None):
    ip_address = get_serving_ip()
    protocol = 'https' if https else 'http'
    app = Flask(__name__)

    if os.path.isdir(path_to_serve):
        click.echo(click.style(f"[+] Using certificate: {cert_path}", fg='green'))
        click.echo(click.style(f"[+] Using key: {key_path}", fg='green'))
        click.echo(f"Serving at {protocol}://{ip_address}:{port}/")
        for filename in os.listdir(path_to_serve):
            click.echo(f"{protocol}://{ip_address}:{port}/{filename}")
    else:
        filename = os.path.basename(path_to_serve)
        click.echo(f"Serving at {protocol}://{ip_address}:{port}/{filename}")

    @app.route('/<path:filename>')
    def serve_directory(filename):
        if os.path.isdir(path_to_serve):
            full_path = os.path.join(path_to_serve, filename)
        else:
            full_path = path_to_serve if filename == os.path.basename(path_to_serve) else None
        if full_path and os.path.exists(full_path):
            return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path))
        return "File not found", 404

    app.run(host='0.0.0.0', port=port, ssl_context=ssl_context)

def list_aliases(search, use, port):
    if use:
        invoke_serve_by_number(search, use, port=port)
    else:
        display_aliases(search)

def invoke_serve_by_number(search=None, use=None, https=True, port=443):
    counter = 1
    selected_alias = None
    for section in config.sections():
        for key, value in config.items(section):
            alias_name = key
            alias_path = os.path.join(base_dir, value)
            if search:
                search_lower = search.lower()
                if not (search_lower in alias_name.lower() or search_lower in alias_path.lower()):
                    continue
            if counter == use:
                selected_alias = alias_name
                break
            counter += 1
    if selected_alias:
        dir_section = None
        for section in config.sections():
            if selected_alias in config[section]:
                dir_section = section
                break
        if dir_section:
            relative_path = config.get(dir_section, selected_alias, fallback=None)
            path_to_serve = os.path.join(base_dir, relative_path)
        else:
            click.echo(f"Alias '{selected_alias}' not found in config/common.ini.")
            return
        serve_files(path_to_serve, port=port)


    else:
        click.echo(f"No alias found for the number {use}.")

def display_aliases(search=None):
    counter = 1
    for section in config.sections():
        for key, value in config.items(section):
            alias_name = key
            alias_path = os.path.join(base_dir, value)
            if search:
                search_lower = search.lower()
                if not (search_lower in alias_name.lower() or search_lower in alias_path.lower()):
                    continue
            click.echo(f"Alias: {alias_name}\nPath: {alias_path}\nuse: {counter}^\n-> -u {alias_name}\n")
            counter += 1

                       
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
    """Download missing files, and update outdated files."""
    if update_self:
        subprocess.run(["pip", "install", "--upgrade", "your-package-name"])
    elif update_self_test:
        subprocess.run(["pip", "install", "--index-url", "https://test.pypi.org/simple/", "--upgrade", "your-package-name-test"])
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

def create_directory(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        click.echo(click.style(f"[+] Created directory: {dir_path}", fg='green'))

def handle_github_auth(api_key):
    if api_key:
        click.echo(click.style(f"[+] Using Github API key for authentication", fg='green'))
    else:
        click.echo(click.style(f"[-] No Github API key provided, using unauthenticated requests", fg='yellow'))
        click.echo(click.style(f"[-] Unauthenticated requests are subject to higher limiting: 60/hr.", fg='yellow')) 
        click.echo(click.style(f"[-] You can create a token here: https://github.com/settings/tokens/new", fg='yellow'))
        click.echo(click.style(f"[-] Running init --check or similar will faill without a token.", fg='yellow'))

def handle_directory(directory, headers, check):
    target_path = os.path.join(base_dir, directory)
    target_url = f"https://api.github.com/repos/byinarie/qu1ckdr0p2/contents/qu1ckdr0p2/{directory}"
            
    response = requests.get(target_url, headers=headers)
    if response.status_code != 200:
        click.echo(click.style(f"[-] Failed to fetch directory contents: {target_url}. Status Code: {response.status_code}, Reason: {response.reason}", fg='red'))
        return

    files = response.json()
    local_files = list_local_files(target_path)
    
    for file_info in files:
        if file_info['type'] != 'file':
            continue
        file_name = file_info['name']
        file_url = file_info.get('download_url')
        if not file_url:
            click.echo(click.style(f"[-] Download URL not found for {file_name}", fg='red'))
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
                    click.echo(click.style(f"[+] Updated {file_path}", fg='green'))
        else:
            download_and_save_file(file_url, file_path)
                
def download_and_save_file(url, file_path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(file_path, 'wb') as f:
            f.write(response.content)
            click.echo(click.style(f"[+] Downloaded {file_path}", fg='green'))
    else:
        click.echo(click.style(f"[-] Failed to download {file_path}", fg='red'))

def calculate_git_blob_sha1(data):
    content_length = len(data)
    return hashlib.sha1(f'blob {content_length}\0'.encode() + data).hexdigest()


def list_local_files(directory_path):
    return set(os.listdir(directory_path))

def update_self_function():
    try:
        subprocess.run(['pip', 'install', '--upgrade', 'qu1ckdr0p2'], check=True)
        click.echo(click.style("[+] Successfully updated the tool.", fg='green'))
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"[-] Failed to update the tool: {e}", fg='red'))
        
def example():
    examples = [
        {
            "command": "serve --list",
            "description": "Lists all available aliases."
        },
        {
            "command": "serve --search seatbelt",
            "description": "Searches for aliases containing the word 'seatbelt'."
        },
        {
            "command": "serve --search seatbelt -u 3",
            "description": "Uses the 3rd alias from the search results for 'seatbelt'."
        },
        {
            "command": "serve --https 9000",
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
    
    click.echo("Examples of how to use this tool:\n")
    for example in examples:
        click.echo(click.echo(click.style(f"[+] Command:\n  {example['command']}", fg='green')))
        click.echo(click.echo(click.style(f"[+] Description:\n  {example['description']}", fg='yellow')))
        click.echo('-' * 50)

if __name__ == "__main__":
    target_directory = os.path.dirname(os.path.abspath(__file__))   
    cli()
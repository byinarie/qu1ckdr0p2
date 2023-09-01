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
from concurrent.futures import ThreadPoolExecutor


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
user_home = os.path.expanduser("~")
base_dir = os.path.join(user_home, ".qu1ckdr0p2")

config = configparser.ConfigParser()
common_ini_path = os.path.join(base_dir, 'config/common.ini')
config.read(common_ini_path)
# print(config.sections())
# print(config.items("._DIR"))
# Not sorting out other platforms for now
blacklist_keywords = ['sample', 'arm64', 'readme.md', 'readme', 'license', 'mips', 'mips64', 'mipsle', 'ppc', 's390', 'arm', 'aarch64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv', 'arm64', 'armle', 'armbe', 'armhf', 'armel', 'arm64', 'armv7', 'armv8', 'armv6', 'armv5', 'armv4', 'armv3', 'armv2', 'armv1', 'armv0', 'armv']
@click.group()
def cli():
    pass

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

        click.echo(click.style(f"[+] Certificate and key generated at {cert_path} and {key_path}", fg='green'))

    return cert_path, key_path
          
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
@click.argument('alias', type=str, required=False)
@click.option('-d', '--directory', type=click.Path(exists=True, file_okay=False), help='Path to the directory to serve.')
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Path to the file to serve.')
@click.option('--https', is_flag=True, help='Use HTTPS instead of HTTP.')
@click.option('--port', default=80, help='Port number to run the server on.')
def serve(alias=None, directory=None, file=None, https=False, port=8080):
    global base_dir  # Make sure to use the global base_dir variable

    if directory and file:
        click.echo("Please provide either a directory path or a file path, not both.")
        return

    if https:
        cert_dir = 'certs/'
        cert_path, key_path = generate_self_signed_cert(cert_dir)
        ssl_context = (cert_path, key_path)
    else:
        ssl_context = None

    if directory:
        path_to_serve = directory
    elif file:
        path_to_serve = file
    elif alias:
        dir_section = None
        for section in config.sections():
            if alias in config[section]:
                dir_section = section
                break

        if dir_section:
            relative_path = config.get(dir_section, alias, fallback=None)
            path_to_serve = os.path.join(base_dir, relative_path)  # Use base_dir here
        else:
            click.echo(f"Alias '{alias}' not found in config/common.ini.")
            return
    else:
        path_to_serve = base_dir 

    ip_address = get_serving_ip()
    protocol = 'https' if https else 'http'
    app = Flask(__name__)
    if os.path.isdir(path_to_serve):
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
    app.run(host=ip_address, port=port, ssl_context=ssl_context)

@cli.command(name="list")
@click.option('--search', type=str, help='Search for a specific alias using a search string.')
def list_aliases(search):
    """List all aliases or search for a specific alias."""
    display_aliases(search)  

def display_aliases(search=None):
    for section in config.sections():
        for key, value in config.items(section):
            alias_name = key
            alias_path = os.path.join(base_dir, value)
            if search and (search.lower() not in alias_name.lower() and search.lower() not in alias_path.lower()):
                continue
            click.echo(f"Alias: {alias_name}\nPath: {alias_path}\n")
            
                        
@cli.command()
@click.option('--check', is_flag=True, help='Check and download missing or outdated files.')
@click.option('--skip-config', is_flag=True, help='Skip checking the config directory.')
@click.option('--skip-windows', is_flag=True, help='Skip checking the windows directory.')
@click.option('--skip-linux', is_flag=True, help='Skip checking the linux directory.')
@click.option('--skip-mac', is_flag=True, help='Skip checking the mac directory.')
@click.option('--api-key', help='GitHub API key for authentication')
def init(check, skip_config, skip_windows, skip_linux, skip_mac, api_key):
    user_home = os.path.expanduser("~")
    base_dir = os.path.join(user_home, ".qu1ckdr0p2")
    directory = os.path.dirname(os.path.abspath(__file__))
    target_directories = ["config", "windows", "linux", "mac"]

    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for dir_name in target_directories:
        dir_path = os.path.join(base_dir, dir_name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    click.echo(click.style(f"[+] Directories exist. Continuing.", fg='green'))
    
    
    for target_dir in target_directories:
        full_path = os.path.join(base_dir, target_dir)
        print(full_path)
    
    repo_owner = "byinarie"
    repo_name = "qu1ckdr0p2"
    
    headers = {'Authorization': f'token {api_key}'} if api_key else None
    if api_key:
        click.echo(click.style(f"[+] Using GitHub API key for authentication", fg='green'))
    else:
        click.echo(click.style(f"[-] No GitHub API key provided, using unauthenticated requests", fg='yellow'))
        click.echo(click.style(f"[-] Anauthenticated requests are subject to higher limiting", fg='yellow')) 
        click.echo(click.style(f"[-] You can create a token here: https://github.com/settings/tokens/new", fg='yellow')) 
               
    for directory in target_directories:
        if (skip_config and directory == 'config') or (skip_windows and directory == 'windows') or (skip_linux and directory == 'linux') or (skip_mac and directory == 'mac'):
            continue
        
        target_path = os.path.join(base_dir, directory)
        target_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/qu1ckdr0p2/{directory}"
            
        response = requests.get(target_url, headers=headers)
        if response.status_code != 200:
            click.echo(click.style(f"[-] Failed to fetch directory contents: {target_url}. Status Code: {response.status_code}, Reason: {response.reason}", fg='red'))
            continue

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

if __name__ == "__main__":
    download_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads/')
    target_directory = os.path.dirname(os.path.abspath(__file__))   
    cli()
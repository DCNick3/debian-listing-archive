#!/usr/bin/env python3

import requests
import re
from gzip import GzipFile
from pathlib import PosixPath, Path
import os
import hashlib
from tqdm import tqdm

MIRROR_URL = os.environ.get("MIRROR") or "http://ftp.us.debian.org/debian"
ARCHITECTURES = ["amd64", "i386", "armhf", "arm64", "all"]
CHANNELS = ["main"]
DISTRIBUTIONS = ["stretch", "buster", "bullseye"] # oldoldstable, oldstable and stable (currently). Don't care about other releases

LSLR_DIR_REGEX = re.compile(r"([^:]*):\n(([^\n]+\n)+)(\n|$)")
LSLR_NAME_REGEX = re.compile(r"[sldrwx\-]{10}\s+\d+\s+\w+\s+\w+\s+(\d+)\s+\w+\s+\d+\s+\d+(?::\d+)?\s+((?:(?! -> ).)*)(?: -> (.*))?")
DISTS_DIR_REGEX = re.compile(r"^\./dists/([^/]+)/([^/]+)/binary-([^/]+)$")
BY_HASH_REGEX = re.compile(r"^.*/by-hash/SHA256/([a-f0-9]+)$")

PACKAGES_FILE_NAME = "Packages.xz"

LOCAL_PATH = Path("debian").resolve()

def get_lslr():
    if "LSLR" in os.environ:
        with open(os.environ["LSLR"], 'r') as f:
            return f.read()

    print("Getting the listing...")
    r = requests.get(MIRROR_URL + "/ls-lR.gz", stream=True)
    r.raise_for_status()
    with GzipFile(mode='r', fileobj=r.raw) as f:
        return str(f.read(), 'utf8')
    
def parse_lslr(lslr):
    print("Parsing the listing...")
    res = dict()
    for m in LSLR_DIR_REGEX.finditer(lslr):
        if not m:
            continue
        filename = m.group(1)
        contents = m.group(2)
        res[filename] = contents
    return res

def parse_lslr_files(s):
    res = dict()
    for m in LSLR_NAME_REGEX.finditer(s):
        filename = m.group(2)
        size = int(m.group(1))
        link = m.group(3)
        res[filename] = {"size": size, "target": link}
    return res

lslr = parse_lslr(get_lslr())

def filter_dists_dirs(path):
    res = []
    for x in lslr:
        m = DISTS_DIR_REGEX.match(x)
        if not m:
            continue
        dist = m.group(1)
        channel = m.group(2)
        arch = m.group(3)
        if dist not in DISTRIBUTIONS or channel not in CHANNELS or arch not in ARCHITECTURES:
            continue
        res.append(x)
    return res
    

dists_dirs = filter_dists_dirs(lslr.keys())
dists_dirs = [ x for x in dists_dirs if PACKAGES_FILE_NAME in parse_lslr_files(lslr[x]) ]


dists_paths = [ PosixPath(x) / PACKAGES_FILE_NAME for x in dists_dirs ]

def get_entry(path):
    dirdata = lslr["./" + str(path.parent)]
    direntries = parse_lslr_files(dirdata)
    ent = direntries[path.name]
    return ent

def realpath(path):
    ent = get_entry(path)
    if ent['target']:
        return realpath(path.parent / ent['target'])
    return path

def size(path):
    ent = get_entry(path)
    return ent["size"]

HASH2PATH = dict()

def hash_file(path):
    if not path.is_file():
        return None
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def map_local(path):
    _, distro, channel, arch, _ = path.parts
    filename = f"{distro}-{channel}-{arch.replace('binary-', '')}-Packages.xz"
    return LOCAL_PATH / filename

# we don't do dedup, because it does not happen much that two packages have the same hash
def should_download(pathpair):
    visible, real = pathpair
    hm = BY_HASH_REGEX.match(str(real))
    file_hash = None
    file_hash = hm.group(1)
    HASH2PATH[file_hash] = real
    
    local_hash = hash_file(map_local(visible))
    #print(visible, file_hash, local_hash)
    return local_hash != file_hash


tasks = [ (x, realpath(x)) for x in dists_paths]
tasks = [ item for item in tasks if should_download(item)]
total_size = sum(size(x) for _, x in tasks)

if tasks:
    print("Gonna update %d files" % len(tasks))

    with tqdm(total=total_size, unit='iB', unit_scale=True) as pbar:
        s = requests.Session()
        for visible, real in tasks:
            desc = "%70s" % str(visible.relative_to("dists").parent)

            pbar.set_description(desc)
            r = s.get(MIRROR_URL + '/' + str(real), stream=True)
            r.raise_for_status()
            local_path = map_local(visible)
            os.makedirs(local_path.parent, exist_ok=True)
            with open(local_path, 'wb') as f:
                for data in r.iter_content(32 * 1024):
                    pbar.update(len(data))
                    f.write(data)
else:
    print("Up to date!")

print("Hashing...")

with open("hashes.txt", 'w') as f:
    for file in sorted(LOCAL_PATH.iterdir()):
        hash = hash_file(file)
        f.write(f"{file.name} {hash}\n")

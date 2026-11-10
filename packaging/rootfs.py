#!/usr/bin/env python3
"""Unpacks an official Docker Hub image (linux/amd64) as a plain root filesystem, for packaging/test.sh.

usage: rootfs.py IMAGE:TAG DIR    e.g. rootfs.py debian:13 ~/.cache/unbraid-rootfs/debian-13
Only the registry's HTTPS API: no Docker, no root. Layers are applied in order; whiteouts remove what they name.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
])


def get(url, token, accept=ACCEPT):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": accept})
    return urllib.request.urlopen(req, timeout=300)


def main(image, target):
    name, tag = image.split(":") if ":" in image else (image, "latest")
    repo = name if "/" in name else f"library/{name}"
    token = json.load(urllib.request.urlopen(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=60))["token"]
    base = f"https://registry-1.docker.io/v2/{repo}"
    manifest = json.load(get(f"{base}/manifests/{tag}", token))
    if "manifests" in manifest:  # an index: the linux/amd64 image
        digest = next(m["digest"] for m in manifest["manifests"]
                      if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64")
        manifest = json.load(get(f"{base}/manifests/{digest}", token))
    if os.path.exists(target):
        shutil.rmtree(target)
    os.makedirs(target)
    with tempfile.TemporaryDirectory() as tmp:
        for layer in manifest["layers"]:
            blob = os.path.join(tmp, "layer")
            with get(f"{base}/blobs/{layer['digest']}", token, "*/*") as r, open(blob, "wb") as out:
                shutil.copyfileobj(r, out)
            names = subprocess.run(["tar", "-tf", blob], check=True, capture_output=True, text=True).stdout.split("\n")
            for n in names:  # whiteouts: ".wh.x" deletes x from the layers below
                base_name = os.path.basename(n.rstrip("/"))
                if base_name.startswith(".wh.") and base_name != ".wh..wh..opq":
                    victim = os.path.join(target, os.path.dirname(n), base_name[4:])
                    shutil.rmtree(victim, ignore_errors=True) if os.path.isdir(victim) else (os.path.exists(victim) and os.remove(victim))
            # Device nodes can't be made without root; the sandbox brings its own /dev.
            subprocess.run(["tar", "-xf", blob, "-C", target, "--no-same-owner", "--exclude=dev/*", "--exclude=*.wh.*"], check=True)
    print(target)


if __name__ == "__main__":
    main(sys.argv[1], os.path.expanduser(sys.argv[2]))

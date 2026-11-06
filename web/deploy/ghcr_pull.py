#!/usr/bin/env python3
"""Fetch a public ghcr.io image through an HTTP proxy into an OCI layout tar (for `docker load`)."""
import hashlib, json, os, sys, tarfile, urllib.request

REPO, TAG, PROXY, OUT = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
REG = "https://ghcr.io"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": PROXY, "http": PROXY}))
tok = json.load(opener.open(f"{REG}/token?scope=repository:{REPO}:pull&service=ghcr.io", timeout=30))["token"]
ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def get(path, accept=ACCEPT):
    req = urllib.request.Request(f"{REG}/v2/{REPO}/{path}", headers={"Authorization": f"Bearer {tok}", "Accept": accept})
    return opener.open(req, timeout=120)


work = OUT + ".d"
os.makedirs(work + "/blobs/sha256", exist_ok=True)


def blob(digest, size):
    dest = f"{work}/blobs/sha256/{digest.split(':')[1]}"
    if os.path.exists(dest) and os.path.getsize(dest) == size:
        return dest
    fails = 0
    # The proxy silently truncates long streams, so resume with Range requests.
    while True:
        have = os.path.getsize(dest) if os.path.exists(dest) else 0
        if have == size:
            break
        if have > size or fails > 20:
            os.remove(dest)
            if fails > 20:
                raise SystemExit(f"giving up on {digest}")
            continue
        req = urllib.request.Request(
            f"{REG}/v2/{REPO}/blobs/{digest}",
            headers={"Authorization": f"Bearer {tok}", "Range": f"bytes={have}-{min(size, have + (64 << 20)) - 1}"},
        )
        try:
            with opener.open(req, timeout=120) as r, open(dest, "ab") as f:
                data = r.read()
                if r.status == 200 and have:
                    raise OSError("server ignored Range")
                f.write(data)
        except Exception as exc:  # noqa: BLE001
            fails += 1
            print("retry", digest[:19], have, repr(exc)[:120], flush=True)
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    if "sha256:" + h.hexdigest() != digest:
        os.remove(dest)
        raise SystemExit(f"digest mismatch {digest}")
    print("got", digest[:19], size, flush=True)
    return dest


raw = get(f"manifests/{TAG}").read()
doc = json.loads(raw)
if "manifests" in doc:
    pick = next(m for m in doc["manifests"] if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64")
    raw = get(f"manifests/{pick['digest']}").read()
    doc = json.loads(raw)
mdigest = "sha256:" + hashlib.sha256(raw).hexdigest()
open(f"{work}/blobs/sha256/{mdigest.split(':')[1]}", "wb").write(raw)
blob(doc["config"]["digest"], doc["config"].get("size"))
for layer in doc["layers"]:
    blob(layer["digest"], layer.get("size"))

index = {"schemaVersion": 2, "manifests": [{
    "mediaType": doc.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
    "digest": mdigest, "size": len(raw),
    "annotations": {"io.containerd.image.name": f"ghcr.io/{REPO}:{TAG}", "org.opencontainers.image.ref.name": TAG},
}]}
json.dump(index, open(work + "/index.json", "w"))
json.dump({"imageLayoutVersion": "1.0.0"}, open(work + "/oci-layout", "w"))
with tarfile.open(OUT, "w") as t:
    for name in ("oci-layout", "index.json", "blobs"):
        t.add(f"{work}/{name}", arcname=name)
print("DONE", OUT, flush=True)

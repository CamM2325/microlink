#!/usr/bin/env python3
"""Update the firmware of MicroLink devices over the tailnet.

Each device needs the config web UI with firmware upload enabled
(examples/sdkconfig.ota.defaults) and must already run a firmware built that
way. Run this on a machine in the same tailnet:

    ML_HTTP_PASSWORD=... tools/ml_ota.py build/app.bin 100.64.0.5 sensor-2 ...

For each device it reads the running version (GET /api/status), uploads the
image (POST /api/ota), waits for the device to come back and checks that it
runs the new image. With ML_OTA_ROLLBACK the device keeps the image only once
it has reconnected, so a device that "comes back" has proven the update.

Python standard library only. Exit status 0 if every device was updated.
"""
import argparse
import base64
import concurrent.futures
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


def request(ip, port, path, auth, data=None, timeout=10):
    # The device only answers a Host header that is its own IP literal
    # (DNS-rebinding guard), so always connect by address.
    req = urllib.request.Request("http://%s:%d%s" % (ip, port, path), data=data)
    req.add_header("Authorization", "Basic " + auth)
    if data is not None:
        req.add_header("Content-Type", "application/octet-stream")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or "{}")


def update_one(host, image, args, auth):
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        return host, False, "cannot resolve: %s" % e
    try:
        before = request(ip, args.port, "/api/status", auth)
    except (OSError, urllib.error.URLError, ValueError) as e:
        return host, False, "not reachable: %s" % e
    old = "%s on %s" % (before.get("fw_version", "?"), before.get("fw_partition", "?"))

    t0 = time.time()
    try:
        res = request(ip, args.port, "/api/ota", auth, data=image, timeout=args.upload_timeout)
    except urllib.error.HTTPError as e:
        return host, False, "upload refused (%d): %s" % (e.code, e.read().decode(errors="replace").strip())
    except (OSError, urllib.error.URLError, ValueError) as e:
        return host, False, "upload failed: %s" % e
    target = res.get("partition")
    secs = time.time() - t0
    print("%s: %d bytes uploaded in %.0f s (%.0f kB/s), restarting into %s"
          % (host, len(image), secs, len(image) / 1024 / max(secs, 0.001), target), flush=True)

    deadline = time.time() + args.wait
    time.sleep(10)
    while time.time() < deadline:
        try:
            after = request(ip, args.port, "/api/status", auth, timeout=5)
            if after.get("fw_partition") == target and after.get("state") == "CONNECTED":
                return host, True, "%s -> %s on %s" % (old, after.get("fw_version", "?"), target)
            if after.get("fw_partition") not in (None, target):
                return host, False, "came back on %s: the new image was rolled back" % after.get("fw_partition")
        except (OSError, urllib.error.URLError, ValueError):
            pass
        time.sleep(5)
    return host, False, "did not come back within %d s" % args.wait


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("image", help="app image (.bin) from the build directory")
    p.add_argument("hosts", nargs="+", help="tailnet IPs or MagicDNS names")
    p.add_argument("--password", default=os.environ.get("ML_HTTP_PASSWORD"),
                   help="config UI password (default: $ML_HTTP_PASSWORD)")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--parallel", type=int, default=4, help="devices updated at once (default 4)")
    p.add_argument("--upload-timeout", type=int, default=300)
    p.add_argument("--wait", type=int, default=360,
                   help="seconds to wait for a device to come back (default 360)")
    args = p.parse_args()
    if not args.password:
        p.error("set --password or ML_HTTP_PASSWORD")

    with open(args.image, "rb") as f:
        image = f.read()
    if not image or image[0] != 0xE9:
        p.error("%s is not an ESP app image" % args.image)
    auth = base64.b64encode(("admin:" + args.password).encode()).decode()

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        jobs = [pool.submit(update_one, h, image, args, auth) for h in args.hosts]
        for job in concurrent.futures.as_completed(jobs):
            host, ok, msg = job.result()
            print("%s: %s %s" % (host, "OK  " if ok else "FAIL", msg), flush=True)
            failed += not ok
    print("%d of %d updated" % (len(args.hosts) - failed, len(args.hosts)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

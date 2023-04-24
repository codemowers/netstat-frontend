#!/usr/bin/env python3
import aiohttp
import graphviz
import os
from collections import Counter
from fnmatch import fnmatch
from ipaddress import IPv4Address, IPv4Network
from sanic import Sanic
from sanic.response import raw

URL_AGGREGATE = os.environ.get("URL_AGGREGATE", "http://127.0.0.1:3002/aggregate.json")

app = Sanic("netstat-frontend")


def humanize(j, filter_namespaces=(), collapse_hostnames=()):
    hostname = j.get("hostname")
    if j.get("pod"):
        color = "#2acaea"
        if filter_namespaces and j.get("namespace") in filter_namespaces:
            color = "#00ff7f"
        return "%s/%s" % (j["namespace"], j["owner"]["name"] if j.get("owner") else j["pod"]), color
    elif hostname:
        hostname = ".".join(hostname.split(".")[-2:])
        org = j.get("whois", {}).get("org")
        if org:
            hostname = org
        color = "#ffff66"
        return "%s" % (hostname), color
    else:
        color = "#ff4040"
        return "%s" % (j["addr"]), color


@app.get("/diagram.svg")
async def render(request):
    async with aiohttp.ClientSession() as session:
        async with session.get(URL_AGGREGATE) as response:
            z = await response.json()
    collapse_hostnames = request.args.getlist("collapse_hostnames", ())
    exclude_namespaces = request.args.getlist("exclude", ("longhorn-system", "metallb-system", "prometheus-operator"))
    include_namespaces = request.args.getlist("include")
    dot = graphviz.Graph("topology", engine="sfdp")
    connections = Counter()
    for conn in z["connections"]:
        local, remote = conn["local"], conn["remote"]
        if IPv4Address(remote["addr"]) in IPv4Network("10.96.0.0/12"):
            continue
        if local.get("namespace") in exclude_namespaces or \
           remote.get("namespace") in exclude_namespaces:
            continue
        if include_namespaces:
            matches = local.get("namespace") in include_namespaces or \
                remote.get("namespace") in include_namespaces
            if not matches:
                continue
        hr, cr = humanize(remote, include_namespaces, collapse_hostnames)
        hl, cl = humanize(local, include_namespaces, collapse_hostnames)

        key = hl, hr
        if key[0] == key[1]:
            continue
        if key[0] < key[1]:
            key = key[1], key[0]
        dot.attr("node", shape="box", style="filled", color=cr, fontname="sans")
        dot.node(hr)
        dot.attr("node", shape="box", style="filled", color=cl, fontname="sans")
        dot.node(hl)
        connections[key] += 1

    dot.attr("node", shape="box", style="filled", color="#dddddd", fontname="sans")
    for (l, r), count in connections.items():
        dot.edge(l, r, label=str(count), fontname="sans")
    dot.format = "svg"
    return raw(dot.pipe(), content_type="image/svg+xml")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3006, single_process=True, motd=False)

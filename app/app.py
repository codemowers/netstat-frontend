#!/usr/bin/env python3
import aiodns
import aiohttp
import asyncio
import graphviz
import os
from collections import Counter
from fnmatch import fnmatch
from ipaddress import IPv4Address, IPv4Network
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.api_client import ApiClient
from prometheus_client import Histogram
from sanic_prometheus import monitor
from sanic import Sanic
from sanic.response import json, raw

app = Sanic("netstat-ui")


histogram_latency = Histogram("netstat_stage_latency_sec",
    "Latency histogram",
    ["stage"])

POD_NAMESPACE = os.environ["POD_NAMESPACE"]


@histogram_latency.labels("kube-api-get-pods").time()
async def fetch_pods():
    ip_to_pod = {}
    cid_to_container = {}
    async with ApiClient() as api:
        v1 = client.CoreV1Api(api)
        for pod in (await v1.list_namespaced_pod("")).items:
            owner_kind, owner_name = None, None
            if pod.metadata.owner_references:
                owner_kind, owner_name = \
                    pod.metadata.owner_references[0].kind, \
                    pod.metadata.owner_references[0].name
            ip_to_pod[pod.status.pod_ip] = pod.metadata.namespace, \
                pod.metadata.name, owner_kind, owner_name
            for status in pod.status.container_statuses or ():
                cid_to_container[status.container_id] = pod.metadata.namespace, \
                    pod.metadata.name, status.name, \
                    owner_kind, owner_name
    return ip_to_pod, cid_to_container


@histogram_latency.labels("fetch-exports").time()
async def fetch(url, session):
    print("Making HTTP request to %s" % url)
    async with session.get(url) as response:
        return await response.json()


@histogram_latency.labels("resolve-targets").time()
async def resolve_targets(ctx):
    addr = "_http._tcp.netstat-server.%s.svc.cluster.local" % POD_NAMESPACE
    print("Resolving SRV record for %s" % addr)
    return await ctx.resolver.query(addr, "SRV")


async def aggregate(ctx):
    ip_to_pod, cid_to_container = await fetch_pods()
    targets = await resolve_targets(ctx)
    tasks = []

    async with aiohttp.ClientSession() as session:
        for target in targets:
            url = "http://%s:%d/export" % (target.host, target.port)
            tasks.append(fetch(url, session))
        responses = await asyncio.gather(*tasks)
    aggregated = {"connections": [], "listening": [], "reverse": {}}

    for response in responses:
        for key, value in response["reverse"].items():
            aggregated["reverse"][key] = value

    for response in responses:
        for cid, lport, raddr, rport, proto, state in response.get("connections", ()):
            if not cid:
                continue
            try:
                local_namespace, local_pod, _, owner_kind, owner_name = cid_to_container[cid]
            except KeyError:
                print("Failed to resolve container", cid)
                continue
            pair = {
                "proto": proto,
                "state": state,
                "local": {
                    "namespace": local_namespace,
                    "pod": local_pod,
                    "port": lport,
                    "owner": {
                        "kind": owner_kind,
                        "name": owner_name,
                    }
                }
            }
            remote = ip_to_pod.get(raddr)
            pair["remote"] = {"addr": raddr, "port": rport}
            hostname = aggregated["reverse"].get(raddr)
            if hostname:
                pair["remote"]["hostname"] = hostname
            if remote:
                remote_namespace, remote_pod, owner_kind, owner_name = remote
                pair["remote"]["namespace"] = remote_namespace
                pair["remote"]["pod"] = remote_pod
                pair["remote"]["owner"] = {"kind": owner_kind, "name": owner_name}
            aggregated["connections"].append(pair)
        aggregated["listening"] += response.get("listening", [])
    return aggregated


@app.get("/aggregate.json")
async def fanout(request):
    return json(await aggregate(app.ctx))


def humanize(j, filter_namespaces=(), collapse_hostnames=()):
    hostname = j.get("hostname")
    if j.get("pod"):
        color = "#2acaea"
        if filter_namespaces and j.get("namespace") in filter_namespaces:
            color = "#00ff7f"
        return "%s/%s" % (j["namespace"], j["owner"]["name"] if j.get("owner") else j["pod"]), color
    elif hostname:
        for pattern in collapse_hostnames:
            if fnmatch(hostname, pattern):
                hostname = pattern
                break
        color = "#ffff66"
        return "%s" % (j["hostname"]), color
    else:
        color = "#ff4040"
        return "%s" % (j["addr"]), color


@app.get("/diagram.svg")
async def render(request):
    collapse_hostnames = request.args.getlist("collapse_hostnames", ())
    exclude_namespaces = request.args.getlist("exclude", ("longhorn-system", "metallb-system", "prometheus-operator"))
    include_namespaces = request.args.getlist("include")
    z = await aggregate(app.ctx)
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


@app.listener("before_server_start")
async def setup_db(app, loop):

    app.ctx.resolver = aiodns.DNSResolver()
    if os.getenv("KUBECONFIG"):
        await config.load_kube_config()
    else:
        config.load_incluster_config()

if __name__ == "__main__":
    monitor(app).expose_endpoint()
    app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)

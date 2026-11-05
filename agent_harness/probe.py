"""Collect observed Docker restrictions, not just requested flags."""
import json
import subprocess
from .real_eval import MCP, ROOT, docker


def main():
    trace = []
    client = MCP("normal", trace)
    try:
        hello = client.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "probe", "version": "1"}}, timeout=30)
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = client.request("tools/list")
        info = json.loads(subprocess.check_output(docker("inspect", client.name), text=True))[0]
        code = '''import json,os
result={"uid":os.getuid(),"status":open("/proc/self/status").read(),"interfaces":open("/proc/net/dev").read()}
try:
 open("/rootfs-write-probe","w").write("probe")
 result["root_write_blocked"]=False
except OSError as e:
 result["root_write_blocked"]=True
 result["write_errno"]=e.errno
print(json.dumps(result))'''
        observed = json.loads(subprocess.check_output(docker("exec", client.name, "python", "-c", code), text=True))
        host = info["HostConfig"]
        checks = {"mcp_handshake": hello["protocolVersion"] == "2025-11-25",
                  "tools_discovered": len(tools["tools"]) == 3,
                  "nonroot": observed["uid"] == 65534,
                  "readonly_root_observed": observed["root_write_blocked"] and observed["write_errno"] == 30,
                  "network_none": host["NetworkMode"] == "none",
                  "capabilities_dropped": "CapEff:\t0000000000000000" in observed["status"],
                  "seccomp_active": "Seccomp:\t2" in observed["status"],
                  "no_new_privileges": "NoNewPrivs:\t1" in observed["status"],
                  "memory_limit": host["Memory"] == 128 * 1024 * 1024,
                  "pid_limit": host["PidsLimit"] == 32,
                  "cpu_limit": host["NanoCpus"] == 500000000}
        path = ROOT / "reports" / "docker-probe.json"
        path.write_text(json.dumps({"checks": checks, "observed": observed, "inspect": info,
                                    "trace": trace}, indent=2), encoding="utf-8")
        print(json.dumps(checks, indent=2))
        if not all(checks.values()):
            raise SystemExit("Docker checks failed")
    finally:
        client.close()


if __name__ == "__main__":
    main()

"""Observed container constraints plus a controlled additional seccomp deny rule."""
import json
import subprocess
from .expanded_cases import cases
from .expanded_eval import ExpandedMCP, initialize, atomic_json
from .real_eval import ROOT, docker

CODE = r'''
import ctypes as c,errno,json,os,platform,socket
assert platform.machine() == "x86_64", "probe syscall numbers require x86_64"
libc=c.CDLL(None,use_errno=True)
class Filter(c.Structure):
 _fields_=[("code",c.c_ushort),("jt",c.c_ubyte),("jf",c.c_ubyte),("k",c.c_uint)]
class Program(c.Structure):
 _fields_=[("len",c.c_ushort),("filter",c.POINTER(Filter))]
# Check architecture, then deny getppid (110) with EPERM. Default Docker filter stays active.
filters=(Filter*7)(Filter(0x20,0,0,4),Filter(0x15,1,0,0xc000003e),Filter(0x06,0,0,0x80000000),
 Filter(0x20,0,0,0),Filter(0x15,0,1,110),Filter(0x06,0,0,0x00050000|errno.EPERM),Filter(0x06,0,0,0x7fff0000))
before=libc.syscall(110)
assert libc.prctl(38,1,0,0,0)==0
program=Program(7,filters)
assert libc.prctl(22,2,c.byref(program),0,0)==0, c.get_errno()
c.set_errno(0)
after=libc.syscall(110)
denied_errno=c.get_errno()
result={"uid":os.getuid(),"getppid_before":before,"getppid_after":after,"denied_errno":denied_errno,
 "getpid_after":libc.syscall(39),"status":open("/proc/self/status").read(),"interfaces":open("/proc/net/dev").read()}
try:
 open("/rootfs-write-probe","w").write("probe")
 result["root_write_errno"]=0
except OSError as e:
 result["root_write_errno"]=e.errno
try:
 socket.create_connection(("1.1.1.1",443),timeout=1)
 result["network_blocked"]=False
except OSError:
 result["network_blocked"]=True
for name in ("memory.max","pids.max","cpu.max"):
 try: result[name]=open("/sys/fs/cgroup/"+name).read().strip()
 except OSError: result[name]=None
print(json.dumps(result))
'''


def main():
    client = ExpandedMCP([])
    try:
        initialize(client, cases()[0])
        info = json.loads(subprocess.check_output(docker("inspect", client.name), text=True))[0]
        observed = json.loads(subprocess.check_output(docker("exec", client.name, "python", "-c", CODE), text=True))
        host = info["HostConfig"]
        checks = {"nonroot": observed["uid"] == 65534,
                  "readonly_root": observed["root_write_errno"] == 30,
                  "network_isolated": observed["network_blocked"] and host["NetworkMode"] == "none",
                  "no_capabilities": "CapEff:\t0000000000000000" in observed["status"],
                  "no_new_privileges": "NoNewPrivs:\t1" in observed["status"],
                  "seccomp_active": "Seccomp:\t2" in observed["status"],
                  # Parent may be outside this PID namespace: successful getppid then returns 0.
                  "custom_syscall_rule_denied": observed["getppid_before"] >= 0 and observed["getppid_after"] == -1 and observed["denied_errno"] == 1,
                  "allowed_syscall_still_works": observed["getpid_after"] > 0,
                  "memory_limit_observed": observed["memory.max"] == str(128*1024*1024),
                  "pid_limit_observed": observed["pids.max"] == "32",
                  "cpu_limit_observed": observed["cpu.max"] == "50000 100000"}
        path = ROOT / "reports" / "sandbox-expanded.json"
        atomic_json(path, {"checks": checks, "observed": observed, "inspect": info,
                          "scope": "Fixed test process stacks a getppid deny rule onto Docker's existing seccomp; not semantic authorization or syscall telemetry."})
        print(json.dumps(checks, indent=2))
        if not all(checks.values()):
            raise SystemExit("Sandbox checks failed")
    finally:
        client.close()


if __name__ == "__main__":
    main()

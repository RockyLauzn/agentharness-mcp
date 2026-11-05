"""Probe every denied syscall from a forked tool-like process in the pinned image."""
import json
import subprocess
from datetime import datetime, timezone

from .real_eval import ROOT, docker


CHILD = r'''
import ctypes as ct
import json
import os
import sys
from engine_core import install_filter

denied = install_filter()
pid = os.fork()
if pid:
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))
libc = ct.CDLL(None, use_errno=True)
libc.syscall.restype = ct.c_long
results = {}
for number in denied:
    ct.set_errno(0)
    value = libc.syscall(number, 0, 0, 0, 0, 0, 0)
    results[str(number)] = [value, ct.get_errno()]
ct.set_errno(0)
allowed_pid = libc.syscall(39, 0, 0, 0, 0, 0, 0)
status = open('/proc/self/status', encoding='utf-8').read()
ok = all(value == -1 and error == 1 for value, error in results.values()) and allowed_pid == os.getpid() and 'Seccomp_filters:\t2' in status
print(json.dumps({'passed': ok, 'child_pid': os.getpid(), 'denied': results, 'allowed_getpid': allowed_pid,
                  'seccomp_filters': next((s for s in status.splitlines() if s.startswith('Seccomp_filters:')), None)}), flush=True)
os._exit(0 if ok else 2)
'''


def main():
    command = docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--memory", "192m", "--cpus", "0.5",
                     "--pids-limit", "32", "--user", "65534:65534",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--entrypoint", "python",
                     "agent-harness:workflow", "-c", CHILD)
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)
    if result.returncode:
        raise SystemExit(f"Kernel probe failed (exit {result.returncode}): {result.stderr[-500:]}")
    data = json.loads(result.stdout)
    if not data["passed"]:
        raise SystemExit("Kernel probe reported incomplete syscall blocking")
    data["image_id"] = json.loads(subprocess.check_output(docker("inspect", "agent-harness:workflow"),
                                                         text=True))[0]["Id"]
    data["observed_utc"] = datetime.now(timezone.utc).isoformat()
    (ROOT / "reports/seccomp-workflow.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                                                   encoding="utf-8")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()

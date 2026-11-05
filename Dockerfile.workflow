FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
WORKDIR /app
COPY agent_harness/engine_core.py agent_harness/engine_server.py /app/
USER 65534:65534
ENTRYPOINT ["python", "-u", "/app/engine_server.py"]

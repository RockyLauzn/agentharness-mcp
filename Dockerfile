FROM python:3.12-slim
WORKDIR /app
COPY agent_harness/mcp_server.py /app/mcp_server.py
USER 65534:65534
ENTRYPOINT ["python", "-u", "/app/mcp_server.py"]

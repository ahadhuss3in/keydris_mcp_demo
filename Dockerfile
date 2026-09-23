# Governed SecOps Agent — all-in-one image.
#
# The image contains the LangGraph agent (run_demo.py), the Jev/OpenRouter
# clients, and the Keydris-guarded MCP server (mcp_server.py). The stdio MCP
# server is spawned as a child process inside the container, so no extra
# service is required.
#
# Build:
#   docker build -t governed-secops-agent .
#
# Run the demo (secrets passed at runtime, never baked in):
#   docker run --rm --env-file .env governed-secops-agent
#
# Run the offline guardrail test suite (no API key needed):
#   docker run --rm governed-secops-agent python -m pytest
#
# Run a single alert:
#   docker run --rm --env-file .env governed-secops-agent \
#     python run_demo.py --alert-id ALT-2026-0001

FROM python:3.12-slim-bookworm

# ---- Runtime environment ---------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# ---- uv (package manager) --------------------------------------------------
# Pulled from PyPI rather than the ghcr.io image so the build only needs Docker Hub.
RUN pip install --no-cache-dir uv==0.11.1

# Keep the venv on PATH for *login* shells too (e.g. `docker run -it ... bash -l`),
# which otherwise source /etc/profile and reset PATH away from /app/.venv/bin.
RUN printf 'export PATH="/app/.venv/bin:$PATH"\n' > /etc/profile.d/venv.sh \
    && chmod +x /etc/profile.d/venv.sh

WORKDIR /app

# ---- Dependencies (cached independently of source changes) -----------------
# Copy only the manifests first so editing app code doesn't reinstall packages.
# `--all-groups` also installs the `dev` group, which includes pytest.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --all-groups

# ---- Application source ----------------------------------------------------
COPY . .
# Re-sync so the venv is guaranteed consistent with the copied manifest.
RUN uv sync --frozen --all-groups

# ---- Default entrypoint ----------------------------------------------------
# End-to-end run: data/alerts.json -> investigate (LLM) -> judge (Jev)
#                 -> enforcer (Keydris-guarded MCP block_ip)
CMD ["python", "run_demo.py"]
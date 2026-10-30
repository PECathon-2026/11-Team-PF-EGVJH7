# PrivacyLens reproducible test environment.
#   docker compose up --build --exit-code-from tests
#
# Pinned to Debian bookworm: Playwright's --with-deps installer supports it
# across every Playwright version allowed by requirements.txt.
FROM python:3.11-slim-bookworm

# PLAYWRIGHT_BROWSERS_PATH puts Chromium where the non-root user can reach it.
# PRIVACYLENS_MOCK_LLM keeps the container from calling any external LLM.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PRIVACYLENS_MOCK_LLM=1

WORKDIR /app

# Install Python dependencies first so this layer is cached across code edits.
COPY requirements.txt .
RUN pip install -r requirements.txt

# --with-deps apt-installs Chromium's Linux libraries (libnss3, libgbm1,
# fonts, ...) and then downloads the matching browser build.
RUN python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Run the suite as an unprivileged user; Chromium keeps its sandbox enabled.
RUN useradd --create-home --uid 10001 tester \
    && chown -R tester:tester /app
USER tester

CMD ["python", "-m", "pytest", "-v"]

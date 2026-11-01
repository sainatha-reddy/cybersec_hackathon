# PacketDoctor web dashboard as a container (used for the Hugging Face Space demo).
# Local use needs none of this: `packetdoctor serve` runs the same app on 127.0.0.1.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PACKETDOCTOR_HOSTED=1 \
    PACKETDOCTOR_MAX_UPLOAD_MB=50

# Hugging Face runs Spaces as user 1000; use the same unprivileged user everywhere.
RUN useradd --create-home --uid 1000 app
WORKDIR /home/app/packetdoctor

COPY requirements.lock ./
RUN pip install --retries 10 --timeout 60 -r requirements.lock

COPY --chown=app:app packetdoctor ./packetdoctor
COPY --chown=app:app samples ./samples

USER app
EXPOSE 7860

# Uses the host's PORT when set (Render, Koyeb), else 7860 (Hugging Face).
# One process on purpose: analysis jobs are tracked in this process's memory.
CMD python -m uvicorn packetdoctor.web.app:app --host 0.0.0.0 --port "${PORT:-7860}" --workers 1 --log-level warning --proxy-headers --forwarded-allow-ips "*"

FROM python:3.12-slim

WORKDIR /app
COPY . .

# Pure stdlib — nothing to install.
RUN python -m compileall . -q

EXPOSE 8000
CMD ["python", "sift.py"]

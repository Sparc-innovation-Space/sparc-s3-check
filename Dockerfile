# Stage 12.6: the file storage check app (test-file-storage.sh). Standard library only: nothing to install.
FROM python:3.13-slim
WORKDIR /app
COPY server.py .
RUN useradd --create-home appuser
USER appuser
EXPOSE 8000
CMD ["python", "server.py"]

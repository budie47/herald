FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN mkdir -p staticfiles && DJANGO_SECRET_KEY=build python manage.py collectstatic --noinput \
    && chmod +x /app/entrypoint.sh \
    && useradd --create-home herald && mkdir -p /data/uploads && chown -R herald /app /data
USER herald

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "herald.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "gthread", "--threads", "4", "--timeout", "180"]

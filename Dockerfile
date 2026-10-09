FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
# Web UI by default; override to use the CLI, e.g.
#   docker run --rm -v $PWD/out:/app/threatlens_output threatlens python -m threatlens examples/clinic_booking.yaml
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]

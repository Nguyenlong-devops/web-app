FROM python:3.10-slim

WORKDIR /app

# Cài đặt công cụ hệ thống cần thiết
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# SỬA DÒNG NÀY: Vì file requirements.txt nằm trong thư mục app/
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chạy ứng dụng
CMD ["python", "app.py"]
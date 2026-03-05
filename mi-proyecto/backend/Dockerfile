FROM python:3.10-slim

WORKDIR /app

# Instalar dependencias primero para cachear capa de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Exponer puerto para Flask
EXPOSE 5000

# Arrancar servidor
CMD ["python", "app.py"]
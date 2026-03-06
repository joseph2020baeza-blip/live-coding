FROM python:3.10-slim

# Crear usuario sin privilegios
RUN useradd -m -s /bin/bash appuser

WORKDIR /app

# Instalar dependencias primero para cachear capa de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Crear el directorio de la BD SQLite y asignar propietario a appuser
# Esto es crítico: si instance/ llega del host con permisos root, SQLite
# lanzará "attempt to write a readonly database" al intentar insertar.
RUN mkdir -p /app/instance && chown -R appuser:appuser /app

# Cambiar al usuario no root
USER appuser

# Exponer puerto para Flask
EXPOSE 5000

# Arrancar servidor
CMD ["python", "app.py"]
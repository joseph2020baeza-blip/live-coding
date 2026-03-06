FROM python:3.10-slim

# Crear usuario sin privilegios
RUN useradd -m -s /bin/bash appuser

WORKDIR /app

# Instalar dependencias primero para cachear capa de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY . .

# Cambiar permisos al usuario no root
RUN chown -R appuser:appuser /app

# Cambiar al usuario no root
USER appuser

# Exponer puerto para Flask
EXPOSE 5000

# Arrancar servidor
CMD ["python", "app.py"]
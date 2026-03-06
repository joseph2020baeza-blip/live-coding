FROM nginx:alpine

# Removemos conf default de nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copiamos nuestra configuracion de proxy reverso
COPY nginx.conf /etc/nginx/conf.d/

# ── Seguridad: ejecutar como usuario no privilegiado ──────────────────────────
# nginx:alpine ya incluye el usuario 'nginx' (uid 101).
# Le damos permisos sobre los directorios que Nginx necesita en tiempo de ejecución
# para poder arrancar sin root. El proceso MASTER necesita root solo para abrir el
# puerto 80; en nginx.conf se establece `user nginx;` para que los workers sean
# del usuario nginx.
RUN chown -R nginx:nginx \
        /var/cache/nginx \
        /var/log/nginx \
        /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid

# Copiamos el frontend estático
COPY . /usr/share/nginx/html

# Aseguramos que el usuario nginx pueda leer los ficheros estáticos
RUN chown -R nginx:nginx /usr/share/nginx/html

USER nginx

# Exponemos el puerto
EXPOSE 80

# Comando por defecto
CMD ["nginx", "-g", "daemon off;"]

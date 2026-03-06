FROM nginx:alpine

# Removemos conf default de nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copiamos nuestra configuracion de proxy reverso
COPY nginx.conf /etc/nginx/conf.d/

# Exponemos el puerto
EXPOSE 80

# Comando por defecto
CMD ["nginx", "-g", "daemon off;"]

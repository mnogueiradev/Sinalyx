# Servidor Nginx Simples
FROM nginx:alpine
# Copia os arquivos JÁ COMPILADOS do seu computador para o servidor
COPY build/web /usr/share/nginx/html

# Configuração para garantir que o Flutter Web funcione sem erros 404
RUN echo 'server { \
    listen 80; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html index.htm; \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

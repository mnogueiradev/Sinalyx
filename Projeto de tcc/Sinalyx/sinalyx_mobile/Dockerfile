# 1️⃣ Estágio de Build do Flutter
FROM ghcr.io/cirruslabs/flutter:stable AS build
WORKDIR /app
# Copia todo o código do app mobile para dentro do container
COPY . .
# Baixa as dependências e compila para a Web
RUN flutter pub get
RUN flutter build web --release

# 2️⃣ Estágio de Servidor (Nginx)
FROM nginx:alpine
# Copia os arquivos HTML/JS gerados pelo Flutter para a pasta do Nginx
COPY --from=build /app/build/web /usr/share/nginx/html
# Configuração para garantir que o Flutter Web funcione perfeitamente sem erros 404
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

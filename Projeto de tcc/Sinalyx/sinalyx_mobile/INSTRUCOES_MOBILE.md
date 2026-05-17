# Guia de Execução: Sinalyx Mobile

Este documento contém as instruções detalhadas para executar a versão móvel (Android) do projeto Sinalyx. O aplicativo foi desenvolvido em Flutter e realiza o gerenciamento de usuários (CRUD completo) comunicando-se diretamente com a API do projeto.

---

## ⚠️ Pré-requisitos Importantes

Como o aplicativo móvel atua como um "cliente" que consome os dados do servidor, **o backend e o banco de dados precisam estar rodando no computador host**.

1. Abra o terminal na pasta raiz do projeto (`Sinalyx`).
2. Suba os containers do Docker:
   ```bash
   docker compose up -d sinalyx_postgres sinalyx_api
   ```
3. Certifique-se de que o computador e o dispositivo Android estão conectados na **mesma rede Wi-Fi**.

---

## Método 1: Instalação via arquivo APK (Recomendado)

Esta é a forma mais simples, pois dispensa configurações de drivers e depuração no computador. Basta gerar o instalador e enviar para o celular.

### Passo 1: Gerar o APK
No terminal do computador, acesse a pasta do projeto móvel e rode o comando de build:
```bash
cd sinalyx_mobile
flutter build apk --debug
```

### Passo 2: Transferir e Instalar
1. O processo acima gerará um arquivo chamado `app-debug.apk` no caminho:
   `sinalyx_mobile\build\app\outputs\flutter-apk\app-debug.apk`
2. Transfira este arquivo para o celular Android (via cabo, Google Drive, WhatsApp, e-mail, etc.).
3. Pelo celular, toque no arquivo baixado para iniciar a instalação.
   * *Nota: Pode ser necessário autorizar a "instalação de apps de fontes desconhecidas" nas configurações de segurança do Android.*
4. Abra o aplicativo "Sinalyx" instalado na sua tela inicial.

---

## Método 2: Execução Direta via Cabo USB (Depuração)

Para rodar o código diretamente do computador para o celular sem gerar um arquivo de instalação.

### Passo 1: Preparar o Celular (Modo Desenvolvedor)
1. No Android, acesse **Configurações > Sobre o telefone**.
2. Toque **7 vezes** seguidas em **"Número da versão"** (ou "Número da compilação") para habilitar o modo desenvolvedor.
3. Volte, vá em **Opções do Desenvolvedor** e ative a chave **"Depuração USB"**.

### Passo 2: Conectar e Rodar
1. Conecte o celular ao computador usando um cabo USB de transferência de dados.
2. Na tela do celular, aparecerá um aviso: *"Permitir depuração USB?"*. Marque "Permitir sempre" e toque em **OK**.
3. No terminal do computador, dentro da pasta `sinalyx_mobile`, verifique se o aparelho foi reconhecido:
   ```bash
   flutter devices
   ```
4. Se o aparelho aparecer na lista, execute o aplicativo:
   ```bash
   flutter run -d android
   ```
5. O aplicativo será compilado e abrirá automaticamente na tela do celular.

---

## 🔐 Dados de Acesso (Login)

Para avaliar as funcionalidades de CRUD no aplicativo, utilize as seguintes credenciais de Administrador na tela de login:

* **E-mail:** `admin@sinalyx.local`
* **Senha:** `AKAStkiun210$`

Após o login, a tela principal exibirá a lista de usuários puxada do banco de dados, onde será possível criar novos acessos, editar e excluir.

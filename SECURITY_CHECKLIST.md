# Checklist de Segurança e Validação — ReaDroid Android

Este checklist estabelece as verificações estritas de segurança, integridade de arquivos e privacidade que regem a operação do aplicativo ReaDroid no sistema Android.

---

### 1. Integridade e Imutabilidade do Arquivo Original
- [x] **Tratamento Read-Only:** O arquivo APK original aberto via Storage Access Framework (SAF) é estritamente tratado como somente-leitura.
- [x] **Isolamento de Sandbox:** Todas as cópias de trabalho e descompactações ocorrem exclusivamente no diretório de cache privado do app (`context.cacheDir`).
- [x] **Prevenção de Sobrescrita:** Operações de reconstrução e assinatura sempre geram novos arquivos com sufixo (ex.: `_rebuilt.apk`), exigindo confirmação explícita do usuário para exportação via SAF.

### 2. Defesa Contra Arquivos Maliciosos
- [x] **Mitigação de Zip Slip:** Validação de entradas ZIP para impedir que caminhos relativos maliciosos (`../`) escapem do diretório de destino.
- [x] **Mitigação de Zip Bomb:** Limites rígidos de descompressão:
  - Máximo de 64 MB por entrada ZIP individual.
  - Teto global de 256 MB para varredura de strings estáticas.
  - Truncamento e alerta explícito caso o limite de segurança seja atingido.
- [x] **Isolamento de Execução:** O aplicativo **nunca executa** o código DEX, classes ou binários `.so` do APK analisado. A análise é 100% estática.

### 3. Privacidade e Proteção de Dados (Fase 7)
- [x] **IA Desativada por Padrão:** O assistente de inteligência artificial começa obrigatoriamente desativado.
- [x] **Consentimento Explícito:** Nenhum dado sai do dispositivo sem ação direta do usuário no botão de envio.
- [x] **Criptografia por Hardware:** Chaves de API e credenciais de gateways externos são salvas com criptografia AES-256 GCM pelo **Android Keystore System** via `EncryptedSharedPreferences`.
- [x] **Escopo Restrito de Dados:** O app nunca envia o APK binário ou chaves privadas para a IA; apenas o resumo estático do manifesto e metadados autorizados são compartilhados no prompt.

### 4. Reconstrução e Assinatura Criptográfica (Fase 6)
- [x] **Geração Local de Chaves:** Pares de chaves RSA de 2048-bit gerados internamente em Keystore PKCS12 protegida por senha.
- [x] **Esquemas Modernos:** Suporte nativo aos esquemas v1 (JAR signing), v2 e v3 através da biblioteca oficial Google `apksig`.
- [x] **Alerta de Identidade:** O usuário é informado de que reassinar um aplicativo altera a identidade criptográfica do desenvolvedor, não substituindo o app original da loja.

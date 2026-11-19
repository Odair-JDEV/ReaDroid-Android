# ReaDroid Android

Aplicativo Android para **entender o que um APK faz**, escrito em Kotlin e pensado
para quem nunca analisou um aplicativo. A análise é **estática, local, offline e sem root**:
o APK escolhido nunca é executado e o arquivo original nunca é alterado.

---

## Para quem é

A tela inicial faz três perguntas simples — escolher o arquivo, ler o que foi encontrado
e ver um resumo em linguagem comum. Não há menu técnico no caminho: permissões aparecem
como "o aplicativo pede estes acessos", e as configurações de risco do manifesto viram
avisos curtos, não jargão.

Recursos que exigem conhecimento de análise de APK (edição de manifesto, assinatura e
assistente de IA) ficam atrás do botão **Mais**, com explicação do que fazem.

## O que o app faz

1. **Escolhe o APK pelo seletor do Android (SAF)** — sem pedir acesso amplo ao
   armazenamento; o arquivo original é lido como somente-leitura e a análise roda
   sobre uma cópia isolada no cache privado do app.
2. **Lê o `AndroidManifest.xml` binário (AXML) em Kotlin puro** — decodifica o
   *string pool* (UTF-8 e UTF-16LE), o mapa de recursos e os elementos XML, extraindo
   pacote, versão, SDK mínimo/alvo, permissões e componentes. Sem JADX, Apktool ou aapt2.
3. **Varre o código por endereços** — URLs, domínios reais (validados contra uma lista
   estrita de TLDs, para não confundir classes Java/Kotlin com domínios) e candidatos a IPv4.
4. **Resume em linguagem simples** — o que foi pedido, o que merece atenção e o que não
   foi encontrado, com ressalva explícita de que a análise é estática e não é um veredito.
5. **Guarda o histórico por SHA-256** — análises anteriores ficam no aparelho, e o mesmo
   arquivo reusa o resultado já calculado.
6. **Exporta o relatório em Markdown** pelo seletor do sistema.

## Recursos avançados

- **Edição de manifesto** em memória (flags de depuração, backup e tráfego em texto claro).
- **Assinatura local** com chave gerada no aparelho via `apksig` (v1, v2 e v3).
- **Assistente de IA opcional**, desativado por padrão, com chave guardada no
  Android Keystore (`EncryptedSharedPreferences`).

## Limites, ditos com clareza

- A análise é **estática**: ausência de indicadores **não** prova ausência de risco.
- O app **não executa** DEX, classes ou bibliotecas nativas do APK analisado.
- Reassinar um APK **troca a identidade criptográfica** do desenvolvedor original; o
  resultado não substitui o aplicativo publicado na loja.
- Não há decompilação para Java/Smali nesta versão. Consulte o projeto Python/Termux
  para esse fluxo.

## Tecnologia

- Kotlin + Jetpack Compose (Material 3)
- compileSdk 36 · targetSdk 36 · minSdk 26 (Android 8.0+)
- Gradle 9.1 · Android Gradle Plugin 9.0
- `com.android.tools.build:apksig` para assinatura

## Estrutura

```
app/src/main/kotlin/com/readroid/app/
├── MainActivity.kt              # Activity principal, edge-to-edge
├── Navigation.kt                # Navegação (Navigation 3)
├── core/
│   ├── axml/                    # Modelos e parser binário AXML
│   ├── analyzer/                # Inspeção ZIP, hash e varredura de strings
│   ├── report/                  # Relatório em linguagem simples
│   ├── storage/                 # Histórico local por SHA-256
│   ├── editor/                  # Edição de flags do manifesto
│   ├── signing/                 # Keystore local e assinatura com apksig
│   └── ai/                      # Cliente opcional e cofre de credenciais
└── ui/
    ├── main/                    # Fluxo guiado: início, resultados, histórico
    └── theme/                   # Paleta, tipografia e tema
```

## Build

Requer JDK 17 e o Android SDK 36.

```bash
./gradlew :app:assembleDebug     # APK de depuração
./gradlew :app:testDebugUnitTest # testes unitários
./gradlew :app:assembleRelease   # APK assinado, se keystore.properties existir
```

A assinatura de release lê `keystore.properties` na raiz do projeto. Sem esse arquivo a
build continua funcionando, porém sem assinar — o arquivo e a keystore não são versionados.

# ReaDroid Android — Auditoria técnica FASE 0

**Data:** 2026-11-18  
**Escopo:** `APK_PROJETO/android` e comparação com `Rea-APK-IA/Rea-APK-IA`.  
**Regra desta fase:** nenhum arquivo de código do aplicativo foi alterado.

## 1. Sumário executivo

O Android atual é um analisador offline funcional para um subconjunto de APKs. Ele importa por SAF, trabalha sobre uma cópia no cache, calcula SHA-256, lê AXML binário, extrai metadados básicos, procura URLs/domínios/IPs, gera Markdown, mantém histórico, edita três flags booleanas existentes e assina uma cópia com `apksig`.

Ele ainda **não é** um ambiente de engenharia reversa completo. Não há JADX, Apktool, Baksmali, editor Smali, editor de recursos, pesquisa global em projeto extraído, agente de IA com ferramentas, múltiplos gateways, AccessibilityService, pipeline completo de reconstrução, verificação pós-assinatura, comparação de APKs, rollback ou gerenciamento completo de projetos.

O problema técnico mais grave é o caminho de reassinatura atual. `ApkRebuilderAndSigner` recria todas as entradas ZIP com `ZipEntry(name)`, convertendo `resources.arsc` e bibliotecas nativas de `STORED` para `DEFLATED`. O arquivo continua passando na verificação criptográfica do `apksig`, mas fica incompatível com a regra de instalação do Android 11+ para apps com target 30 ou superior. O manifesto também mantém `extractNativeLibs=false` enquanto o caminho comprime `.so`.

A integração direta de todas as engines não é viável como simples dependência Gradle. Medições reais no APK local indicaram:

| Engine | Medição | Conclusão |
|---|---:|---|
| JADX 1.5.6 | 11.692 classes, 0 erros, 54–57 s, heap mínimo observado 768 MB | Exige orçamento de RAM, timeout e cancelamento |
| JADX com recursos | 11.692 classes, 157 recursos, cerca de 49–70 s | Não deve rodar sem limites |
| Baksmali 3.0.9 | 23.059 arquivos Smali, cerca de 364 s, 266 MB | Operação pesada, sob demanda |
| ARSCLib 1.4.0 | Manifesto editado e APK reempacotado; heap de 128 MB aprovado | Melhor candidato nativo para AXML/ARSC e ZIP |
| `apksig` 9.0.1 | 2.097 method IDs; verificação em 96–480 ms no desktop | Viável para assinatura e verificação |
| Stack completo | 77.523 method IDs antes do app | Com o app atual, exige pelo menos 4 DEX |

A próxima fase deve corrigir segurança, preservação ZIP, verificação pós-assinatura e estados de edição antes de integrar engines maiores.

## 2. Método e escopo

Foram executados:

- Leitura dos arquivos Kotlin, recursos, manifesto, Gradle e testes.
- Inventário de 20 arquivos Kotlin de produção e 3.277 linhas Kotlin totais incluindo testes.
- Build Debug, testes unitários, lint e compilação dos testes instrumentados.
- Leitura do projeto Python, com 34 arquivos Python, 5.939 linhas de produção e 2.413 linhas de testes.
- Execução real de JADX, Apktool, Smali/Baksmali, ARSCLib, `apksig`, `d8` e `zipalign`.
- Comparação de hashes, compressão e alinhamento antes e depois da reconstrução.
- Verificação adversarial dos achados quando os agentes responderam. Falhas 502 dos agentes restantes não foram tratadas como evidência positiva; esses pontos foram mantidos apenas quando confirmados localmente.

A evidência bruta está em [audit-verdicts-raw.txt](audit-verdicts-raw.txt).

## 3. Inventário Android atual

### Produção

- `MainActivity.kt`, `Navigation.kt`, `NavigationKeys.kt`: uma Activity e um destino.
- `core/axml`: parser binário AXML próprio e modelo de manifesto.
- `core/analyzer`: ZIP, SHA-256, manifesto e varredura de strings.
- `core/editor`: patch in-place de três flags booleanas.
- `core/report`: relatório Markdown.
- `core/storage`: histórico JSON e relatórios Markdown.
- `core/signing`: PKCS12, certificado autoassinado e assinatura v1/v2/v3.
- `core/ai`: quatro prompts e uma chamada HTTP OpenAI-compatible.
- `ui/main`: importação, resultados, histórico, tela avançada e exportação.
- `data`: `DataRepository` e `MainScreenViewModel` não estão ligados à navegação de produção.

### Dependências

- Kotlin 2.3.20, AGP 9.0.1 e Gradle 9.1.0.
- compileSdk/targetSdk 36, minSdk 26.
- Jetpack Compose, Material 3 e Navigation 3.
- `apksig` 9.0.1.
- `androidx.security:security-crypto` 1.1.0-alpha06. A versão estável consultada é 1.1.0.
- BouncyCastle `bcpkix-jdk18on` 1.79.

O diretório `APK_PROJETO/android` não possui `.git`. O checkout Git que contém os commits está em `reaandroid/ReaDroid`. O `keystore.properties` é local e ignorado.

## 4. Validação executada

### Android

O build registrado terminou com:

```text
BUILD SUCCESSFUL in 24m 23s
64 actionable tasks: 64 executed
```

O build incluiu `testDebugUnitTest`, `lintDebug` e `assembleDebugAndroidTest`.

| Classe | Testes | Falhas | Erros |
|---|---:|---:|---:|
| ApkAnalyzerTest | 3 | 0 | 0 |
| AxmlParserTest | 1 | 0 | 0 |
| AxmlEditorTest | 3 | 0 | 0 |
| ReportGeneratorTest | 1 | 0 | 0 |
| ApkSignerHelperTest | 4 | 0 | 0 |
| MainScreenViewModelTest | 2 | 0 | 0 |
| **Total unitário** | **14** | **0** | **0** |
| **Instrumentado compilado** | **3** | **não executado em dispositivo** | **não executado em dispositivo** |

O lint não encontrou erros bloqueantes, mas registrou 25 avisos, incluindo dependências desatualizadas, recursos não usados, `OldTargetApi`, `ObsoleteSdkInt`, `AutoboxingStateCreation`, `UseKtx` e `TrustAllX509TrustManager` em dependência.

### Python

A suíte original foi executada em ambiente isolado:

```text
187 passed, 5 subtests passed in 8.75s
```

Isso comprova o projeto Python, não equivalência do Android.

### Lacunas de teste

Os testes Android usam ZIPs sintéticos e assinatura de payload. Não existe teste automatizado que execute o fluxo completo contra APK real, reconstrua e instale APK, valide `resources.arsc`, use `ApkVerifier`, teste backup, rollback, SAF em dispositivo ou AccessibilityService.

## 5. Achados prioritários

### Alta — senha fixa do keystore

`ApkSignerHelper.kt:19-23` usa `readroid123` como `storePass` e `keyPass`. A chamada de produção em `AdvancedScreen.kt:195-198` não passa `KeystoreConfig`, portanto usa os defaults. O arquivo fica em `context.filesDir/readroid_signing.p12`.

O keystore é criado somente depois de o usuário entrar no fluxo avançado, modificar uma flag existente e assinar. O risco é recuperação do arquivo por backup, transferência ou acesso privilegiado, seguida de abertura com senha publicada no aplicativo.

**Correção FASE 1:** remover defaults secretos, gerar credencial aleatória protegida pelo Android Keystore, usar área excluída de backup e declarar regras explícitas.

### Alta — APK produzido pode ser não instalável

`ApkRebuilderAndSigner.kt:42-47` usa `ZipEntry(entry.name)` para todas as entradas. O método de compressão e o alinhamento não são preservados.

| Variante | Entradas STORED | `resources.arsc` | `.so` | `apksig` |
|---|---:|---|---|---|
| Original | 97 | STORED, alinhado a 4 bytes | STORED e alinhadas a 16 KiB | verificado |
| Rezip atual | 0 | DEFLATED | DEFLATED | verificado |
| ARSCLib | 97 | STORED, alinhado a 4 bytes | STORED e alinhadas a 16 KiB | verificado |

A documentação oficial afirma que apps target 30+ não podem ser instalados com `resources.arsc` comprimido ou desalinhado. Portanto, verificação criptográfica não é prova de instalabilidade.

O APK publicado declara `extractNativeLibs=false`, que pressupõe bibliotecas não comprimidas. O caminho atual contradiz esse requisito.

**Correção FASE 1:** usar escritor que preserve ou aplique `STORED` e alinhamento para `resources.arsc` e `.so`, assinar e verificar antes de liberar.

### Média — ausência de verificação pós-assinatura

Não há `ApkVerifier` em `app/src/main`. `signApk` chama `apkSigner.sign()`, calcula SHA-256 e retorna sucesso. SHA-256 não valida assinatura APK.

O Python possui `verify_apk()` e interrompe o pipeline quando falha. O Android não possui equivalente.

**Correção FASE 1:** adicionar `ApkVerifier`, conferir v2/v3, devolver issues, remover saída inválida e testar APK corrompido.

### Média — backup permissivo

`AndroidManifest.xml:8` define `android:allowBackup="true"`. Não há `android:dataExtractionRules` nem `android:fullBackupContent` referenciados. Os XMLs existentes são stubs comentados e não são usados.

Histórico e relatórios ficam em `filesDir`. Preferências guardam um blob cifrado, mas o PKCS12 de assinatura fica em `filesDir` com senha fixa.

**Correção FASE 1:** excluir keystore, temporários e dados sensíveis das regras de backup.

### Média — editor AXML limitado e feedback enganoso

`AxmlEditor.kt:47` copia buffer de tamanho fixo. As únicas escritas são os `putInt` em `:116`, `:123` e `:130`, somente para atributos booleanos existentes dentro de `<application>` e com `TYPE_INT_BOOLEAN` em `:111`.

Não há inserção de atributo, elemento ou string pool. `addInternetPermission` em `AxmlEditor.kt:13` não é lido. Os estados da UI começam em `false` e são sempre passados como valores não nulos. Um APK que tenha `allowBackup`, mas não `debuggable`, pode reportar sucesso sem alterar `debuggable`, pois outra flag existente torna `isModified` verdadeiro.

**Correção FASE 1:** usar estado tri-state, informar cada alteração aplicada, falhar quando a alteração solicitada não existir e adicionar testes positivos. Para inclusão de elementos, usar biblioteca AXML/ARSC que suporte crescimento de chunks.

### Baixa — API key visível

`AdvancedScreen.kt:295-296` coloca `ai.apiKey` em `OutlinedTextField` sem `PasswordVisualTransformation`. É uma exposição local de privacidade, não um vazamento automático por logs. A persistência usa `EncryptedSharedPreferences`.

**Correção FASE 1:** mascarar a entrada, revelar temporariamente e nunca incluir a chave em mensagens ou relatórios.

### Baixa — I/O e código não conectado

- Leitura síncrona do histórico ocorre em callback de UI.
- `ContentResolver.query` para nome do documento pode bloquear o fluxo.
- Inicialização de `AiSecurityStore` ocorre durante composição.
- `readStringPoolSimple` é morto e sempre retorna vazio.
- `MainScreenViewModel` e `DataRepository` não estão ligados à produção.
- O README promete cache por SHA-256, mas a abertura recalcula tudo.

## 6. Paridade com Python

| Área | Python | Android atual |
|---|---|---|
| AXML/manifesto | parser, XML texto e fallbacks | parser AXML próprio, sem fallback real |
| JADX | `decompile_with_jadx` | ausente |
| Smali/recursos | `extract_smali_with_apktool` | ausente |
| Edição | cinco quick edits, incluindo INTERNET | três flags existentes |
| Pacote | `rename_package` e referências Smali | ausente |
| Build | apktool build | ausente como pipeline |
| Alinhamento | zipalign | ausente |
| Assinatura | apksigner/jarsigner | apksig v1/v2/v3, sem verify |
| Comparação | `compare_apks` | ausente |
| Preflight | espaço, minSdk e device SDK | ausente |
| Cache | SHA-256 e pruning | ausente |
| Obfuscação | detector de nomes curtos | ausente |
| Agente | ferramentas, read-only/dry-run, propostas, diff, backup e rollback | chat de uma chamada |
| Gateways | múltiplos provedores | uma URL, modelo e chave |
| Idiomas | pt, en, ar, hi | hardcoded em português |
| Histórico | builds, estado e backups | análise JSON e Markdown |
| Layout Inspector | ausente | ausente |

A lógica de segurança do agente, estados, diff, autorização e histórico deve ser reescrita em Kotlin, não empacotada como Python.

## 7. Viabilidade das ferramentas

### JADX

Funcionou no desktop com 11.692 classes e zero erros. Heap mínimo observado no APK real: 768 MB. O núcleo contém AWT/Swing e `javax.imageio`, ausentes no Android.

**Decisão:** isolar núcleo de entrada/decompilação, remover GUI desktop, testar ARM64 e impor limites de RAM, timeout, cancelamento e saída.

### Apktool

Apktool 2.11.0 gerou Smali do APK real antes de falhar em recursos por dependências/stubs desktop e `aapt2`. O Apktool 3.0.3 também usa `AaptManager` e binário `aapt2` externo. Os binários identificados não formam um caminho Android ARM64 pronto.

**Decisão:** não prometer Apktool completo no dispositivo até existir cadeia ARM64 testada. Usar ARSCLib para o subconjunto AXML/ARSC compatível.

### Smali/Baksmali

Baksmali processou 23.059 classes em cerca de 364 segundos e gerou aproximadamente 266 MB. Deve ser operação sob demanda, com limites e limpeza.

### ARSCLib

ARSCLib 1.4.0 editou manifesto, adicionou uma permissão, regravou `resources.arsc`, preservou entradas STORED e produziu APK verificável. Funcionou com heap de 128 MB. Licença identificada: Apache-2.0, exigindo atribuição e arquivos de licença/NOTICE adequados.

### Multidex

O APK atual tem 170.051 method IDs. O conjunto mínimo mediu 40.489. A soma exige pelo menos quatro DEX. O stack completo mediu cerca de 77.523 antes do app.

**Decisão:** integração modular e sob demanda; não adicionar todas as engines em um único `implementation`.

## 8. Status funcional

| Funcionalidade | Status | Evidência |
|---|---|---|
| Importação SAF/cópia | Parcialmente concluído | Fluxo real; UI test não executa dispositivo |
| Análise básica | Parcialmente concluído | 6 testes; sem assinatura/certificado completo |
| Manifest Inspector | Parcialmente concluído | Parser AXML próprio |
| Edição manifesto | Parcialmente concluído | Três sobrescritas booleanas |
| JADX/Java | Pendente | Nenhuma integração Android |
| Smali/Baksmali | Pendente | Nenhum código de produção |
| Editor de recursos | Pendente | Sem workspace extraído |
| Pesquisa global | Pendente | Sem projeto extraído |
| Agente IA | Pendente | Sem ferramentas/propostas/rollback |
| Gateways múltiplos | Pendente | Um endpoint/modelo/chave |
| Reconstrução completa | Pendente | Apenas troca de manifesto |
| Assinatura v1/v2/v3 | Parcialmente concluído | `apksig` assina; não verifica APK |
| Verificação APK | Pendente | Sem `ApkVerifier` em produção |
| Alinhamento | Pendente | Sem zipalign no app |
| Histórico | Parcialmente concluído | Análise JSON/Markdown |
| Layout Inspector | Pendente | Sem AccessibilityService |

## 9. Plano por fases

### FASE 1 — Estabilização

1. Remover senha fixa e proteger material de assinatura.
2. Definir regras de backup.
3. Adicionar `ApkVerifier`.
4. Substituir rezip por escritor que preserve `resources.arsc`, `.so`, compressão e alinhamento.
5. Corrigir tri-state e resultado de edição.
6. Mover todo I/O para dispatchers apropriados.
7. Implementar cache real ou corrigir o README.
8. Adicionar testes de assinatura, verificação, alinhamento, flag ausente e falhas.

### FASE 2 — Engenharia reversa

1. Criar modelo de projeto com original imutável, workspace e manifest de operações.
2. Integrar ARSCLib para AXML/ARSC.
3. Integrar Smali/Baksmali sob demanda.
4. Investigar núcleo JADX compatível com Android sem GUI desktop.
5. Implementar busca paginada e visualizadores antes dos editores.
6. Validar cada caminho contra APK real de teste.

### FASE 3 — Agente

1. Reescrever ferramentas Python como interfaces Kotlin limitadas ao workspace.
2. Implementar modos leitura, proposta e execução autorizada.
3. Vincular aprovação ao hash da proposta e criar backup.
4. Registrar diff, validação e rollback.
5. Testar path escape, arquivo protegido e proposta alterada.

### FASE 4 — Gateways

1. Criar modelo de gateway sem segredo em texto.
2. Implementar adaptadores independentes.
3. Validar HTTPS por padrão.
4. Testar timeout, HTTP não-2xx, JSON inválido e exclusão de credencial.

### FASE 5 — Layout Inspector

1. Declarar AccessibilityService e ativação explícita.
2. Modelar árvore apenas com dados disponíveis.
3. Criar JSON e estado do serviço.
4. Testar serviço desativado, árvore vazia e conteúdo protegido.

### FASE 6 — Builder final

1. Validar workspace, manifesto, recursos e Smali.
2. Reconstruir com cadeia Android ARM64 real ou declarar indisponibilidade.
3. Alinhar, assinar, verificar, calcular SHA-256 e registrar histórico.
4. Testar instalação em dispositivo Android.
5. Gerar Release somente depois dos gates.

## 10. Limitações

- Não havia dispositivo Android conectado; testes instrumentados foram compilados, não executados.
- Decode completo de recursos com Apktool no Android ARM64 não está comprovado.
- O APK usado nas sondagens é o Release local do ReaDroid, não um corpus de terceiros.
- A instalabilidade precisa ser testada depois da correção ZIP.
- O Android tree não é checkout Git independente.
- Avisos de versões não foram atualizados nesta auditoria.

## 11. Conclusão

A FASE 0 foi concluída sem alterações no código do aplicativo. A base atual compila e fornece análise estática básica, mas muitas promessas do produto permanecem pendentes. A próxima alteração segura é a FASE 1, começando por integridade do APK, verificação pós-assinatura, proteção do keystore e correção do feedback de edição. Nenhuma integração de engenharia reversa, agente IA ou AccessibilityService deve ser marcada como concluída antes de testes reais no Android.

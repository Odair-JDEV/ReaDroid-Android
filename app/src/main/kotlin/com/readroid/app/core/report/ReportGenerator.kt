package com.readroid.app.core.report

import com.readroid.app.core.analyzer.ApkInspectionResult
import com.readroid.app.core.analyzer.ResourceTableInspection
import com.readroid.app.core.analyzer.StringScanResult
import com.readroid.app.core.axml.ParsedManifest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Gerador de relatórios em linguagem simples e clara (Markdown),
 * sem terminologia obscura, focado em transparência de dados e segurança estática.
 */
object ReportGenerator {

    private val DANGEROUS_PERMISSIONS = mapOf(
        "android.permission.READ_SMS" to "ler mensagens SMS",
        "android.permission.SEND_SMS" to "enviar SMS",
        "android.permission.RECEIVE_SMS" to "receber SMS",
        "android.permission.READ_CONTACTS" to "ler contatos da agenda",
        "android.permission.WRITE_CONTACTS" to "alterar ou apagar contatos",
        "android.permission.CALL_PHONE" to "fazer chamadas telefônicas",
        "android.permission.READ_CALL_LOG" to "ler histórico de chamadas",
        "android.permission.ACCESS_FINE_LOCATION" to "localização precisa (GPS)",
        "android.permission.ACCESS_COARSE_LOCATION" to "localização aproximada",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "localização em segundo plano",
        "android.permission.CAMERA" to "usar a câmera",
        "android.permission.RECORD_AUDIO" to "gravar áudio/microfone",
        "android.permission.READ_EXTERNAL_STORAGE" to "ler arquivos do dispositivo",
        "android.permission.WRITE_EXTERNAL_STORAGE" to "gravar arquivos no dispositivo",
        "android.permission.MANAGE_EXTERNAL_STORAGE" to "acesso irrestrito aos arquivos",
        "android.permission.READ_PHONE_STATE" to "ler estado e identidade do telefone (IMEI/rede)",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "instalar outros aplicativos (APKs)",
        "android.permission.SYSTEM_ALERT_WINDOW" to "desenhar janelas sobre outros aplicativos",
        "android.permission.QUERY_ALL_PACKAGES" to "listar todos os aplicativos instalados",
        "android.permission.POST_NOTIFICATIONS" to "enviar notificações push",
        "android.permission.BODY_SENSORS" to "ler sensores corporais (frequência cardíaca, etc.)",
        "android.permission.GET_ACCOUNTS" to "ver contas cadastradas no aparelho"
    )

    /**
     * Gera relatório completo em Markdown.
     */
    fun buildMarkdownReport(
        inspection: ApkInspectionResult,
        stringScan: StringScanResult?,
        resourceTable: ResourceTableInspection? = null
    ): String {
        val sb = StringBuilder()
        val manifest = inspection.manifest
        val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())

        sb.append("# Relatório de Análise Estática: ").append(inspection.fileName).append("\n\n")
        sb.append("> Gerado pelo ReaDroid Android em ").append(dateStr).append(" (Offline & Sem Root).\n\n")

        sb.append("## 1. Identidade e Estrutura do Arquivo\n\n")
        sb.append("- **Nome do Arquivo:** `").append(inspection.fileName).append("`\n")
        sb.append("- **Tamanho:** ").append(inspection.fileSizeBytes / 1024).append(" KB (").append(inspection.fileSizeBytes).append(" bytes)\n")
        sb.append("- **SHA-256:** `").append(inspection.sha256).append("`\n")
        sb.append("- **Pacote (applicationId):** `").append(manifest?.packageName ?: "Não identificado").append("`\n")
        sb.append("- **Versão:** ").append(manifest?.versionName ?: "?").append(" (Código: ").append(manifest?.versionCode ?: "?").append(")\n")
        sb.append("- **Compatibilidade Android:** SDK Mínimo ").append(manifest?.minSdkVersion ?: "?").append(" | SDK Alvo ").append(manifest?.targetSdkVersion ?: "?").append("\n")
        sb.append("- **Arquivos de Código (DEX):** ").append(inspection.dexFiles.size).append(" (").append(inspection.dexFiles.joinToString(", ")).append(")\n")
        sb.append("- **Bibliotecas Nativas (.so):** ").append(inspection.nativeLibraries.size).append("\n")
        sb.append("- **Total de Entradas ZIP:** ").append(inspection.zipEntryCount).append("\n\n")

        // 2. Flags de Segurança
        sb.append("## 2. Configurações de Segurança do Manifesto\n\n")
        val app = manifest?.application
        val debuggable = app?.isDebuggable == true
        val allowBackup = app?.allowBackup != false
        val cleartext = app?.usesCleartextTraffic == true

        sb.append("- **Modo Depurável (debuggable):** ").append(if (debuggable) "⚠️ **Ligado** (permite depuração por cabo adb)" else "✅ Desligado (produção)").append("\n")
        sb.append("- **Permite Backup (allowBackup):** ").append(if (allowBackup) "⚠️ **Ativado** (dados podem ser extraídos por backup)" else "✅ Desativado").append("\n")
        sb.append("- **Tráfego HTTP sem TLS (usesCleartextTraffic):** ").append(if (cleartext) "⚠️ **Permitido** (pode enviar dados sem criptografia HTTPS)" else "✅ Não configurado livremente").append("\n\n")

        // 3. Permissões
        val permissions = manifest?.permissions.orEmpty()
        sb.append("## 3. Permissões Requisitadas (").append(permissions.size).append(")\n\n")
        if (permissions.isEmpty()) {
            sb.append("_Nenhuma permissão declarada no manifesto._\n\n")
        } else {
            val sensitive = permissions.filter { it.name in DANGEROUS_PERMISSIONS }
            if (sensitive.isNotEmpty()) {
                sb.append("### ⚠️ Permissões Sensíveis Encontradas\n\n")
                sensitive.forEach { perm ->
                    val descText = DANGEROUS_PERMISSIONS[perm.name] ?: ""
                    sb.append("- **`").append(perm.name).append("`** → _").append(descText).append("_\n")
                }
                sb.append("\n")
            }

            val normal = permissions.filter { it.name !in DANGEROUS_PERMISSIONS }
            if (normal.isNotEmpty()) {
                sb.append("### Outras Permissões\n\n")
                normal.take(25).forEach { perm ->
                    sb.append("- `").append(perm.name).append("`\n")
                }
                if (normal.size > 25) {
                    sb.append("- _... e mais ").append(normal.size - 25).append(" permissões._\n")
                }
                sb.append("\n")
            }
        }

        // 4. Componentes expostos
        val components = manifest?.components.orEmpty()
        val exportedComponents = components.filter { it.exported == true }
        sb.append("## 4. Componentes Expostos (").append(exportedComponents.size).append(" de ").append(components.size).append(")\n\n")
        if (exportedComponents.isEmpty()) {
            sb.append("_Nenhum componente explicitamente exportado para outros apps._\n\n")
        } else {
            exportedComponents.take(30).forEach { comp ->
                sb.append("- **[").append(comp.type.xmlTag).append("]** `").append(comp.name).append("` (Permissão exigida: ").append(comp.permission ?: "Nenhuma").append(")\n")
            }
            if (exportedComponents.size > 30) {
                sb.append("- _... e mais ").append(exportedComponents.size - 30).append(" componentes expostos._\n")
            }
            sb.append("\n")
        }

        // 5. Strings e Redes
        if (stringScan != null) {
            sb.append("## 5. Endereços e Comunicação Extraídos do Código\n\n")
            sb.append("- **Total de URLs extraídas:** ").append(stringScan.urls.size).append("\n")
            sb.append("- **Domínios reais filtrados:** ").append(stringScan.domains.size).append("\n")
            sb.append("- **Candidatos a IPv4:** ").append(stringScan.ipv4Candidates.size).append("\n")
            if (stringScan.isTruncated) {
                sb.append("- _Aviso: A varredura atingiu o teto de segurança e foi truncada._\n")
            }
            sb.append("\n")

            if (stringScan.domains.isNotEmpty()) {
                sb.append("### Domínios em Destaque\n\n")
                stringScan.domains.take(20).forEach { domain ->
                    sb.append("- `").append(domain).append("`\n")
                }
                if (stringScan.domains.size > 20) {
                    sb.append("- _... e mais ").append(stringScan.domains.size - 20).append(" domínios._\n")
                }
                sb.append("\n")
            }
        }

        // 6. Tabela de recursos (inventário somente leitura)
        if (resourceTable != null) {
            sb.append("## 6. Inventário da Tabela de Recursos\n\n")
            sb.append("- **String pool global:** ").append(if (resourceTable.stringPoolPresent) "presente" else "ausente").append("\n")
            sb.append("- **Strings no pool:** ").append(resourceTable.strings.size).append("\n")
            sb.append("- **Pacotes na tabela:** ").append(resourceTable.packageCount).append("\n")
            if (resourceTable.isTruncated) {
                sb.append("- _Aviso: a leitura foi truncada pelos limites de segurança._\n")
            }
            if (resourceTable.unsupportedChunks.isNotEmpty()) {
                sb.append("- _Chunks não interpretados: ").append(resourceTable.unsupportedChunks.joinToString(", ") { "0x${it.toString(16)}" }).append("._\n")
            }
            val sample = resourceTable.strings.take(15)
            if (sample.isNotEmpty()) {
                sb.append("\n### Amostra de Strings do Pool\n\n")
                sample.forEach { entry ->
                    sb.append("- `").append(entry.value.take(120).replace("\n", " ")).append("`\n")
                }
                if (resourceTable.strings.size > sample.size) {
                    sb.append("- _... e mais ").append(resourceTable.strings.size - sample.size).append(" strings._\n")
                }
            }
            sb.append("\n")
        }

        sb.append("---\n")
        sb.append("### Nota de Confidencialidade e Integridade\n")
        sb.append("_Este relatório reflete exclusivamente análise estática de arquivos empacotados. Ausência de indicadores não comprova ausência de ameaças. O app não foi executado._\n")

        return sb.toString()
    }
}

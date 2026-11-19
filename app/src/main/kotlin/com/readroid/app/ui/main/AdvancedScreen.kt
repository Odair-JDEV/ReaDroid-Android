package com.readroid.app.ui.main

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.readroid.app.core.ai.AiApiClient
import com.readroid.app.core.ai.AiSecurityStore
import com.readroid.app.core.ai.AiSettings
import com.readroid.app.core.ai.PromptLibrary
import com.readroid.app.core.analyzer.ApkInspectionResult
import com.readroid.app.core.project.ApkProjectStore
import com.readroid.app.core.project.ManifestSnapshotStore
import com.readroid.app.core.editor.AxmlEditor
import com.readroid.app.core.editor.QuickEditsConfig
import com.readroid.app.core.signing.ApkRebuilderAndSigner
import com.readroid.app.core.signing.ApkSignerHelper
import com.readroid.app.core.signing.SigningResult
import com.readroid.app.ui.theme.Accent
import com.readroid.app.ui.theme.AccentSoft
import com.readroid.app.ui.theme.Amber
import com.readroid.app.ui.theme.AmberSoft
import com.readroid.app.ui.theme.Coral
import com.readroid.app.ui.theme.CoralSoft
import com.readroid.app.ui.theme.InkBorder
import com.readroid.app.ui.theme.InkOverlay
import com.readroid.app.ui.theme.InkRaised
import com.readroid.app.ui.theme.Mint
import com.readroid.app.ui.theme.MintSoft
import com.readroid.app.ui.theme.MonoStyle
import com.readroid.app.ui.theme.TextPrimary
import com.readroid.app.ui.theme.TextSecondary
import com.readroid.app.ui.theme.Violet
import com.readroid.app.ui.theme.VioletSoft
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipFile

/**
 * Área avançada: edição de flags do manifesto, reconstrução com assinatura local
 * e assistente de IA opcional. Fica fora do fluxo guiado de propósito.
 */
@Composable
fun AdvancedScreen(
    apkFile: File?,
    inspection: ApkInspectionResult?,
    reportMarkdown: String?,
    projectId: String? = null
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val aiStore = remember { AiSecurityStore(context) }
    val projectStore = remember { ApkProjectStore(context.filesDir) }

    var setDebuggable by remember { mutableStateOf(false) }
    var setAllowBackup by remember { mutableStateOf(false) }
    var setCleartext by remember { mutableStateOf(false) }
    var requestDebuggable by remember { mutableStateOf(false) }
    var requestAllowBackup by remember { mutableStateOf(false) }
    var requestCleartext by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<SigningResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var rollbackWorking by remember { mutableStateOf(false) }
    var rollbackMessage by remember { mutableStateOf<String?>(null) }
    var rollbackError by remember { mutableStateOf<String?>(null) }

    var ai by remember { mutableStateOf(AiSettings()) }
    var aiAnswer by remember { mutableStateOf<String?>(null) }
    var aiConsent by remember { mutableStateOf(false) }
    var promptIndex by remember { mutableStateOf(0) }

    val signedApk = remember { File(context.cacheDir, "readroid_signed.apk") }

    LaunchedEffect(Unit) {
        ai = withContext(Dispatchers.IO) { runCatching { aiStore.loadSettings() }.getOrElse { AiSettings() } }
    }

    val saveApk = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")
    ) { uri: Uri? ->
        if (uri != null && signedApk.exists()) {
            scope.launch(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        FileInputStream(signedApk).use { it.copyTo(out) }
                    }
                }.onFailure { error = "Não foi possível salvar o APK: ${it.message}" }
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 8.dp, bottom = 26.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text("Recursos avançados", style = MaterialTheme.typography.headlineMedium, color = TextPrimary)
            Text(
                "Para quem já conhece análise de APK. Nada aqui é necessário para entender um aplicativo.",
                color = TextSecondary,
                style = MaterialTheme.typography.bodySmall
            )
        }

        if (apkFile == null || !apkFile.exists()) {
            item {
                NoticeBox(
                    title = "Nenhum APK carregado",
                    body = "Analise um APK na tela inicial para habilitar a edição e a assinatura.",
                    color = Amber,
                    background = AmberSoft
                )
            }
        } else {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = InkRaised)
                ) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Flags do manifesto", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Uma cópia é modificada; o arquivo original permanece intacto.",
                            color = TextSecondary,
                            style = MaterialTheme.typography.bodySmall
                        )
                        ToggleRow("android:debuggable", "Permite depuração por adb", setDebuggable) { setDebuggable = it; requestDebuggable = true }
                        ToggleRow("android:allowBackup", "Permite backup dos dados", setAllowBackup) { setAllowBackup = it; requestAllowBackup = true }
                        ToggleRow("usesCleartextTraffic", "Permite HTTP sem TLS", setCleartext) { setCleartext = it; requestCleartext = true }

                        Button(
                            onClick = {
                                working = true
                                error = null
                                result = null
                                scope.launch {
                                    try {
                                        val signResult = withContext(Dispatchers.IO) {
                                            val manifestBytes = ZipFile(apkFile).use { zip ->
                                                val entry = zip.getEntry("AndroidManifest.xml")
                                                    ?: throw IllegalStateException("O APK não possui AndroidManifest.xml.")
                                                zip.getInputStream(entry).use { it.readBytes() }
                                            }
                                            val edited = AxmlEditor.applyQuickEdits(
                                                manifestBytes,
                                                QuickEditsConfig(
                                                    setDebuggable = setDebuggable.takeIf { requestDebuggable },
                                                    setAllowBackup = setAllowBackup.takeIf { requestAllowBackup },
                                                    setCleartextTraffic = setCleartext.takeIf { requestCleartext }
                                                )
                                            )
                                            if (edited.missingChanges.isNotEmpty()) {
                                                throw IllegalStateException("Não foi possível aplicar: ${edited.missingChanges.joinToString()}. Este editor só altera atributos booleanos existentes.")
                                            }
                                            if (!edited.isModified) {
                                                throw IllegalStateException("Nenhuma flag selecionada difere do valor atual no manifesto.")
                                            }
                                            val unsigned = File(context.cacheDir, "readroid_unsigned.apk")
                                            val operationId = "sign-${System.currentTimeMillis()}"
                                            try {
                                                val snapshotStore = ManifestSnapshotStore(projectStore)
                                                val snapshot = if (projectId != null) snapshotStore.save(projectStore.readProject(projectId), operationId, manifestBytes) else null
                                                ApkRebuilderAndSigner.replaceManifest(
                                                    sourceApk = apkFile,
                                                    outputApk = unsigned,
                                                    newManifestBytes = edited.modifiedBytes
                                                )
                                                val (keystore, keystoreConfig) = ApkSignerHelper.getOrCreateProductionKeystore(
                                                    context,
                                                    File(context.filesDir, "readroid_signing.p12")
                                                )
                                                val signedResult = ApkRebuilderAndSigner.signApk(unsigned, signedApk, keystore, keystoreConfig)
                                                if (projectId != null) {
                                                    projectStore.operationLog(projectId).append(
                                                        operationId = operationId,
                                                        type = "MANIFEST_EDIT_AND_SIGN",
                                                        baseSha256 = projectId,
                                                        inputSha256 = inspection?.sha256,
                                                        outputPath = signedApk.name,
                                                        outputSha256 = signedResult.sha256,
                                                        status = if (signedResult.isSuccess) "COMMITTED" else "FAILED",
                                                        message = if (signedResult.isSuccess) edited.appliedChanges.joinToString() else signedResult.message
                                                    )
                                                }
                                                signedResult
                                            } finally {
                                                unsigned.delete()
                                            }
                                        }
                                        result = signResult
                                    } catch (t: Throwable) {
                                        error = t.message ?: "Falha ao reconstruir o APK."
                                    } finally {
                                        working = false
                                    }
                                }
                            },
                            enabled = !working,
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color.White)
                        ) {
                            if (working) {
                                CircularProgressIndicator(
                                    modifier = Modifier.width(20.dp).height(20.dp),
                                    color = Color.White,
                                    strokeWidth = 2.dp
                                )
                                Spacer(Modifier.width(10.dp))
                                Text("Reconstruindo...")
                            } else {
                                Text("Aplicar e assinar cópia")
                            }
                        }
                    }
                }
            }
        }

        error?.let { message ->
            item { NoticeBox("Não foi possível concluir", message, Coral, CoralSoft) }
        }

        result?.let { signed ->
            item {
                NoticeBox(
                    title = if (signed.isSuccess) "Cópia assinada com a chave local" else "A assinatura falhou",
                    body = signed.message,
                    color = if (signed.isSuccess) Mint else Coral,
                    background = if (signed.isSuccess) MintSoft else CoralSoft
                )
            }
            if (signed.isSuccess) {
                item {
                    Text("A assinatura troca a identidade do desenvolvedor original.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    signed.sha256?.let { Text(it, color = TextSecondary, style = MonoStyle, maxLines = 2, overflow = TextOverflow.Ellipsis) }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = { saveApk.launch("readroid_assinado.apk") }, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp)) {
                        Text("Salvar APK assinado")
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = InkRaised)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
                    Text("Histórico de edições e reversão", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Cada edição guarda uma cópia verificada do manifesto anterior. A reversão gera um novo APK assinado com esses bytes; o original permanece intacto.",
                        color = TextSecondary,
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (projectId == null) {
                        Text("Disponível quando o projeto é persistido.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    } else {
                        val snapshotStore = remember(projectId) { ManifestSnapshotStore(projectStore) }
                        val log = remember(projectId) { projectStore.operationLog(projectId) }
                        val editRecords = runCatching { log.readAll().filter { it.type == "MANIFEST_EDIT_AND_SIGN" && it.status == "COMMITTED" } }.getOrDefault(emptyList())
                        rollbackMessage?.let { Text(it, color = Mint, style = MaterialTheme.typography.bodySmall) }
                        rollbackError?.let { Text(it, color = Coral, style = MaterialTheme.typography.bodySmall) }
                        if (editRecords.isEmpty()) {
                            Text("Nenhuma edição registrada ainda.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                        }
                        editRecords.asReversed().forEach { record ->
                            val hasSnapshot = snapshotStore.find(projectStore.readProject(projectId), record.operationId) != null
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.width(210.dp)) {
                                    Text(record.operationId, color = TextPrimary, style = MonoStyle, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(record.message ?: "", color = TextSecondary, style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                                OutlinedButton(
                                    onClick = {
                                        rollbackWorking = true
                                        rollbackError = null
                                        rollbackMessage = null
                                        scope.launch(Dispatchers.IO) {
                                            try {
                                                val project = projectStore.readProject(projectId)
                                                val snapshot = snapshotStore.find(project, record.operationId)
                                                    ?: throw IllegalStateException("O snapshot desta edição não está disponível.")
                                                val previousBytes = snapshotStore.load(snapshot)
                                                val rollbackId = "rollback-${System.currentTimeMillis()}"
                                                val unsigned = File(context.cacheDir, "readroid_rollback_unsigned.apk")
                                                try {
                                                    snapshotStore.save(project, rollbackId, previousBytes)
                                                    ApkRebuilderAndSigner.replaceManifest(
                                                        sourceApk = apkFile ?: throw IllegalStateException("APK de origem indisponível."),
                                                        outputApk = unsigned,
                                                        newManifestBytes = previousBytes
                                                    )
                                                    val (keystore, keystoreConfig) = ApkSignerHelper.getOrCreateProductionKeystore(
                                                        context,
                                                        File(context.filesDir, "readroid_signing.p12")
                                                    )
                                                    val signedResult = ApkRebuilderAndSigner.signApk(unsigned, signedApk, keystore, keystoreConfig)
                                                    log.append(
                                                        operationId = rollbackId,
                                                        type = "MANIFEST_ROLLBACK",
                                                        baseSha256 = projectId,
                                                        inputSha256 = record.outputSha256,
                                                        outputPath = signedApk.name,
                                                        outputSha256 = signedResult.sha256,
                                                        status = if (signedResult.isSuccess) "COMMITTED" else "FAILED",
                                                        message = "Reversão de ${record.operationId}"
                                                    )
                                                    rollbackMessage = if (signedResult.isSuccess) "Reversão assinada pronta para salvar." else "A reversão falhou: ${signedResult.message}"
                                                    if (signedResult.isSuccess) result = signedResult
                                                } finally {
                                                    unsigned.delete()
                                                }
                                            } catch (t: Throwable) {
                                                rollbackError = t.message ?: "Falha ao reverter a edição."
                                            } finally {
                                                rollbackWorking = false
                                            }
                                        }
                                    },
                                    enabled = !rollbackWorking && hasSnapshot
                                ) {
                                    Text(if (hasSnapshot) "Reverter" else "Sem snapshot")
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = InkRaised)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.width(240.dp)) {
                            Text("Assistente de IA", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                            Text("Opcional e desativado por padrão.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                        }
                        Switch(
                            checked = ai.isEnabled,
                            onCheckedChange = { enabled ->
                                ai = ai.copy(isEnabled = enabled)
                                scope.launch(Dispatchers.IO) { runCatching { aiStore.saveSettings(ai) } }
                            }
                        )
                    }

                    if (ai.isEnabled) {
                        OutlinedTextField(
                            value = ai.providerUrl,
                            onValueChange = { ai = ai.copy(providerUrl = it) },
                            label = { Text("Endereço do provedor") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = ai.modelName,
                            onValueChange = { ai = ai.copy(modelName = it) },
                            label = { Text("Modelo") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = ai.apiKey,
                            onValueChange = { ai = ai.copy(apiKey = it) },
                            label = { Text("Chave (guardada no Android Keystore)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation()
                        )

                        Text("Pergunta", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
                        PromptLibrary.TEMPLATES.forEachIndexed { index, template ->
                            TextButton(onClick = { promptIndex = index }, modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    text = (if (index == promptIndex) "◉  " else "○  ") + template.title,
                                    color = if (index == promptIndex) Accent else TextSecondary,
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        }

                        ToggleRow(
                            "Entendo que o resumo da análise será enviado",
                            "Somente o relatório em texto; nunca o APK nem a chave.",
                            aiConsent
                        ) { aiConsent = it }

                        Button(
                            onClick = {
                                working = true
                                error = null
                                aiAnswer = null
                                scope.launch {
                                    try {
                                        val template = PromptLibrary.TEMPLATES[promptIndex]
                                        val answer = withContext(Dispatchers.IO) {
                                            AiApiClient.executeChatCompletion(
                                                settings = ai,
                                                systemPrompt = "Você é um assistente de análise estática de APK. Responda em português, sem inventar dados que não estejam no relatório.",
                                                userPrompt = template.prompt,
                                                contextData = reportMarkdown ?: "APK: ${inspection?.fileName ?: "desconhecido"}"
                                            )
                                        }
                                        aiAnswer = answer
                                        withContext(Dispatchers.IO) { runCatching { aiStore.saveSettings(ai) } }
                                    } catch (t: Throwable) {
                                        error = t.message ?: "Falha ao consultar a IA."
                                    } finally {
                                        working = false
                                    }
                                }
                            },
                            enabled = !working && aiConsent && ai.apiKey.isNotBlank(),
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            shape = RoundedCornerShape(14.dp)
                        ) { Text(if (working) "Consultando..." else "Perguntar à IA") }
                    }
                }
            }
        }

        aiAnswer?.let { answer ->
            item {
                Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = InkOverlay)) {
                    Column(Modifier.padding(15.dp)) {
                        Text("Resposta", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(6.dp))
                        Text(answer, color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        item {
            NoticeBox(
                title = "O APK analisado nunca é executado",
                body = "Toda a análise é estática e acontece no aparelho.",
                color = Violet,
                background = VioletSoft
            )
        }
    }
}

@Composable
private fun ToggleRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.width(230.dp)) {
            Text(title, color = TextPrimary, style = MaterialTheme.typography.bodyMedium)
            Text(subtitle, color = TextSecondary, style = MaterialTheme.typography.labelSmall)
        }
        Spacer(Modifier.width(8.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun NoticeBox(title: String, body: String, color: Color, background: Color) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = background)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, color = TextPrimary, fontWeight = FontWeight.SemiBold)
            Text(body, color = TextSecondary, style = MaterialTheme.typography.bodySmall)
        }
    }
}

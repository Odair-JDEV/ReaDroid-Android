package com.readroid.app.ui.main

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import com.readroid.app.core.analyzer.ApkAnalyzer
import com.readroid.app.core.analyzer.ApkInspectionResult
import com.readroid.app.core.analyzer.ApkEntryFilter
import com.readroid.app.core.analyzer.ApkEntryInventory
import com.readroid.app.core.analyzer.DexClassInfo
import com.readroid.app.core.analyzer.DexFilter
import com.readroid.app.core.analyzer.DexInventory
import com.readroid.app.core.analyzer.DexInventoryReader
import com.readroid.app.core.analyzer.ApkEntryInventoryReader
import com.readroid.app.core.analyzer.ApkEntryInventoryException
import com.readroid.app.core.analyzer.ApkEntryPagination
import com.readroid.app.core.analyzer.EntryKind
import com.readroid.app.core.analyzer.ResourceTableInspection
import com.readroid.app.core.analyzer.ResourceTablePagination
import com.readroid.app.core.analyzer.StringScanResult
import com.readroid.app.core.axml.ManifestObservation
import com.readroid.app.core.axml.ManifestObservations
import com.readroid.app.core.report.ReportGenerator
import com.readroid.app.core.project.ApkProject
import com.readroid.app.core.project.ApkProjectStore
import com.readroid.app.core.project.WorkspaceBrowser
import com.readroid.app.core.project.WorkspaceEntry
import com.readroid.app.core.project.WorkspaceExtractor
import com.readroid.app.core.project.OperationLog
import com.readroid.app.core.storage.AnalysisHistoryStore
import com.readroid.app.core.storage.HistoryEntry
import com.readroid.app.ui.theme.Accent
import com.readroid.app.ui.theme.AccentSoft
import com.readroid.app.ui.theme.Amber
import com.readroid.app.ui.theme.AmberSoft
import com.readroid.app.ui.theme.Coral
import com.readroid.app.ui.theme.CoralSoft
import com.readroid.app.ui.theme.Ink
import com.readroid.app.ui.theme.InkBorder
import com.readroid.app.ui.theme.InkOverlay
import com.readroid.app.ui.theme.InkRaised
import com.readroid.app.ui.theme.Mint
import com.readroid.app.ui.theme.MintSoft
import com.readroid.app.ui.theme.MonoStyle
import com.readroid.app.ui.theme.TextPrimary
import com.readroid.app.ui.theme.TextSecondary
import com.readroid.app.ui.theme.Violet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private enum class AppPage { HOME, RESULTS, HISTORY, ADVANCED }

/**
 * Neutraliza caracteres de controle, formatantes e bidirecionais antes de exibir
 * conteúdo não confiável (nomes de entradas ZIP, conteúdo de arquivos extraídos).
 * Evita falsificação visual em uma interface de inspeção de segurança.
 */
private fun sanitizeForDisplay(value: String, maxLength: Int = 2_000): String {
    val sanitized = value.map { c ->
        val type = Character.getType(c)
        val isControl = type == Character.CONTROL.toInt() || type == Character.FORMAT.toInt() ||
            type == Character.UNASSIGNED.toInt() || c == '�'
        if (isControl) "�" else c.toString()
    }.joinToString("")
    return if (sanitized.length > maxLength) sanitized.take(maxLength) + "…" else sanitized
}

private data class AnalysisOutcome(
    val inspection: ApkInspectionResult,
    val scan: StringScanResult,
    val report: String,
    val resourceTable: ResourceTableInspection?,
    val entryInventory: ApkEntryInventory?,
    val entryInventoryError: String?
)

/**
 * Extrator ligado ao projeto no momento do uso. O [WorkspaceExtractor] exige um
 * OperationLog específico; este adaptador resolve o log do projeto informado.
 */
private class ProjectBoundWorkspaceExtractor(private val store: ApkProjectStore) :
    com.readroid.app.core.project.WorkspaceExtractorFacade {
    override fun extract(project: ApkProject, requestedPaths: Collection<String>): List<java.io.File> =
        WorkspaceExtractor(store, store.operationLog(project)).extract(project, requestedPaths)
}

@Composable
fun MainScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val historyStore = remember { AnalysisHistoryStore(context) }
    val projectStore = remember { ApkProjectStore(context.filesDir) }
    val workspaceBrowser = remember(projectStore) { WorkspaceBrowser(projectStore, ProjectBoundWorkspaceExtractor(projectStore)) }

    var activeProject by remember { mutableStateOf<ApkProject?>(null) }
    val workingApk = activeProject?.let { project -> File(projectStore.projectDirectory(project.projectId), "original.apk") }

    var page by remember { mutableStateOf(AppPage.HOME) }
    var inspection by remember { mutableStateOf<ApkInspectionResult?>(null) }
    var scan by remember { mutableStateOf<StringScanResult?>(null) }
    var resourceTable by remember { mutableStateOf<ResourceTableInspection?>(null) }
    var entryInventory by remember { mutableStateOf<ApkEntryInventory?>(null) }
    var entryInventoryError by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<String?>(null) }
    var history by remember { mutableStateOf<List<HistoryEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var selectedResultSection by remember { mutableIntStateOf(0) }

    LaunchedEffect(Unit) {
        history = withContext(Dispatchers.IO) { historyStore.getHistory() }
    }

    val exportReport = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/markdown")
    ) { uri: Uri? ->
        val markdown = report ?: return@rememberLauncherForActivityResult
        if (uri != null) {
            scope.launch(Dispatchers.IO) {
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(markdown.toByteArray(Charsets.UTF_8))
                }
            }
        }
    }

    val pickApk = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        loading = true
        error = null
        scope.launch {
            try {
                val outcome = withContext(Dispatchers.IO) {
                    val name = displayName(context, uri)
                    val project = context.contentResolver.openInputStream(uri)?.use { input ->
                        projectStore.importProject(input, name)
                    } ?: error("Não foi possível abrir o arquivo escolhido.")
                    val original = projectStore.originalFile(project)
                    val inspected = ApkAnalyzer.inspectApk(original).copy(fileName = project.displayName)
                    val strings = ApkAnalyzer.scanStrings(original)
                    val resourceTable = runCatching { ApkAnalyzer.inspectResourceTable(original) }
                        .getOrNull()
                    val inventoryResult = runCatching { ApkEntryInventoryReader.read(original) }
                    val markdown = ReportGenerator.buildMarkdownReport(inspected, strings, resourceTable)
                    val savedReport = historyStore.saveReportMarkdown(inspected.sha256, markdown)
                    historyStore.saveEntry(
                        HistoryEntry(
                            sha256 = inspected.sha256,
                            fileName = inspected.fileName,
                            fileSizeBytes = inspected.fileSizeBytes,
                            packageName = inspected.manifest?.packageName,
                            versionName = inspected.manifest?.versionName,
                            analyzedAt = System.currentTimeMillis(),
                            reportFilePath = savedReport.absolutePath
                        )
                    )
                    projectStore.operationLog(project).append(
                        operationId = "import-${project.projectId.take(12)}-${project.importedAt}",
                        type = "IMPORT",
                        baseSha256 = project.originalSha256,
                        inputSha256 = project.originalSha256,
                        outputPath = "original.apk",
                        outputSha256 = project.originalSha256,
                        status = "COMMITTED",
                        message = project.displayName
                    )
                    AnalysisOutcome(inspected, strings, markdown, resourceTable, inventoryResult.getOrNull(), inventoryResult.exceptionOrNull()?.let { e -> (e as? ApkEntryInventoryException)?.message ?: "Não foi possível listar as entradas do APK." }) to project
                }
                inspection = outcome.first.inspection
                scan = outcome.first.scan
                report = outcome.first.report
                resourceTable = outcome.first.resourceTable
                entryInventory = outcome.first.entryInventory
                entryInventoryError = outcome.first.entryInventoryError
                activeProject = outcome.second
                history = withContext(Dispatchers.IO) { historyStore.getHistory() }
                page = AppPage.RESULTS
            } catch (t: Throwable) {
                error = t.message ?: "Não foi possível analisar este APK."
            } finally {
                loading = false
            }
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = Ink,
        topBar = {
            AppHeader(
                onAdvanced = { page = AppPage.ADVANCED },
                showBack = page != AppPage.HOME,
                onBack = { page = AppPage.HOME }
            )
        },
        bottomBar = {
            BottomNav(
                page = page,
                onHome = { page = AppPage.HOME },
                onHistory = { page = AppPage.HISTORY; history = historyStore.getHistory() }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(Ink)
        ) {
            when (page) {
                AppPage.HOME -> HomePage(
                    loading = loading,
                    error = error,
                    historyCount = history.size,
                    onPick = { pickApk.launch(arrayOf("application/vnd.android.package-archive", "application/zip")) },
                    onHistory = { page = AppPage.HISTORY },
                    onHelp = { page = AppPage.ADVANCED }
                )
                AppPage.RESULTS -> ResultsPage(
                    inspection = inspection,
                    scan = scan,
                    resourceTable = resourceTable,
                    entryInventory = entryInventory,
                    entryInventoryError = entryInventoryError,
                    activeProject = activeProject,
                    workspaceBrowser = workspaceBrowser,
                    workingApk = workingApk,
                    report = report,
                    selectedSection = selectedResultSection,
                    onSection = { selectedResultSection = it },
                    onExport = {
                        val base = inspection?.fileName?.substringBeforeLast('.') ?: "analise"
                        exportReport.launch("${base}_relatorio.md")
                    },
                    onPickAnother = { pickApk.launch(arrayOf("application/vnd.android.package-archive", "application/zip")) }
                )
                AppPage.ADVANCED -> AdvancedScreen(
                    apkFile = workingApk,
                    inspection = inspection,
                    reportMarkdown = report,
                    projectId = activeProject?.projectId
                )
                AppPage.HISTORY -> HistoryPage(history = history, onClear = {
                    scope.launch(Dispatchers.IO) {
                        historyStore.clearHistory()
                        history = emptyList()
                    }
                })
            }
        }
    }
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun AppHeader(showBack: Boolean, onBack: () -> Unit, onAdvanced: () -> Unit) {
    TopAppBar(
        modifier = Modifier.statusBarsPadding(),
        title = {
            Column {
                Text("ReaDroid", style = androidx.compose.material3.MaterialTheme.typography.titleLarge, color = TextPrimary)
                Text("Entenda aplicativos com clareza", style = androidx.compose.material3.MaterialTheme.typography.labelSmall, color = TextSecondary)
            }
        },
        navigationIcon = {
            if (showBack) {
                TextButton(onClick = onBack) { Text("‹  Voltar", color = TextSecondary) }
            }
        },
        actions = {
            TextButton(onClick = onAdvanced) { Text("Mais", color = TextSecondary) }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = Ink)
    )
}

@Composable
private fun HomePage(
    loading: Boolean,
    error: String?,
    historyCount: Int,
    onPick: () -> Unit,
    onHistory: () -> Unit,
    onHelp: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 18.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text("Vamos entender um aplicativo juntos", style = androidx.compose.material3.MaterialTheme.typography.displaySmall, color = TextPrimary)
            Spacer(Modifier.height(8.dp))
            Text(
                "Escolha um APK e eu mostro, em linguagem simples, o que ele pede e com quem pode se comunicar.",
                style = androidx.compose.material3.MaterialTheme.typography.bodyLarge,
                color = TextSecondary
            )
        }
        item { StepCard(currentStep = if (loading) 2 else 1) }
        item {
            Button(
                onClick = onPick,
                enabled = !loading,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                shape = RoundedCornerShape(18.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color.White)
            ) {
                if (loading) {
                    CircularProgressIndicator(modifier = Modifier.width(22.dp).height(22.dp), color = Color.White, strokeWidth = 2.dp)
                    Spacer(Modifier.width(10.dp))
                    Text("Lendo o aplicativo...")
                } else {
                    Text("Escolher um APK", style = androidx.compose.material3.MaterialTheme.typography.labelLarge)
                }
            }
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = InkRaised)
            ) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Como funciona", style = androidx.compose.material3.MaterialTheme.typography.titleMedium, color = TextPrimary)
                    SimpleBullet("O arquivo original nunca é alterado")
                    SimpleBullet("A análise acontece no próprio celular")
                    SimpleBullet("Nenhum aplicativo analisado é executado")
                    TextButton(onClick = onHelp, modifier = Modifier.align(Alignment.Start)) {
                        Text("Quero entender melhor", color = Accent)
                    }
                }
            }
        }
        if (error != null) {
            item { NoticeCard(title = "Não consegui ler esse arquivo", body = error, color = Coral, background = CoralSoft) }
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth().clickable(onClick = onHistory),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = InkOverlay)
            ) {
                Row(Modifier.padding(17.dp), verticalAlignment = Alignment.CenterVertically) {
                    BadgeIcon("↺", Accent, AccentSoft)
                    Spacer(Modifier.width(13.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Análises anteriores", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                        Text(if (historyCount == 0) "Ainda não há análises salvas" else "$historyCount análise(s) neste aparelho", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                    }
                    Text("›", color = TextSecondary, fontSize = 26.sp)
                }
            }
        }
    }
}

@Composable
private fun StepCard(currentStep: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = AccentSoft)
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Três passos, sem complicação", color = TextPrimary, fontWeight = FontWeight.SemiBold)
            StepLine(number = "1", text = "Escolher o arquivo", done = currentStep > 1)
            StepLine(number = "2", text = "Ler o que encontramos", done = currentStep > 2)
            StepLine(number = "3", text = "Ver um resumo fácil", done = false)
        }
    }
}

@Composable
private fun StepLine(number: String, text: String, done: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        BadgeIcon(if (done) "✓" else number, if (done) Mint else Accent, if (done) MintSoft else InkOverlay, size = 28.dp)
        Spacer(Modifier.width(10.dp))
        Text(text, color = if (done) TextSecondary else TextPrimary, style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ResultsPage(
    inspection: ApkInspectionResult?,
    scan: StringScanResult?,
    resourceTable: ResourceTableInspection?,
    entryInventory: ApkEntryInventory?,
    entryInventoryError: String?,
    activeProject: ApkProject?,
    workspaceBrowser: WorkspaceBrowser?,
    workingApk: File?,
    report: String?,
    selectedSection: Int,
    onSection: (Int) -> Unit,
    onExport: () -> Unit,
    onPickAnother: () -> Unit
) {
    if (inspection == null) {
        EmptyState("Ainda não há uma análise", "Escolha um APK para começar.", onPickAnother)
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 14.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text("Aqui está o que encontrei", style = androidx.compose.material3.MaterialTheme.typography.headlineMedium, color = TextPrimary)
            Text(inspection.fileName, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        item { OverviewCard(inspection, scan) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ResultPill("Resumo", selectedSection == 0) { onSection(0) }
                ResultPill("Permissões", selectedSection == 1) { onSection(1) }
                ResultPill("Conexões", selectedSection == 2) { onSection(2) }
                ResultPill("Recursos", selectedSection == 3) { onSection(3) }
                ResultPill("Arquivos", selectedSection == 4) { onSection(4) }
                ResultPill("Manifesto", selectedSection == 5) { onSection(5) }
                ResultPill("Código", selectedSection == 6) { onSection(6) }
            }
        }
        when (selectedSection) {
            0 -> item { SimpleSummary(inspection, scan) }
            1 -> item { PermissionSummary(inspection) }
            2 -> item { ConnectionSummary(scan) }
            3 -> item { ResourceTableViewer(resourceTable) }
            4 -> item { EntryBrowser(entryInventory, entryInventoryError, activeProject, workspaceBrowser) }
            5 -> item { ManifestViewer(inspection.manifest) }
            6 -> item { DexBrowser(inspection.dexFiles, workingApk) }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = onExport, modifier = Modifier.weight(1f), shape = RoundedCornerShape(14.dp)) { Text("Salvar relatório") }
                OutlinedButton(onClick = onPickAnother, modifier = Modifier.weight(1f), shape = RoundedCornerShape(14.dp)) { Text("Outro APK") }
            }
        }
        item {
            Text("SHA-256", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
            Text(inspection.sha256, color = TextSecondary, style = MonoStyle, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        if (!report.isNullOrBlank()) {
            item { Text("Análise somente leitura · o APK não foi executado", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall) }
        }
    }
}


@Composable
private fun ManifestViewer(manifest: com.readroid.app.core.axml.ParsedManifest?) {
    if (manifest == null) {
        NoticeCard(
            title = "Manifesto não disponível",
            body = "O AndroidManifest.xml não pôde ser decodificado como AXML válido. Nenhuma estrutura é inferida.",
            color = TextSecondary,
            background = InkOverlay
        )
        return
    }
    var query by remember(manifest) { mutableStateOf("") }
    var offset by remember(manifest) { mutableIntStateOf(0) }
    val observations = ManifestObservations.build(manifest)
    val filtered = ManifestObservations.filter(observations, query)
    val page = ManifestObservations.page(filtered, offset)

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Observações do AndroidManifest.xml", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        Text(
            "Representação estruturada do parser AXML nativo. Não é XML-fonte; referências, namespaces e atributos não reconhecidos podem permanecer sem resolução.",
            color = TextSecondary,
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall
        )
        OutlinedTextField(
            value = query,
            onValueChange = { query = it; offset = 0 },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Buscar nome ou valor") }
        )
        if (page.items.isEmpty()) {
            Text("Nenhuma observação corresponde à busca.", color = TextSecondary)
        } else {
            page.items.forEach { observation ->
                ManifestObservationCard(observation)
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (page.total == 0) "0 de 0" else "${page.offset + 1}-${page.offset + page.items.size} de ${page.total}",
                color = TextSecondary,
                style = androidx.compose.material3.MaterialTheme.typography.labelSmall
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedButton(onClick = { offset = (offset - page.limit).coerceAtLeast(0) }, enabled = page.offset > 0) { Text("Anterior") }
                OutlinedButton(onClick = { page.nextOffset?.let { offset = it } }, enabled = page.nextOffset != null) { Text("Próxima") }
            }
        }
    }
}

@Composable
private fun ManifestObservationCard(observation: ManifestObservation) {
    val highlight = observation.highlight
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = if (highlight) AmberSoft else InkRaised)
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(observation.category.title, color = if (highlight) Amber else Accent, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
                Text(sanitizeForDisplay(observation.label, 256), color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
            }
            Text(
                observation.value?.let { sanitizeForDisplay(it, 1_000) } ?: "não observado",
                color = TextPrimary,
                style = MonoStyle,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun DexBrowser(dexFiles: List<String>, apk: File?) {
    if (dexFiles.isEmpty()) {
        EmptyState("Nenhum arquivo DEX", "Este APK não contém código Dalvik para inventariar.", null)
        return
    }
    if (apk == null) {
        NoticeCard("APK indisponível", "O arquivo original deste projeto não está aberto nesta tela.", TextSecondary, InkOverlay)
        return
    }
    var selectedDex by remember(dexFiles, apk) { mutableStateOf(dexFiles.first()) }
    var query by remember(dexFiles, apk) { mutableStateOf("") }
    var offset by remember(dexFiles, apk) { mutableIntStateOf(0) }
    var inventory by remember(dexFiles, apk) { mutableStateOf<DexInventory?>(null) }
    var loadError by remember(dexFiles, apk) { mutableStateOf<String?>(null) }
    var selectedMethod by remember(dexFiles, apk) { mutableStateOf<com.readroid.app.core.analyzer.DexMethodInfo?>(null) }
    var methodBody by remember(dexFiles, apk) { mutableStateOf<com.readroid.app.core.analyzer.DexMethodBody?>(null) }
    var methodError by remember(dexFiles, apk) { mutableStateOf<String?>(null) }
    var requestId by remember(dexFiles, apk) { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    fun loadDex(name: String) {
        scope.launch(Dispatchers.IO) {
            val result = runCatching { DexInventoryReader.read(apk, name) }
            inventory = result.getOrNull()
            loadError = result.exceptionOrNull()?.message
        }
    }

    LaunchedEffect(selectedDex, apk) {
        inventory = null
        loadError = null
        selectedMethod = null
        methodBody = null
        methodError = null
        loadDex(selectedDex)
    }

    fun openMethod(method: com.readroid.app.core.analyzer.DexMethodInfo) {
        val thisRequest = ++requestId
        selectedMethod = method
        methodBody = null
        methodError = null
        scope.launch(Dispatchers.IO) {
            val result = runCatching { DexInventoryReader.readMethodBody(apk, selectedDex, method.methodIndex) }
            if (requestId == thisRequest && selectedMethod?.methodIndex == method.methodIndex) {
                methodBody = result.getOrNull()
                methodError = result.exceptionOrNull()?.message
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Inventário de código (DEX)", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        Text(
            "Classes e métodos vêm do índice DEX. Toque em um método para ver uma desassemblagem parcial; instruções não reconhecidas ficam marcadas. Nenhum código é executado.",
            color = TextSecondary,
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall
        )
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            dexFiles.take(8).forEach { name ->
                ResultPill(name.removePrefix("classes").removeSuffix(".dex").ifEmpty { "1" }, selectedDex == name) {
                    selectedDex = name; offset = 0
                }
            }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it; offset = 0 },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Buscar classe ou método") }
        )
        when {
            loadError != null -> NoticeCard("Leitura DEX recusada", loadError!!, Coral, CoralSoft)
            inventory == null -> Text("Carregando inventário...", color = TextSecondary)
            else -> {
                val inv = inventory!!
                Text("${inv.classCount} classe(s) · ${inv.methodCount} método(s) no índice · DEX ${inv.version}", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                val filtered = DexInventoryReader.filter(inv, DexFilter(query))
                val classPage = DexInventoryReader.page(filtered, offset)
                if (classPage.items.isEmpty()) {
                    Text("Nenhuma classe corresponde à busca.", color = TextSecondary)
                }
                classPage.items.forEach { cls ->
                    DexClassCard(cls, onMethod = ::openMethod, selectedMethodIndex = selectedMethod?.methodIndex)
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        if (classPage.total == 0) "0 de 0" else "${classPage.offset + 1}-${classPage.offset + classPage.items.size} de ${classPage.total}",
                        color = TextSecondary,
                        style = androidx.compose.material3.MaterialTheme.typography.labelSmall
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(onClick = { offset = (offset - classPage.limit).coerceAtLeast(0) }, enabled = classPage.offset > 0) { Text("Anterior") }
                        OutlinedButton(onClick = { classPage.nextOffset?.let { offset = it } }, enabled = classPage.nextOffset != null) { Text("Próxima") }
                    }
                }
            }
        }
        selectedMethod?.let { method ->
            MethodBodyViewer(method, methodBody, methodError)
        }
    }
}

@Composable
private fun DexClassCard(cls: DexClassInfo, onMethod: (com.readroid.app.core.analyzer.DexMethodInfo) -> Unit, selectedMethodIndex: Int?) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp), colors = CardDefaults.cardColors(containerColor = InkRaised)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(sanitizeForDisplay(cls.descriptor, 512), color = TextPrimary, style = MonoStyle, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(
                buildString {
                    append("${cls.methods.size} método(s)")
                    cls.superclass?.let { append(" · super $it") }
                    cls.sourceFile?.let { append(" · $it") }
                },
                color = TextSecondary,
                style = androidx.compose.material3.MaterialTheme.typography.labelSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            if (cls.methods.isNotEmpty()) {
                cls.methods.take(6).forEach { method ->
                    Text(
                        sanitizeForDisplay("${if (method.direct) "direct" else "virtual"} ${method.name} ${method.descriptor}", 256),
                        color = if (method.methodIndex == selectedMethodIndex) Accent else TextSecondary,
                        style = MonoStyle,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.clickable { onMethod(method) }
                    )
                }
                if (cls.methods.size > 6) Text("E mais ${cls.methods.size - 6} método(s).", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun MethodBodyViewer(
    method: com.readroid.app.core.analyzer.DexMethodInfo,
    body: com.readroid.app.core.analyzer.DexMethodBody?,
    error: String?
) {
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp), colors = CardDefaults.cardColors(containerColor = InkOverlay)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(sanitizeForDisplay(method.descriptor, 512), color = Accent, style = MonoStyle, maxLines = 2, overflow = TextOverflow.Ellipsis)
            when {
                error != null -> NoticeCard("Corpo de método indisponível", error, Coral, CoralSoft)
                body == null -> Text("Carregando corpo...", color = TextSecondary)
                else -> {
                    Text(
                        "${body.registersSize} registrador(es) · ${body.insSize} entrada(s) · ${body.outsSize} chamada(s) · ${body.insnsSize} unidade(s)",
                        color = TextSecondary,
                        style = androidx.compose.material3.MaterialTheme.typography.labelSmall
                    )
                    body.lines.forEach { line ->
                        Text(sanitizeForDisplay(line, 256), color = TextPrimary, style = MonoStyle, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }
    }
}

@Composable
private fun ResourceTableViewer(inspection: ResourceTableInspection?) {
    if (inspection == null) {
        NoticeCard(
            title = "Tabela de recursos não disponível",
            body = "Este APK não apresentou resources.arsc legível dentro dos limites de segurança.",
            color = TextSecondary,
            background = InkOverlay
        )
        return
    }

    var offset by remember(inspection) { mutableIntStateOf(0) }
    val page = ResourceTablePagination.page(inspection, offset)
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Strings observadas em resources.arsc", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        Text(
            "${page.total} strings · ${inspection.packageCount} pacote(s) · ${inspection.chunkCount} chunk(s)",
            color = TextSecondary,
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall
        )
        Text(
            "Inventário global somente leitura. IDs, configurações e aliases não são resolvidos nesta etapa.",
            color = TextSecondary,
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall
        )
        if (page.sourceTruncated) {
            Text("A leitura atingiu um limite de segurança e pode estar incompleta.", color = Amber, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
        }
        if (page.items.isEmpty()) {
            Text("Nenhuma string foi observada nesta tabela.", color = TextSecondary)
        } else {
            page.items.forEach { entry ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = InkRaised)
                ) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("#${entry.index}", color = Accent, style = MonoStyle)
                        Text(
                            entry.value,
                            color = TextPrimary,
                            maxLines = 6,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (page.total == 0) "0 de 0" else "${page.offset + 1}-${page.offset + page.items.size} de ${page.total}",
                color = TextSecondary,
                style = androidx.compose.material3.MaterialTheme.typography.labelSmall
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedButton(onClick = { offset = (offset - page.limit).coerceAtLeast(0) }, enabled = page.offset > 0) { Text("Anterior") }
                OutlinedButton(onClick = { page.nextOffset?.let { offset = it } }, enabled = page.nextOffset != null) { Text("Próxima") }
            }
        }
    }
}


@Composable
private fun EntryBrowser(
    inventory: ApkEntryInventory?,
    error: String?,
    activeProject: ApkProject?,
    browser: WorkspaceBrowser?
) {
    if (error != null) {
        NoticeCard("Não foi possível listar as entradas", error, Coral, CoralSoft)
        return
    }
    if (inventory == null) {
        NoticeCard("Inventário não disponível", "A lista de arquivos não foi carregada nesta análise.", TextSecondary, InkOverlay)
        return
    }
    var query by remember(inventory) { mutableStateOf("") }
    var kind by remember(inventory) { mutableStateOf<EntryKind?>(null) }
    var offset by remember(inventory) { mutableIntStateOf(0) }
    val filtered = ApkEntryInventoryReader.apply(inventory, ApkEntryFilter(query, kind))
    val page = ApkEntryPagination.page(filtered, offset)

    var workspaceEntries by remember(inventory) { mutableStateOf<List<WorkspaceEntry>>(emptyList()) }
    var extractedNow by remember(inventory) { mutableStateOf<List<String>?>(null) }
    var workspaceError by remember(inventory) { mutableStateOf<String?>(null) }
    var workspaceBusy by remember(inventory) { mutableStateOf(false) }
    var viewing by remember(inventory) { mutableStateOf<String?>(null) }
    var viewMode by remember(inventory) { mutableStateOf("text") }
    var textPage by remember(inventory) { mutableStateOf<com.readroid.app.core.project.WorkspaceTextPage?>(null) }
    var hexPage by remember(inventory) { mutableStateOf<com.readroid.app.core.project.WorkspaceHexPage?>(null) }
    var viewError by remember(inventory) { mutableStateOf<String?>(null) }
    var viewBusy by remember(inventory) { mutableStateOf(false) }
    var viewRequestId by remember(inventory) { mutableIntStateOf(0) }
    val viewScope = rememberCoroutineScope()

    fun reloadWorkspace() {
        val project = activeProject ?: return
        val b = browser ?: return
        viewScope.launch(Dispatchers.IO) {
            val list = runCatching { b.listEntries(project) }.getOrDefault(emptyList())
            workspaceEntries = list
        }
    }

    LaunchedEffect(inventory, activeProject) { reloadWorkspace() }

    fun extractEntry(name: String) {
        val project = activeProject ?: return
        val b = browser ?: return
        workspaceBusy = true
        workspaceError = null
        viewScope.launch {
            try {
                val files = withContext(Dispatchers.IO) { b.extract(project, listOf(name)) }
                extractedNow = files.map { it.name }
                reloadWorkspace()
            } catch (t: Throwable) {
                workspaceError = t.message ?: "Falha na extração."
            } finally {
                workspaceBusy = false
            }
        }
    }

    fun openView(name: String) {
        val project = activeProject ?: return
        val b = browser ?: return
        val request = ++viewRequestId
        viewing = name
        viewMode = "text"
        textPage = null
        hexPage = null
        viewError = null
        viewBusy = true
        viewScope.launch {
            val result = withContext(Dispatchers.IO) {
                val text = runCatching { b.readTextPage(project, name) }
                val hex = runCatching { b.readHexPage(project, name, rows = 8) }
                Triple(text, hex, if (text.isFailure && hex.isFailure) (text.exceptionOrNull() ?: hex.exceptionOrNull())?.message ?: "Falha na leitura." else null)
            }
            if (viewRequestId == request && viewing == name) {
                textPage = result.first.getOrNull()
                hexPage = result.second.getOrNull()
                viewError = result.third
                viewBusy = false
            }
        }
    }

    fun closeView() {
        viewRequestId++
        viewing = null
        textPage = null
        hexPage = null
        viewError = null
        viewBusy = false
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Arquivos dentro do APK", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        Text("${inventory.declaredTotal} entrada(s) · ${inventory.entries.size} listada(s)" + if (inventory.truncated) " · lista truncada" else "", color = if (inventory.truncated) Amber else TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
        Text("Somente metadados. A extração é opcional, por arquivo, para visualização limitada.", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = query, onValueChange = { query = it; offset = 0 }, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Buscar por nome") })
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            ResultPill("Todos", kind == null) { kind = null; offset = 0 }
            ResultPill("DEX", kind == EntryKind.DEX) { kind = EntryKind.DEX; offset = 0 }
            ResultPill("Libs", kind == EntryKind.NATIVE_LIB) { kind = EntryKind.NATIVE_LIB; offset = 0 }
            ResultPill("res/", kind == EntryKind.RESOURCE) { kind = EntryKind.RESOURCE; offset = 0 }
            ResultPill("assets/", kind == EntryKind.ASSET) { kind = EntryKind.ASSET; offset = 0 }
        }
        if (page.items.isEmpty()) Text("Nenhuma entrada corresponde à busca.", color = TextSecondary)
        page.items.forEach { entry ->
            val alreadyExtracted = workspaceEntries.any { it.relativePath == entry.name }
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp), colors = CardDefaults.cardColors(containerColor = InkRaised)) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(sanitizeForDisplay(entry.name, maxLength = 512), color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${entry.kind} · comp. ${entry.compressedSize} B · ${entry.size} B · método ${entry.method} · CRC ${entry.crc32.toString(16)}", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (alreadyExtracted) {
                            TextButton(onClick = { openView(entry.name) }) { Text("Visualizar", color = Accent) }
                        } else {
                            TextButton(onClick = { extractEntry(entry.name) }, enabled = !workspaceBusy) {
                                Text(if (workspaceBusy) "Extraindo..." else "Extrair para visualizar", color = Accent)
                            }
                        }
                    }
                }
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(if (page.total == 0) "0 de 0" else "${page.offset + 1}-${page.offset + page.items.size} de ${page.total}", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedButton(onClick = { offset = (offset - page.limit).coerceAtLeast(0) }, enabled = page.offset > 0) { Text("Anterior") }
                OutlinedButton(onClick = { page.nextOffset?.let { offset = it } }, enabled = page.nextOffset != null) { Text("Próxima") }
            }
        }

        if (workspaceError != null) {
            NoticeCard("Extração recusada", workspaceError!!, Coral, CoralSoft)
        }
        if (extractedNow != null) {
            NoticeCard("Extraído para o workspace", "${extractedNow!!.size} arquivo(s): ${extractedNow!!.joinToString()}", Mint, MintSoft)
        }
        if (viewing != null) {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = InkOverlay)) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text(sanitizeForDisplay(viewing!!, maxLength = 512), color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                        TextButton(onClick = { closeView() }) { Text("Fechar", color = Coral) }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        ResultPill("Texto", viewMode == "text") { viewMode = "text" }
                        ResultPill("Hex", viewMode == "hex") { viewMode = "hex" }
                    }
                    if (viewBusy) Text("Carregando...", color = TextSecondary)
                    if (viewError != null) Text(viewError!!, color = Coral, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                    if (viewMode == "text") {
                        textPage?.let { page ->
                            Text(sanitizeForDisplay(page.text), color = TextPrimary, style = MonoStyle, maxLines = 20, overflow = TextOverflow.Ellipsis)
                            Text("bytes ${page.offset}-${page.offset + page.returnedBytes} de ${page.totalBytes}" + if (page.replacedInvalidSequences) " · sequências inválidas substituídas" else "", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
                        }
                    } else {
                        hexPage?.let { page ->
                            page.lines.forEach { line ->
                                Text(sanitizeForDisplay(line, maxLength = 512), color = TextPrimary, style = MonoStyle, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            Text("offset ${page.offset} de ${page.totalBytes}", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun OverviewCard(inspection: ApkInspectionResult, scan: StringScanResult?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = InkRaised)
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BadgeIcon("✓", Mint, MintSoft, size = 38.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(inspection.manifest?.application?.label ?: "Aplicativo analisado", color = TextPrimary, fontWeight = FontWeight.Bold)
                    Text(inspection.manifest?.packageName ?: "Pacote não identificado", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                }
            }
            HorizontalDivider(color = InkBorder)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Metric("Permissões", "${inspection.manifest?.permissions?.size ?: 0}", Amber)
                Metric("Componentes", "${inspection.manifest?.components?.size ?: 0}", Violet)
                Metric("Conexões", "${(scan?.urls?.size ?: 0) + (scan?.domains?.size ?: 0)}", Accent)
            }
        }
    }
}

@Composable
private fun SimpleSummary(inspection: ApkInspectionResult, scan: StringScanResult?) {
    val app = inspection.manifest?.application
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Em palavras simples", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        NoticeCard(
            title = if ((inspection.manifest?.permissions?.size ?: 0) == 0) "Nenhuma permissão declarada" else "${inspection.manifest?.permissions?.size} permissão(ões) pedida(s)",
            body = if ((inspection.manifest?.permissions?.size ?: 0) == 0) "Este APK não declarou acesso especial ao aparelho no manifesto." else "Revise a aba Permissões para entender cada acesso.",
            color = if ((inspection.manifest?.permissions?.size ?: 0) == 0) Mint else Amber,
            background = if ((inspection.manifest?.permissions?.size ?: 0) == 0) MintSoft else AmberSoft
        )
        if (app?.isDebuggable == true || app?.allowBackup == true || app?.usesCleartextTraffic == true) {
            NoticeCard("Vale uma atenção", "Há configurações no manifesto que merecem revisão. Isso não prova que o app seja perigoso.", Amber, AmberSoft)
        } else {
            NoticeCard("Nenhum alerta básico", "Não encontrei essas configurações de atenção no manifesto. A análise é estática e não substitui uma auditoria completa.", Mint, MintSoft)
        }
        Text("Estrutura", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        InfoRow("Arquivo", inspection.fileName)
        InfoRow("Tamanho", "${inspection.fileSizeBytes / 1024 / 1024} MB")
        InfoRow("Código", "${inspection.dexFiles.size} arquivo(s) DEX")
        InfoRow("Bibliotecas nativas", "${inspection.nativeLibraries.size} arquivo(s)")
        if (scan?.isTruncated == true) Text("A varredura atingiu o limite de segurança e pode estar incompleta.", color = Amber, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun PermissionSummary(inspection: ApkInspectionResult) {
    val permissions = inspection.manifest?.permissions.orEmpty()
    if (permissions.isEmpty()) {
        EmptyState("Nenhuma permissão declarada", "O manifesto não pediu acessos especiais.", null)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("O aplicativo pede estes acessos", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        permissions.take(40).forEach { permission ->
            InfoRow(permission.name.removePrefix("android.permission."), permission.name)
        }
        if (permissions.size > 40) Text("E mais ${permissions.size - 40} permissões no arquivo original.", color = TextSecondary)
    }
}

@Composable
private fun ConnectionSummary(scan: StringScanResult?) {
    if (scan == null || (scan.urls.isEmpty() && scan.domains.isEmpty() && scan.ipv4Candidates.isEmpty())) {
        EmptyState("Nenhum endereço encontrado", "Não encontrei URLs, domínios ou IPs nas partes examinadas.", null)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Endereços encontrados no código", color = TextPrimary, fontWeight = FontWeight.SemiBold)
        scan.urls.take(30).forEach { InfoRow("URL", it) }
        scan.domains.take(30).forEach { InfoRow("Domínio", it) }
        scan.ipv4Candidates.take(30).forEach { InfoRow("IP", it) }
        Text("São correspondências de texto, não prova de conexão ou atividade maliciosa.", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun HistoryPage(history: List<HistoryEntry>, onClear: () -> Unit) {
    if (history.isEmpty()) {
        EmptyState("Seu histórico está vazio", "As análises feitas neste aparelho aparecerão aqui.", null)
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 14.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column {
                    Text("Histórico", style = androidx.compose.material3.MaterialTheme.typography.headlineMedium, color = TextPrimary)
                    Text("${history.size} análise(s) salva(s)", color = TextSecondary)
                }
                TextButton(onClick = onClear) { Text("Limpar", color = Coral) }
            }
        }
        items(history) { entry ->
            Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = InkRaised)) {
                Column(Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(entry.fileName, color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(entry.packageName ?: "Pacote não identificado", color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                    Text(SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date(entry.analyzedAt)), color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun BottomNav(page: AppPage, onHome: () -> Unit, onHistory: () -> Unit) {
    Surface(color = InkRaised, tonalElevation = 0.dp, modifier = Modifier.navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 9.dp), horizontalArrangement = Arrangement.SpaceAround) {
            NavButton("⌂", "Início", page == AppPage.HOME, onHome)
            NavButton("↺", "Histórico", page == AppPage.HISTORY, onHistory)
        }
    }
}

@Composable
private fun NavButton(symbol: String, label: String, selected: Boolean, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.clip(RoundedCornerShape(14.dp)).clickable(onClick = onClick).padding(horizontal = 22.dp, vertical = 4.dp)) {
        Text(symbol, color = if (selected) Accent else TextSecondary, fontSize = 22.sp)
        Text(label, color = if (selected) Accent else TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun ResultPill(label: String, selected: Boolean, onClick: () -> Unit) {
    Surface(
        modifier = Modifier.clip(CircleShape).clickable(onClick = onClick),
        color = if (selected) AccentSoft else InkOverlay,
        shape = CircleShape
    ) { Text(label, color = if (selected) TextPrimary else TextSecondary, modifier = Modifier.padding(horizontal = 15.dp, vertical = 9.dp), style = androidx.compose.material3.MaterialTheme.typography.labelMedium) }
}

@Composable
private fun BadgeIcon(symbol: String, foreground: Color, background: Color, size: androidx.compose.ui.unit.Dp = 36.dp) {
    Box(modifier = Modifier.width(size).height(size).clip(CircleShape).background(background), contentAlignment = Alignment.Center) {
        Text(symbol, color = foreground, fontWeight = FontWeight.Bold, fontSize = if (size < 32.dp) 13.sp else 17.sp)
    }
}

@Composable
private fun Metric(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 22.sp)
        Text(label, color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
        Text(label, color = TextSecondary, modifier = Modifier.weight(0.42f), style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
        Text(value, color = TextPrimary, modifier = Modifier.weight(0.58f), style = androidx.compose.material3.MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun NoticeCard(title: String, body: String, color: Color, background: Color) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = background)) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
            BadgeIcon(if (color == Mint) "✓" else "!", color, background.copy(alpha = 0.35f), size = 28.dp)
            Spacer(Modifier.width(10.dp))
            Column {
                Text(title, color = TextPrimary, fontWeight = FontWeight.SemiBold)
                Text(body, color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun SimpleBullet(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("•", color = Mint, fontSize = 20.sp)
        Spacer(Modifier.width(8.dp))
        Text(text, color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun EmptyState(title: String, body: String, action: (() -> Unit)?) {
    Column(Modifier.fillMaxSize().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        BadgeIcon("—", Accent, AccentSoft, size = 54.dp)
        Spacer(Modifier.height(15.dp))
        Text(title, color = TextPrimary, style = androidx.compose.material3.MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(6.dp))
        Text(body, color = TextSecondary, style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
        if (action != null) {
            Spacer(Modifier.height(18.dp))
            Button(onClick = action, shape = RoundedCornerShape(14.dp)) { Text("Escolher APK") }
        }
    }
}

private fun displayName(context: android.content.Context, uri: Uri): String {
    var name: String? = null
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0) name = cursor.getString(index)
        }
    }
    return name ?: "aplicativo.apk"
}

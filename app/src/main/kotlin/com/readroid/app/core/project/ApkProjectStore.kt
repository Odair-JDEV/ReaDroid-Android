package com.readroid.app.core.project

import com.readroid.app.core.analyzer.ApkAnalyzer
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Persiste originais importados em armazenamento privado e fora do cache.
 * Nenhum método desta classe executa conteúdo do APK.
 */
class ApkProjectStore(
    private val filesDir: File,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        const val MAX_IMPORT_BYTES = 2L * 1024 * 1024 * 1024
        private const val PROJECTS_DIR = "projects"
        private const val ORIGINAL_FILE = "original.apk"
        private const val METADATA_FILE = "project.json"
    }

    private val projectsDir = File(filesDir, PROJECTS_DIR)

    fun importProject(
        source: InputStream,
        displayName: String,
        packageName: String? = null,
        versionName: String? = null
    ): ApkProject {
        projectsDir.mkdirs()
        val staging = File(projectsDir, ".import-${clock()}-${System.nanoTime()}.tmp")
        try {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            var size = 0L
            staging.outputStream().buffered().use { output ->
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    size += read
                    require(size <= MAX_IMPORT_BYTES) {
                        "APK excede o limite de importação de ${MAX_IMPORT_BYTES / (1024 * 1024)} MiB."
                    }
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
                output.flush()
            }
            val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
            require(sha256.matches(Regex("[0-9a-f]{64}"))) { "Hash SHA-256 inválido." }
            val projectDir = File(projectsDir, sha256)
            val original = File(projectDir, ORIGINAL_FILE)
            val now = clock()
            if (original.exists()) {
                require(hashFile(original) == sha256 && original.length() == size) {
                    "O original persistido está inconsistente; importação recusada."
                }
                staging.delete()
                val existing = readProject(projectDir)
                val reopened = existing.copy(lastOpenedAt = now)
                writeProjectAtomically(projectDir, reopened)
                return reopened
            }

            require(size > 0L) { "O arquivo importado está vazio." }
            require(hashFile(staging) == sha256) { "Falha ao verificar a cópia do original." }
            projectDir.mkdirs()
            moveAtomically(staging, original)
            val project = ApkProject(
                projectId = sha256,
                displayName = displayName.take(512),
                originalSha256 = sha256,
                originalSizeBytes = size,
                packageName = packageName,
                versionName = versionName,
                importedAt = now,
                lastOpenedAt = now
            )
            writeProjectAtomically(projectDir, project)
            return project
        } catch (t: Throwable) {
            staging.delete()
            throw t
        }
    }

    fun projectDirectory(projectId: String): File {
        requireValidProjectId(projectId)
        return File(projectsDir, projectId)
    }

    fun originalFile(project: ApkProject): File {
        val file = File(projectDirectory(project.projectId), ORIGINAL_FILE)
        require(file.isFile) { "Original do projeto não encontrado." }
        return file
    }

    fun workspaceDirectory(project: ApkProject): File =
        File(projectDirectory(project.projectId), "workspace").also { it.mkdirs() }

    fun operationLog(project: ApkProject): OperationLog = operationLog(project.projectId)

    fun operationLog(projectId: String): OperationLog =
        OperationLog(File(projectDirectory(projectId), "operations"))

    fun verifyOriginalIntegrity(project: ApkProject): Boolean =
        originalFile(project).let { it.length() == project.originalSizeBytes && hashFile(it) == project.originalSha256 }

    fun readProject(projectId: String): ApkProject = readProject(projectDirectory(projectId))

    private fun readProject(directory: File): ApkProject {
        val file = File(directory, METADATA_FILE)
        require(file.isFile) { "Manifesto do projeto não encontrado." }
        val json = JSONObject(file.readText(Charsets.UTF_8))
        require(json.optInt("schemaVersion", 0) == 1) { "Versão de manifesto de projeto não suportada." }
        val id = json.getString("projectId")
        requireValidProjectId(id)
        return ApkProject(
            projectId = id,
            displayName = json.getString("displayName"),
            originalSha256 = json.getString("originalSha256"),
            originalSizeBytes = json.getLong("originalSizeBytes"),
            packageName = json.optString("packageName").takeIf { it.isNotEmpty() },
            versionName = json.optString("versionName").takeIf { it.isNotEmpty() },
            importedAt = json.getLong("importedAt"),
            lastOpenedAt = json.getLong("lastOpenedAt")
        ).also { project ->
            require(project.projectId == project.originalSha256) { "Manifesto com identidade divergente." }
        }
    }

    private fun writeProjectAtomically(directory: File, project: ApkProject) {
        val json = JSONObject().apply {
            put("schemaVersion", 1)
            put("projectId", project.projectId)
            put("displayName", project.displayName)
            put("originalSha256", project.originalSha256)
            put("originalSizeBytes", project.originalSizeBytes)
            put("packageName", project.packageName ?: "")
            put("versionName", project.versionName ?: "")
            put("importedAt", project.importedAt)
            put("lastOpenedAt", project.lastOpenedAt)
        }
        val temporary = File(directory, "$METADATA_FILE.tmp")
        temporary.writeText(json.toString(2), Charsets.UTF_8)
        moveAtomically(temporary, File(directory, METADATA_FILE))
    }

    private fun hashFile(file: File): String = file.inputStream().use { ApkAnalyzer.calculateSha256(it) }

    private fun moveAtomically(from: File, to: File) {
        to.parentFile?.mkdirs()
        try {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.ATOMIC_MOVE)
        } catch (_: java.io.IOException) {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun requireValidProjectId(projectId: String) {
        require(projectId.matches(Regex("[0-9a-f]{64}"))) { "Identificador de projeto inválido." }
    }
}

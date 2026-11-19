package com.readroid.app.core.project

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

class WorkspaceExtractor(
    private val projectStore: ApkProjectStore,
    private val operationLog: OperationLog,
    private val maxEntryBytes: Long = 64L * 1024 * 1024,
    private val maxTotalBytes: Long = 256L * 1024 * 1024,
    private val maxEntries: Int = 5_000
) {
    fun extract(project: ApkProject, requestedPaths: Collection<String>): List<File> {
        require(projectStore.verifyOriginalIntegrity(project)) { "Original do projeto inconsistente; extração recusada." }
        require(requestedPaths.isNotEmpty()) { "Nenhuma entrada foi selecionada." }
        val normalized = requestedPaths.map { validatePath(it) }
        require(normalized.toSet().size == normalized.size) { "Entradas duplicadas após normalização." }
        require(normalized.map { it.lowercase() }.toSet().size == normalized.size) { "Colisão de nomes no sistema de arquivos." }
        require(normalized.size <= maxEntries) { "Número de entradas excede o limite." }

        val workspace = projectStore.workspaceDirectory(project)
        val extracted = mutableListOf<File>()
        var total = 0L
        ZipFile(projectStore.originalFile(project)).use { zip ->
            for (path in normalized) {
                val entry = zip.getEntry(path) ?: throw IllegalArgumentException("Entrada não encontrada: $path")
                require(!entry.isDirectory) { "Diretórios não são extraídos: $path" }
                require(entry.method != 99) { "Entrada criptografada não suportada: $path" }
                val target = File(workspace, path)
                require(isInside(workspace, target)) { "Destino fora do workspace: $path" }
                require(!target.exists()) { "Destino já existe: $path" }
                target.parentFile?.mkdirs()
                var written = 0L
                val digest = MessageDigest.getInstance("SHA-256")
                try {
                    zip.getInputStream(entry).use { input ->
                        target.outputStream().buffered().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                written += read
                                total += read
                                require(written <= maxEntryBytes) { "Entrada excede o limite: $path" }
                                require(total <= maxTotalBytes) { "Extração excede a cota total." }
                                digest.update(buffer, 0, read)
                                output.write(buffer, 0, read)
                            }
                        }
                    }
                    extracted += target
                } catch (t: Throwable) {
                    target.delete()
                    throw t
                }
            }
        }
        val aggregate = extracted.sortedBy { it.relativeTo(workspace).path }.joinToString("\n") {
            it.relativeTo(workspace).path.replace(File.separatorChar, '/') + ":" + hashFile(it)
        }
        operationLog.append(
            operationId = "extract-${System.nanoTime()}", type = "WORKSPACE_EXTRACT",
            baseSha256 = project.originalSha256, inputSha256 = project.originalSha256,
            outputPath = workspace.relativeTo(projectStore.projectDirectory(project.projectId)).path,
            outputSha256 = sha256(aggregate), status = "COMMITTED",
            message = "${extracted.size} entrada(s), $total bytes"
        )
        return extracted
    }

    private fun validatePath(path: String): String {
        require(path.isNotEmpty() && '\u0000' !in path) { "Caminho ZIP inválido." }
        require('\\' !in path && !path.startsWith('/') && !path.startsWith("//")) { "Separador ou caminho absoluto não suportado." }
        require(!Regex("^[A-Za-z]:").containsMatchIn(path)) { "Prefixo de unidade não suportado." }
        val parts = path.split('/')
        require(parts.none { it.isEmpty() || it == "." || it == ".." }) { "Segmento de caminho inválido." }
        require(parts.size <= 16 && path.length <= 512 && parts.all { it.length <= 128 }) { "Caminho excede os limites." }
        return parts.joinToString("/")
    }

    private fun isInside(root: File, child: File): Boolean {
        val rootPath = root.canonicalFile.toPath()
        return child.canonicalFile.toPath().startsWith(rootPath)
    }

    private fun hashFile(file: File): String = file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        while (true) { val read = input.read(buffer); if (read < 0) break; digest.update(buffer, 0, read) }
        digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}

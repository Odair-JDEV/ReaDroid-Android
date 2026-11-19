package com.readroid.app.core.project

import java.io.File
import java.nio.charset.CodingErrorAction

/**
 * Leitura limitada e somente leitura do workspace extraído de um projeto.
 * Nunca executa conteúdo; nunca extrai por conta própria.
 */
data class WorkspaceEntry(
    val relativePath: String,
    val sizeBytes: Long,
    val lastModified: Long
)

data class WorkspaceTextPage(
    val text: String,
    val totalBytes: Long,
    val offset: Long,
    val requestedLimit: Int,
    val returnedBytes: Int,
    val nextOffset: Long?,
    val endedAtEof: Boolean,
    val replacedInvalidSequences: Boolean
)

data class WorkspaceHexPage(
    val lines: List<String>,
    val totalBytes: Long,
    val offset: Long,
    val nextOffset: Long?,
    val truncated: Boolean
)

/** Abstração mínima para extração sob demanda, sem expor o log de operações. */
interface WorkspaceExtractorFacade {
    fun extract(project: ApkProject, requestedPaths: Collection<String>): List<File>
}

class WorkspaceBrowser(
    private val projectStore: ApkProjectStore,
    private val extractor: WorkspaceExtractorFacade
) {

    companion object {
        const val MAX_ENTRIES = 2_000
        const val MAX_FILE_BYTES = 8L * 1024 * 1024
        const val TEXT_PAGE_BYTES = 16 * 1024
        const val HEX_ROWS_PER_PAGE = 64
    }

    fun listEntries(project: ApkProject): List<WorkspaceEntry> {
        val workspace = projectStore.workspaceDirectory(project).canonicalFile
        val out = mutableListOf<WorkspaceEntry>()
        val visited = intArrayOf(0)
        walk(workspace, workspace, out, 0, visited)
        return out.sortedBy { it.relativePath }
    }

    fun hasEntry(project: ApkProject, relativePath: String): Boolean =
        safeResolve(project, relativePath) != null

    fun readTextPage(
        project: ApkProject,
        relativePath: String,
        offset: Long = 0L,
        limitBytes: Int = TEXT_PAGE_BYTES
    ): WorkspaceTextPage {
        require(offset >= 0) { "offset negativo." }
        require(limitBytes in 1..TEXT_PAGE_BYTES) { "limitBytes fora dos limites." }
        val file = safeResolve(project, relativePath)
            ?: throw IllegalArgumentException("Arquivo não encontrado no workspace: $relativePath")
        require(file.length() <= MAX_FILE_BYTES) { "Arquivo excede o limite de leitura." }
        require(offset <= file.length()) { "offset além do fim do arquivo." }

        val start = alignedUtf8Start(file, offset)
        var bytes = readRange(file, start, limitBytes.toLong())
        // Recuar até uma borda completa de code point UTF-8 para não fatiar um caractere.
        if (bytes.isNotEmpty() && nextByteContinues(file, start + bytes.size)) {
            var afterLeading = bytes.size
            while (afterLeading > 0 && (bytes[afterLeading - 1].toInt() and 0xC0) == 0x80) afterLeading--
            val leading = if (afterLeading > 0) bytes[afterLeading - 1].toInt() and 0xff else -1
            val expectedWidth = when {
                leading in 0xC2..0xDF -> 2
                leading in 0xE0..0xEF -> 3
                leading in 0xF0..0xF4 -> 4
                else -> 0
            }
            val continuationBytesPresent = bytes.size - afterLeading
            val cut = when {
                afterLeading == 0 -> 0 // a sequência começou antes desta página
                expectedWidth > 0 && continuationBytesPresent < expectedWidth - 1 -> afterLeading - 1
                else -> bytes.size
            }
            if (cut < bytes.size) bytes = bytes.copyOf(cut)
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val text = decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        val next = (start + bytes.size).takeIf { bytes.isNotEmpty() && it < file.length() }
        return WorkspaceTextPage(
            text = text,
            totalBytes = file.length(),
            offset = start,
            requestedLimit = limitBytes,
            returnedBytes = bytes.size,
            nextOffset = next,
            endedAtEof = next == null,
            replacedInvalidSequences = text.contains('�')
        )
    }

    fun readHexPage(
        project: ApkProject,
        relativePath: String,
        offset: Long = 0L,
        rows: Int = HEX_ROWS_PER_PAGE
    ): WorkspaceHexPage {
        require(offset >= 0) { "offset negativo." }
        require(rows in 1..HEX_ROWS_PER_PAGE) { "rows fora dos limites." }
        val file = safeResolve(project, relativePath)
            ?: throw IllegalArgumentException("Arquivo não encontrado no workspace: $relativePath")
        require(file.length() <= MAX_FILE_BYTES) { "Arquivo excede o limite de leitura." }
        require(offset <= file.length()) { "offset além do fim do arquivo." }
        val bytesPerRow = 16
        val alignedOffset = (offset / bytesPerRow) * bytesPerRow
        val toRead = rows * bytesPerRow
        val raw = readRange(file, alignedOffset, toRead.toLong())
        val lines = buildList {
            for (row in 0 until rows) {
                val rowStart = row * bytesPerRow
                if (rowStart >= raw.size) break
                val count = minOf(bytesPerRow, raw.size - rowStart)
                val slice = raw.copyOfRange(rowStart, rowStart + count)
                val hex = slice.joinToString(" ") { "%02x".format(it) }.padEnd(47)
                val ascii = slice.map { b -> if (b in 0x20..0x7e) (b.toInt().toChar()).toString() else "." }.joinToString("")
                add("%08x  %s  |%s|".format(alignedOffset + rowStart, hex, ascii))
            }
        }
        val nextOffset = (alignedOffset + raw.size).takeIf { raw.isNotEmpty() && it < file.length() }
        return WorkspaceHexPage(
            lines = lines,
            totalBytes = file.length(),
            offset = alignedOffset,
            nextOffset = nextOffset,
            truncated = file.length() > MAX_FILE_BYTES
        )
    }

    /** Extrai as entradas solicitadas via WorkspaceExtractor e devolve os arquivos criados. */
    fun extract(project: ApkProject, requestedPaths: Collection<String>): List<File> =
        extractor.extract(project, requestedPaths)

    /** UTF-8 continuation byte at an exact file offset, or false at EOF. */
    private fun nextByteContinues(file: File, position: Long): Boolean {
        if (position >= file.length()) return false
        return java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(position)
            val value = raf.read()
            value >= 0 && (value and 0xC0) == 0x80
        }
    }

    private fun alignedUtf8Start(file: File, offset: Long): Long {
        if (offset == 0L) return 0L
        return java.io.RandomAccessFile(file, "r").use { raf ->
            var start = offset
            var checked = 0
            while (start > 0 && checked < 3) {
                raf.seek(start)
                val current = raf.read()
                if (current < 0 || (current and 0xC0) != 0x80) break
                start--
                checked++
            }
            start
        }
    }

    private fun readRange(file: File, start: Long, maxBytes: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        file.inputStream().use { input ->
            var skipped = 0L
            val buf = ByteArray(64 * 1024)
            while (skipped < start) {
                val chunk = input.read(buf, 0, minOf(buf.size.toLong(), start - skipped).toInt())
                if (chunk < 0) break
                skipped += chunk
            }
            require(skipped == start) { "Arquivo encolheu durante a leitura." }
            val chunk = ByteArray(64 * 1024)
            var remaining = maxBytes
            while (remaining > 0) {
                val read = input.read(chunk, 0, minOf(chunk.size.toLong(), remaining).toInt())
                if (read < 0) break
                out.write(chunk, 0, read)
                remaining -= read
            }
        }
        return out.toByteArray()
    }

    private fun walk(dir: File, root: File, out: MutableList<WorkspaceEntry>, depth: Int, visited: IntArray) {
        require(depth <= 32) { "Workspace com profundidade anormal." }
        java.nio.file.Files.newDirectoryStream(dir.toPath()).use { stream ->
            val iterator = stream.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                require(visited[0] < MAX_ENTRIES) { "Workspace excede o limite de $MAX_ENTRIES entradas." }
                visited[0]++
                if (java.nio.file.Files.isSymbolicLink(entry)) continue // nunca seguir links: o workspace só tem arquivos regulares
                val child = entry.toFile()
                if (child.isDirectory) walk(child, root, out, depth + 1, visited)
                else out += WorkspaceEntry(
                    relativePath = child.relativeTo(root).invariantSeparatorsPath,
                    sizeBytes = child.length(),
                    lastModified = child.lastModified()
                )
            }
        }
    }

    private fun safeResolve(project: ApkProject, relativePath: String): File? {
        require(relativePath.isNotEmpty() && '\u0000' !in relativePath) { "Caminho inválido." }
        require('\\' !in relativePath &&
            !relativePath.startsWith("/") &&
            relativePath != "." && relativePath != ".." &&
            !relativePath.startsWith("../") && !relativePath.endsWith("/..") &&
            !relativePath.contains("/../") &&
            !relativePath.contains("/./")) { "Caminho suspeito." }
        val workspace = projectStore.workspaceDirectory(project).canonicalFile
        val target = File(workspace, relativePath)
        if (target.canonicalPath != workspace.path && !target.canonicalPath.startsWith(workspace.path + File.separator)) return null
        return target.takeIf { it.isFile }
    }
}

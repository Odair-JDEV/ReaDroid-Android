package com.readroid.app.core.analyzer

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/** Falha estruturada para DEX ausente, truncado ou fora do perfil suportado. */
class DexInspectionException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class DexMethodInfo(
    val name: String,
    val descriptor: String,
    val accessFlags: Int,
    val codeOffset: Int,
    val direct: Boolean
)

data class DexClassInfo(
    val descriptor: String,
    val accessFlags: Int,
    val superclass: String?,
    val sourceFile: String?,
    val methods: List<DexMethodInfo>
)

data class DexInventory(
    val entryName: String,
    val fileSizeBytes: Int,
    val version: String,
    val classCount: Int,
    val methodCount: Int,
    val classes: List<DexClassInfo>
)

data class DexFilter(val query: String = "")

data class DexClassPage(
    val items: List<DexClassInfo>,
    val total: Int,
    val offset: Int,
    val limit: Int,
    val nextOffset: Int?
)

/**
 * Leitor estrutural DEX, sem executar bytecode e sem alegar equivalência a Smali.
 * A leitura é limitada ao arquivo DEX selecionado dentro do APK.
 */
object DexInventoryReader {
    const val MAX_DEX_BYTES = 128 * 1024 * 1024
    const val DEFAULT_PAGE_SIZE = 40

    fun read(apk: File, entryName: String): DexInventory {
        try {
            require(apk.isFile) { "APK não encontrado." }
            require(entryName.matches(Regex("classes(?:[2-9][0-9]*|1[0-9]+)?\\.dex"))) { "Entrada DEX inválida." }
            val bytes = ZipFile(apk).use { zip ->
                val entry = zip.getEntry(entryName) ?: throw DexInspectionException("Entrada DEX não encontrada: $entryName")
                require(!entry.isDirectory) { "Entrada DEX é um diretório." }
                require(entry.size in 1..MAX_DEX_BYTES) { "DEX excede o limite de leitura." }
                zip.getInputStream(entry).use { input -> input.readBounded(MAX_DEX_BYTES) }
            }
            return parse(bytes, entryName)
        } catch (e: DexInspectionException) {
            throw e
        } catch (e: Throwable) {
            throw DexInspectionException("Não foi possível inspecionar $entryName: ${e.message ?: e.javaClass.simpleName}", e)
        }
    }

    fun filter(inventory: DexInventory, filter: DexFilter): List<DexClassInfo> {
        val q = filter.query.trim().lowercase()
        if (q.isEmpty()) return inventory.classes
        return inventory.classes.filter { cls ->
            cls.descriptor.lowercase().contains(q) ||
                cls.methods.any { it.name.lowercase().contains(q) }
        }
    }

    fun page(classes: List<DexClassInfo>, offset: Int, limit: Int = DEFAULT_PAGE_SIZE): DexClassPage {
        require(offset >= 0) { "offset deve ser não negativo." }
        require(limit > 0) { "limit deve ser positivo." }
        val start = offset.coerceAtMost(classes.size)
        val end = (start + limit).coerceAtMost(classes.size)
        return DexClassPage(classes.subList(start, end), classes.size, start, limit, end.takeIf { it < classes.size })
    }

    private fun parse(bytes: ByteArray, entryName: String): DexInventory {
        requireBounds(bytes, 0, 112, "cabeçalho DEX")
        val magic = bytes.copyOfRange(0, 8).toString(Charsets.US_ASCII)
        require(magic.startsWith("dex\n") && magic[7] == '\u0000') { "Magic DEX inválido." }
        val version = magic.substring(4, 7)
        val endian = u4(bytes, 40)
        require(endian == 0x12345678L) { "Endian DEX não suportado." }
        val fileSize = u4(bytes, 32).toInt()
        require(fileSize == bytes.size) { "Tamanho DEX declarado diverge do conteúdo." }
        val stringCount = u4(bytes, 56).toInt()
        val stringOff = u4(bytes, 60).toInt()
        val typeCount = u4(bytes, 64).toInt()
        val typeOff = u4(bytes, 68).toInt()
        val methodCount = u4(bytes, 88).toInt()
        val methodOff = u4(bytes, 92).toInt()
        val classCount = u4(bytes, 96).toInt()
        val classOff = u4(bytes, 100).toInt()
        require(stringCount in 1..1_000_000 && typeCount in 1..1_000_000 && methodCount in 0..2_000_000 && classCount in 0..500_000) { "Contagem DEX fora dos limites." }
        requireTable(bytes, stringOff, stringCount, 4, "string_ids")
        requireTable(bytes, typeOff, typeCount, 4, "type_ids")
        requireTable(bytes, methodOff, methodCount, 8, "method_ids")
        requireTable(bytes, classOff, classCount, 32, "class_defs")

        val strings = Array(stringCount) { i -> readString(bytes, u4(bytes, stringOff + i * 4).toInt()) }
        val descriptors = Array(typeCount) { i -> strings.getOrNull(u4(bytes, typeOff + i * 4).toInt()) ?: throw DexInspectionException("Tipo DEX inválido.") }
        val methods = Array(methodCount) { i ->
            val p = methodOff + i * 8
            val classIdx = u2(bytes, p)
            val typeIdx = u2(bytes, p + 2)
            val nameIdx = u4(bytes, p + 4).toInt()
            DexMethodInfo(strings.getOrNull(nameIdx) ?: "<invalid>", "${descriptors.getOrNull(classIdx) ?: "?"}->${strings.getOrNull(nameIdx) ?: "?"}", 0, 0, false)
        }

        val classes = ArrayList<DexClassInfo>(classCount)
        for (i in 0 until classCount) {
            val p = classOff + i * 32
            val classIdx = u4(bytes, p).toInt()
            val flags = u4(bytes, p + 4).toInt()
            val superIdx = u4(bytes, p + 8).toInt()
            val sourceIdx = u4(bytes, p + 16).toInt()
            val classDataOff = u4(bytes, p + 24).toInt()
            val descriptor = descriptors.getOrNull(classIdx) ?: throw DexInspectionException("Classe DEX inválida.")
            val classMethods = if (classDataOff == 0) emptyList() else parseClassData(bytes, classDataOff, methods)
            classes += DexClassInfo(descriptor, flags, descriptors.getOrNull(superIdx), strings.getOrNull(sourceIdx), classMethods)
        }
        return DexInventory(entryName, bytes.size, version, classes.size, methodCount, classes)
    }

    private fun parseClassData(bytes: ByteArray, offset: Int, methods: Array<DexMethodInfo>): List<DexMethodInfo> {
        var p = offset
        fun readUleb(): Int {
            var value = 0; var shift = 0
            repeat(5) {
                requireBounds(bytes, p, 1, "class_data")
                val b = bytes[p++].toInt() and 0xff
                value = value or ((b and 0x7f) shl shift)
                if ((b and 0x80) == 0) return value
                shift += 7
            }
            throw DexInspectionException("ULEB128 DEX inválido.")
        }
        val staticCount = readUleb(); val instanceCount = readUleb(); val directCount = readUleb(); val virtualCount = readUleb()
        repeat(staticCount + instanceCount) { readUleb(); readUleb() }
        val out = mutableListOf<DexMethodInfo>()
        fun methods(count: Int, direct: Boolean) {
            var idx = 0
            repeat(count) {
                idx += readUleb(); val flags = readUleb(); val code = readUleb()
                val base = methods.getOrNull(idx)
                if (base != null) out += base.copy(accessFlags = flags, codeOffset = code, direct = direct)
            }
        }
        methods(directCount, true); methods(virtualCount, false)
        return out
    }

    private fun readString(bytes: ByteArray, offset: Int): String {
        requireBounds(bytes, offset, 1, "string_data")
        var p = offset; var shift = 0; var length = 0
        repeat(5) {
            requireBounds(bytes, p, 1, "string_data length")
            val b = bytes[p++].toInt() and 0xff
            length = length or ((b and 0x7f) shl shift)
            if ((b and 0x80) == 0) return readUntilNul(bytes, p)
            shift += 7
        }
        throw DexInspectionException("String DEX com length inválido.")
    }

    private fun readUntilNul(bytes: ByteArray, offset: Int): String {
        var end = offset
        while (end < bytes.size && bytes[end].toInt() != 0) end++
        require(end < bytes.size) { "String DEX sem terminador." }
        return bytes.copyOfRange(offset, end).toString(Charsets.UTF_8)
    }

    private fun requireTable(bytes: ByteArray, offset: Int, count: Int, width: Int, label: String) {
        require(offset >= 0 && offset.toLong() + count.toLong() * width <= bytes.size) { "Tabela DEX inválida: $label." }
    }

    private fun requireBounds(bytes: ByteArray, offset: Int, length: Int, label: String) {
        require(offset >= 0 && length >= 0 && offset.toLong() + length <= bytes.size) { "Dados DEX truncados: $label." }
    }

    private fun u2(bytes: ByteArray, offset: Int): Int = ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xffff
    private fun u4(bytes: ByteArray, offset: Int): Long = ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xffffffffL

    private fun java.io.InputStream.readBounded(max: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val n = read(buffer)
            if (n < 0) break
            if (out.size() + n > max) throw DexInspectionException("Conteúdo DEX excede o limite.")
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }
}

package com.readroid.app.core.analyzer

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/** Falha estruturada para DEX ausente, truncado ou fora do perfil suportado. */
class DexInspectionException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class DexMethodInfo(
    val methodIndex: Int,
    val name: String,
    val descriptor: String,
    val accessFlags: Int,
    val codeOffset: Int,
    val direct: Boolean
)

data class DexMethodBody(
    val method: DexMethodInfo,
    val registersSize: Int,
    val insSize: Int,
    val outsSize: Int,
    val insnsSize: Int,
    val lines: List<String>,
    val truncated: Boolean
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

    /**
     * Decodifica o corpo de um método em linhas de desassemblagem mínima.
     * Não é Smali completo: cobre opcodes Dalvik comuns e marca o que não decodificou.
     */
    fun readMethodBody(apk: File, entryName: String, methodIndex: Int): DexMethodBody {
        try {
            require(methodIndex >= 0) { "Índice de método inválido." }
            val bytes = ZipFile(apk).use { zip ->
                val entry = zip.getEntry(entryName) ?: throw DexInspectionException("Entrada DEX não encontrada: $entryName")
                require(entry.size in 1..MAX_DEX_BYTES) { "DEX excede o limite de leitura." }
                zip.getInputStream(entry).use { input -> input.readBounded(MAX_DEX_BYTES) }
            }
            return parseMethodBody(bytes, entryName, methodIndex)
        } catch (e: DexInspectionException) {
            throw e
        } catch (e: Throwable) {
            throw DexInspectionException("Não foi possível ler o corpo de $entryName#$methodIndex: ${e.message ?: e.javaClass.simpleName}", e)
        }
    }

    private fun parseMethodBody(bytes: ByteArray, entryName: String, methodIndex: Int): DexMethodBody {
        val inventory = parse(bytes, entryName)
        val method = inventory.classes.asSequence()
            .flatMap { it.methods.asSequence() }
            .firstOrNull { it.methodIndex == methodIndex }
            ?: throw DexInspectionException("Método não encontrado no índice DEX: $methodIndex")
        if (method.codeOffset == 0) {
            return DexMethodBody(method, 0, 0, 0, 0, listOf("(método abstrato ou nativo; sem corpo)"), false)
        }
        requireBounds(bytes, method.codeOffset, 16, "code_item")
        val registersSize = u2(bytes, method.codeOffset)
        val insSize = u2(bytes, method.codeOffset + 2)
        val outsSize = u2(bytes, method.codeOffset + 4)
        val insnsSize = u4(bytes, method.codeOffset + 12).toInt()
        require(insnsSize in 1..1_000_000) { "Tamanho de instruções inválido." }
        val insnsOffset = method.codeOffset + 16
        requireTable(bytes, insnsOffset, insnsSize, 2, "insns")

        var pc = 0
        val lines = mutableListOf<String>()
        var truncated = false
        while (pc < insnsSize) {
            val firstUnit = u2(bytes, insnsOffset + pc * 2)
            val opcode = firstUnit and 0xff
            val width = instructionWidth(bytes, insnsOffset, pc, opcode, firstUnit, insnsSize)
            val line = decodeInstruction(bytes, insnsOffset, pc, opcode, insnsSize)
            lines += line
            pc += width
            if (lines.size >= MAX_METHOD_LINES) {
                truncated = true
                lines += "... (saída truncada no limite de $MAX_METHOD_LINES linhas)"
                break
            }
        }
        return DexMethodBody(method, registersSize, insSize, outsSize, insnsSize, lines, truncated)
    }

    private fun instructionWidth(bytes: ByteArray, base: Int, pc: Int, opcode: Int, firstUnit: Int, insnsSize: Int): Int {
        val width = when {
            opcode == 0x00 && (firstUnit ushr 8) == 0x01 -> 4 // packed/sparse payload marker
            opcode in setOf(0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x1d, 0x1e, 0x21, 0x27, 0x28, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d) -> 1
            opcode in setOf(0x02, 0x05, 0x08, 0x13, 0x16, 0x19, 0x1a, 0x1c, 0x22, 0x23, 0x29, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72) -> 2
            opcode in setOf(0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78) -> 3
            opcode in 0x7b..0xcf -> 1
            opcode in 0xd0..0xe2 -> 2
            else -> 1
        }
        require(width > 0 && pc + width <= insnsSize) { "Instrução DEX truncada no PC $pc." }
        return width
    }

    private fun decodeInstruction(bytes: ByteArray, insnsOffset: Int, pc: Int, opcode: Int, insnsSize: Int): String {
        val at = { unit: Int -> if (pc + unit < insnsSize) u2(bytes, insnsOffset + (pc + unit) * 2) else 0 }
        val hex = "%04x".format(pc * 2)
        val b1 = at(0) shr 8
        val b2 = at(0) and 0xff
        return when (opcode) {
            0x00 -> "nop"
            0x01 -> "move v$b2, v${at(1) and 0xff}"
            0x0a -> "move-result v$b2"
            0x0e -> "return-void"
            0x0f -> "return v$b2"
            0x10 -> "return-wide v$b2"
            0x11 -> "return-object v$b2"
            0x12 -> "const/4 v$b2, 0x${((at(0) and 0xf00) shr 8).toString(16)}"
            0x13 -> "const/16 v$b2, 0x${at(1).toString(16)}"
            0x14 -> "const v$b2, 0x${(at(1) or (at(2) shl 16)).toString(16)}"
            0x1a -> "const-string v$b2, @string/${at(1)}"
            0x1c -> "const-class v$b2, @type/${at(1)}"
            0x22 -> "new-instance v$b2, @type/${at(1)}"
            0x1b -> "const-string/jumbo v$b2, @string/${(at(1) or (at(2) shl 16))}"
            0x21 -> "throw v$b2"
            0x23 -> "new-array v$b2, v${b1}, @type/${at(1)}"
            0x27 -> "move-exception v$b2"
            0x28 -> "goto +${(at(0) and 0xff00) shr 8}"
            0x29 -> "goto/32 +${(at(1) or (at(2) shl 16))}"
            0x2b -> "packed-switch v$b2, @${(at(1) or (at(2) shl 16))}"
            0x2c -> "sparse-switch v$b2, @${(at(1) or (at(2) shl 16))}"
            in 0x2d..0x31 -> {
                val names = mapOf(0x2d to "cmp", 0x2e to "cmpg", 0x2f to "cmpl", 0x30 to "cmp-long", 0x31 to "cmp-wide")
                "${names[opcode] ?: "cmp"} v$b2, v$b1, v${at(1) and 0xff}"
            }
            0x32 -> "if-eq v$b2, v$b1, +${at(1) and 0xff}"
            0x33 -> "if-ne v$b2, v$b1, +${at(1) and 0xff}"
            0x34 -> "if-lt v$b2, v$b1, +${at(1) and 0xff}"
            0x35 -> "if-ge v$b2, v$b1, +${at(1) and 0xff}"
            0x36 -> "if-gt v$b2, v$b1, +${at(1) and 0xff}"
            0x37 -> "if-le v$b2, v$b1, +${at(1) and 0xff}"
            0x38 -> "if-eqz v$b2, +${at(1) and 0xff}"
            0x39 -> "if-nez v$b2, +${at(1) and 0xff}"
            0x3a -> "if-ltz v$b2, +${at(1) and 0xff}"
            0x3b -> "if-gez v$b2, +${at(1) and 0xff}"
            0x3c -> "if-gtz v$b2, +${at(1) and 0xff}"
            0x3d -> "if-lez v$b2, +${at(1) and 0xff}"
            in 0x44..0x51 -> {
                val names = listOf("aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short")
                "${names[opcode - 0x44]} v$b2, v$b1, v${at(1) and 0xff}"
            }
            in 0x4b..0x54 -> {
                val names = listOf("aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short")
                "${names[opcode - 0x4b]} v$b2, v$b1, v${at(1) and 0xff}"
            }
            0x54 -> "iget v$b2, v$b1, @field/${at(1)}"
            0x59 -> "iput v$b2, v$b1, @field/${at(1)}"
            0x62 -> "sget v$b2, @field/${at(1)}"
            0x69 -> "sput v$b2, @field/${at(1)}"
            0x6e -> "invoke-virtual {v..}, @method/${at(1)}"
            0x6f -> "invoke-super {v..}, @method/${at(1)}"
            0x70 -> "invoke-direct {v..}, @method/${at(1)}"
            0x71 -> "invoke-static {v..}, @method/${at(1)}"
            0x72 -> "invoke-interface {v..}, @method/${at(1)}"
            0x74 -> "invoke-virtual/range {v..}, @method/${at(1)}"
            0x75 -> "invoke-super/range {v..}, @method/${at(1)}"
            0x76 -> "invoke-direct/range {v..}, @method/${at(1)}"
            0x77 -> "invoke-static/range {v..}, @method/${at(1)}"
            0x78 -> "invoke-interface/range {v..}, @method/${at(1)}"
            0x0b, 0x0c, 0x0d -> "move${if (opcode == 0x0b) "-wide" else ""}${if (opcode == 0x0c) "-from16" else ""} v$b2, v${at(1) and 0xff}"
            in 0x7b..0x8f -> {
                val names = listOf("int-to-long", "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double",
                    "float-to-int", "float-to-long", "float-to-double", "double-to-int", "double-to-long", "double-to-float",
                    "int-to-byte", "int-to-char", "int-to-short")
                "${names[opcode - 0x7b]} v$b2, v$b1"
            }
            in 0x90..0xaf -> {
                val op = when (opcode) {
                    0x90 -> "add"; 0x91 -> "sub"; 0x92 -> "mul"; 0x93 -> "div"; 0x94 -> "rem"
                    0x95 -> "and"; 0x96 -> "or"; 0x97 -> "xor"; 0x98 -> "shl"; 0x99 -> "shr"
                    0x9a -> "ushr"
                    else -> null
                }
                if (op != null) "$op v$b2, v$b1, v${at(1) and 0xff}" else "opcode-0x${opcode.toString(16)} v$b2, v$b1, v${at(1) and 0xff}"
            }
            in 0xb0..0xcf -> {
                val families = listOf("add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr")
                val family = families[(opcode - 0xb0) % families.size]
                "$family/2addr v$b2, v$b1"
            }
            0x1d -> "monitor-enter v$b2"
            0x1e -> "monitor-exit v$b2"
            else -> "opcode-0x${opcode.toString(16)} (não decodificado)"
        }
    }

    private const val MAX_METHOD_LINES = 400

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
            DexMethodInfo(i, strings.getOrNull(nameIdx) ?: "<invalid>", "${descriptors.getOrNull(classIdx) ?: "?"}->${strings.getOrNull(nameIdx) ?: "?"}", 0, 0, false)
        }

        val classes = ArrayList<DexClassInfo>(classCount)
        for (i in 0 until classCount) {
            val p = classOff + i * 32
            val classIdx = u4(bytes, p).toInt()
            val flags = u4(bytes, p + 4).toInt()
            val superIdx = u4(bytes, p + 8).toInt()
            val sourceIdx = u4(bytes, p + 16).toInt()
            val classDataOff = u4(bytes, p + 28).toInt()
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

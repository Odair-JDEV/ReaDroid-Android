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
            val highByte = firstUnit ushr 8
            val isPayload = opcode == 0x00 && highByte in 0x01..0x03
            val effectiveOpcode = if (isPayload) 0x100 or highByte else opcode
            val width = instructionWidth(bytes, insnsOffset, pc, effectiveOpcode, firstUnit, insnsSize)
            val line = decodeInstruction(bytes, insnsOffset, pc, effectiveOpcode, insnsSize)
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
        fun unit(index: Int): Int {
            require(pc + index < insnsSize) { "Payload DEX truncado no PC $pc." }
            return u2(bytes, base + (pc + index) * 2)
        }
        val width = when {
            opcode == 0x101 -> 4 + unit(1) * 2 // packed-switch payload
            opcode == 0x102 -> 2 + unit(1) * 4 // sparse-switch payload
            opcode == 0x103 -> 4 + unit(2) * 2 // fill-array-data payload
            opcode == 0x00 -> 1
            opcode in 0x01..0x09 -> when (opcode) { 0x02, 0x05, 0x08 -> 2; 0x03, 0x06, 0x09 -> 3; else -> 1 }
            opcode in 0x0a..0x12 -> 1
            opcode == 0x13 || opcode == 0x15 || opcode == 0x16 || opcode == 0x19 || opcode == 0x1a || opcode == 0x1c || opcode == 0x1f || opcode == 0x20 || opcode == 0x22 || opcode == 0x23 -> 2
            opcode == 0x14 || opcode == 0x17 || opcode == 0x1b || opcode == 0x24 || opcode == 0x25 -> 3
            opcode in 0x1d..0x1e || opcode == 0x21 || opcode == 0x27 -> 1
            opcode in 0x26..0x28 -> if (opcode == 0x26) 3 else 1
            opcode == 0x29 -> 2
            opcode in 0x2a..0x2c -> 3
            opcode in 0x2d..0x3d -> if (opcode <= 0x31) 2 else if (opcode <= 0x37) 2 else 2
            opcode in 0x44..0x6d -> 2
            opcode in 0x6e..0x72 || opcode in 0x74..0x78 -> 3
            opcode == 0x73 || opcode == 0x79 || opcode == 0x7a -> 1
            opcode in 0x7b..0x8f -> 1
            opcode in 0x90..0xaf -> 2
            opcode in 0xb0..0xcf -> 1
            opcode in 0xd0..0xd7 -> 2
            opcode in 0xd8..0xe2 -> 2
            else -> 1
        }
        require(width > 0 && pc + width <= insnsSize) { "Instrução DEX truncada no PC $pc." }
        return width
    }

    private fun decodeInstruction(bytes: ByteArray, insnsOffset: Int, pc: Int, opcode: Int, insnsSize: Int): String {
        fun unit(index: Int): Int = if (pc + index < insnsSize) u2(bytes, insnsOffset + (pc + index) * 2) else 0
        fun signed8(value: Int) = (value shl 24) shr 24
        fun signed16(value: Int) = value.toShort().toInt()
        fun signed32(low: Int, high: Int) = low or (high shl 16)
        fun target(delta: Int) = "0x${(pc + delta).toString(16)}"
        val first = unit(0)
        val a = first ushr 8
        val b = a and 0x0f
        val c = a ushr 4
        val aa = a
        val regB = unit(1) and 0xff
        val regC = unit(1) ushr 8
        return when {
            opcode == 0x00 -> "nop"
            opcode == 0x101 -> "packed-switch-payload (${unit(1)} case(s))"
            opcode == 0x102 -> "sparse-switch-payload (${unit(1)} case(s))"
            opcode == 0x103 -> "array-data-payload (${unit(1)} element width, ${unit(2)} element(s))"
            opcode == 0x01 || opcode == 0x04 || opcode == 0x07 -> "${arrayOf("move", "move-wide", "move-object")[(opcode - 0x01) / 3]} v$b, v$c"
            opcode in 0x02..0x09 -> {
                val names = mapOf(0x02 to "move/from16", 0x03 to "move/16", 0x05 to "move-wide/from16", 0x06 to "move-wide/16", 0x08 to "move-object/from16", 0x09 to "move-object/16")
                "${names[opcode]} v$aa, v$regB${if (opcode in setOf(0x03, 0x06, 0x09)) ", v${unit(2)}" else ""}"
            }
            opcode in 0x0a..0x0d -> "${mapOf(0x0a to "move-result", 0x0b to "move-result-wide", 0x0c to "move-result-object", 0x0d to "move-exception")[opcode]} v$aa"
            opcode == 0x0e -> "return-void"
            opcode in 0x0f..0x11 -> "${mapOf(0x0f to "return", 0x10 to "return-wide", 0x11 to "return-object")[opcode]} v$aa"
            opcode == 0x12 -> "const/4 v$b, ${signed8(a shr 4 shl 4) shr 4}"
            opcode == 0x13 -> "const/16 v$aa, ${signed16(unit(1))}"
            opcode == 0x14 -> "const v$aa, 0x${signed32(unit(1), unit(2)).toUInt().toString(16)}"
            opcode == 0x15 -> "const/high16 v$aa, 0x${(signed16(unit(1)) shl 16).toUInt().toString(16)}"
            opcode == 0x16 -> "const-wide/16 v$aa, ${signed16(unit(1))}"
            opcode == 0x17 -> "const-wide/32 v$aa, ${signed32(unit(1), unit(2))}"
            opcode == 0x18 -> "const-wide v$aa, (wide literal)"
            opcode == 0x19 -> "const-wide/high16 v$aa, 0x${(signed16(unit(1)) shl 48).toULong().toString(16)}"
            opcode == 0x1a -> "const-string v$aa, @string/${unit(1)}"
            opcode == 0x1b -> "const-string/jumbo v$aa, @string/${unit(1) or (unit(2) shl 16)}"
            opcode == 0x1c -> "const-class v$aa, @type/${unit(1)}"
            opcode == 0x1d -> "monitor-enter v$aa"
            opcode == 0x1e -> "monitor-exit v$aa"
            opcode == 0x1f -> "check-cast v$aa, @type/${unit(1)}"
            opcode == 0x20 -> "instance-of v$b, v$c, @type/${unit(1)}"
            opcode == 0x21 -> "array-length v$b, v$c"
            opcode == 0x22 -> "new-instance v$aa, @type/${unit(1)}"
            opcode == 0x23 -> "new-array v$b, v$c, @type/${unit(1)}"
            opcode == 0x24 || opcode == 0x25 -> "filled-new-array${if (opcode == 0x25) "/range" else ""} {registers}, @type/${unit(1)}"
            opcode == 0x26 -> "fill-array-data v$aa, ${target(signed32(unit(1), unit(2)))}"
            opcode == 0x27 -> "throw v$aa"
            opcode == 0x28 -> "goto ${target(signed8(a))}"
            opcode == 0x29 -> "goto/16 ${target(signed16(unit(1)))}"
            opcode == 0x2a -> "goto/32 ${target(signed32(unit(1), unit(2)))}"
            opcode == 0x2b || opcode == 0x2c -> "${if (opcode == 0x2b) "packed" else "sparse"}-switch v$aa, ${target(signed32(unit(1), unit(2)))}"
            opcode in 0x2d..0x31 -> {
                val names = mapOf(0x2d to "cmpl-float", 0x2e to "cmpg-float", 0x2f to "cmpl-double", 0x30 to "cmpg-double", 0x31 to "cmp-long")
                "${names[opcode]} v$b, v$c, v$regB"
            }
            opcode in 0x32..0x37 -> {
                val names = listOf("if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le")
                "${names[opcode - 0x32]} v$b, v$c, ${target(signed16(unit(1)))}"
            }
            opcode in 0x38..0x3d -> {
                val names = listOf("if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez")
                "${names[opcode - 0x38]} v$aa, ${target(signed16(unit(1)))}"
            }
            opcode in 0x44..0x51 -> {
                val ops = listOf("aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short",
                    "aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short")
                val op = ops[opcode - 0x44]
                if (opcode <= 0x4a) "$op v$b, v$c, v$regB" else "$op v$b, v$c, v$regB"
            }
            opcode in 0x52..0x6d -> {
                val fieldOps = listOf("iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short",
                    "iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short",
                    "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short",
                    "sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short")
                val op = fieldOps[opcode - 0x52]
                if (opcode <= 0x5e) "$op v$b, v$c, @field/${unit(1)}"
                else if (opcode <= 0x67) "$op v$aa, @field/${unit(1)}"
                else "$op v$aa, @field/${unit(1)}"
            }
            opcode in 0x6e..0x72 || opcode in 0x74..0x78 -> {
                val isRange = opcode >= 0x74
                val names = listOf("invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface")
                val op = names[if (isRange) opcode - 0x74 else opcode - 0x6e] + if (isRange) "/range" else ""
                val count = a and 0x0f
                val g = a ushr 4
                val regs = if (isRange) "v${unit(2)} .. v${unit(2) + count - 1}" else {
                    val w = unit(2); val rs = listOf(w and 0xf, w ushr 4 and 0xf, w ushr 8 and 0xf, w ushr 12 and 0xf).take((count - 1).coerceAtLeast(0))
                    (rs + if (count > 0) listOf(g) else emptyList()).joinToString(", ") { "v$it" }
                }
                "$op {$regs}, @method/${unit(1)}"
            }
            opcode == 0x7b -> "neg-int v$b, v$c"
            opcode == 0x7c -> "not-int v$b, v$c"
            opcode in 0x7b..0x8f -> "${listOf("neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long", "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double", "float-to-int", "float-to-long", "float-to-double", "double-to-int", "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short")[opcode - 0x7b]} v$b, v$c"
            opcode in 0x90..0xaf -> {
                val names = listOf("add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
                    "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
                    "add-float", "sub-float", "mul-float", "div-float", "rem-float", "add-double", "sub-double", "mul-double", "div-double", "rem-double")
                "${names[opcode - 0x90]} v$b, v$c, v$regB"
            }
            opcode in 0xb0..0xcf -> "${listOf("add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr")[(opcode - 0xb0) % 11]}-2addr v$b, v$c"
            opcode in 0xd0..0xd7 -> "${listOf("add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16")[opcode - 0xd0]} v$b, v$c, ${signed16(unit(1))}"
            opcode in 0xd8..0xe2 -> "${listOf("add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8")[opcode - 0xd8]} v$aa, v$regB, ${signed8(unit(1) ushr 8)}"
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

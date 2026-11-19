package com.readroid.app.core.axml

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Exceção lançada quando a estrutura do AXML está truncada ou é inválida.
 */
class AxmlException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Evento do parser AXML: Start Element ou End Element.
 */
sealed class AxmlEvent {
    data class StartElement(
        val tag: String,
        val attributes: Map<String, String>
    ) : AxmlEvent()

    data class EndElement(val tag: String) : AxmlEvent()
}

/**
 * Leitor nativo de AndroidManifest.xml binário (AXML) em Kotlin puro.
 * Sem dependências externas, executa com alta velocidade e baixo consumo de memória.
 */
object AxmlParser {

    private const val AXML_MAGIC = 0x00080003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103

    // Tipos de dados de atributos AXML
    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    // Mapeamento de resource IDs conhecidos para atributos padrão do Android
    private val KNOWN_RES_IDS: Map<Int, String> = mapOf(
        0x01010001 to "label",
        0x01010003 to "name",
        0x01010006 to "permission",
        0x0101000E to "enabled",
        0x0101000F to "debuggable",
        0x01010010 to "exported",
        0x0101020C to "minSdkVersion",
        0x0101021B to "versionCode",
        0x0101021C to "versionName",
        0x0101026C to "maxSdkVersion",
        0x01010270 to "targetSdkVersion",
        0x01010280 to "allowBackup",
        0x010104EC to "usesCleartextTraffic"
    )

    /**
     * Decodifica os bytes de um AndroidManifest.xml binário diretamente em [ParsedManifest].
     */
    fun parse(data: ByteArray): ParsedManifest {
        val events = parseEvents(data)
        return toManifest(events, rawXml = eventsToXml(events))
    }

    /**
     * Decodifica a sequência de eventos de elementos XML.
     */
    fun parseEvents(data: ByteArray): List<AxmlEvent> {
        if (data.size < 8) throw AxmlException("Arquivo pequeno demais para ser um AXML válido (${data.size} bytes).")

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val magic = buffer.short.toInt() and 0xFFFF
        if (magic != 0x0003) throw AxmlException("Assinatura AXML não encontrada (0x0003 esperado, encontrado 0x${magic.toString(16)}).")
        val headerSize = buffer.short.toInt() and 0xFFFF
        val declaredSize = buffer.int
        requireAxmlBounds(headerSize >= 8 && headerSize <= declaredSize && declaredSize <= data.size, "cabeçalho AXML")

        var stringPool: List<String> = emptyList()
        var resourceMap: List<Int> = emptyList()
        val events = mutableListOf<AxmlEvent>()
        var pos = headerSize
        while (pos < declaredSize) {
            requireAxmlBounds(pos + 8 <= declaredSize, "cabeçalho do chunk no offset $pos")
            buffer.position(pos)
            val chunkType = buffer.short.toInt() and 0xFFFF
            val chunkHeaderSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int
            requireAxmlBounds(chunkHeaderSize >= 8 && chunkSize >= chunkHeaderSize && pos.toLong() + chunkSize <= declaredSize, "chunk 0x${chunkType.toString(16)} no offset $pos")
            val chunkEnd = pos + chunkSize

            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    requireAxmlBounds(chunkHeaderSize >= 28, "cabeçalho do string pool")
                    stringPool = parseStringPool(data, pos)
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    requireAxmlBounds(chunkSize - chunkHeaderSize >= 0 && (chunkSize - chunkHeaderSize) % 4 == 0, "mapa de recursos")
                    val count = (chunkSize - chunkHeaderSize) / 4
                    buffer.position(pos + chunkHeaderSize)
                    resourceMap = List(count) { buffer.int }
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    requireAxmlBounds(chunkHeaderSize == 16 && chunkSize >= 36, "start element")
                    buffer.position(pos + 16)
                    buffer.int // namespace index, resolved only when needed
                    val nameIdx = buffer.int
                    val attrStart = buffer.short.toInt() and 0xFFFF
                    val attrSize = buffer.short.toInt() and 0xFFFF
                    val attrCount = buffer.short.toInt() and 0xFFFF
                    buffer.short // class attribute
                    buffer.short // id attribute
                    buffer.short // style attribute
                    requireAxmlBounds(attrSize == 20 && attrStart >= 20 && 16L + attrStart + attrCount.toLong() * attrSize <= chunkSize, "atributos do start element")
                    requireAxmlBounds(16 + attrStart + attrCount * attrSize <= chunkSize, "atributos do start element")
                    val tagName = stringPool.getOrNull(nameIdx) ?: throw AxmlException("Índice de tag inválido: $nameIdx.")
                    val attributes = LinkedHashMap<String, String>()
                    for (i in 0 until attrCount) {
                        val attrPos = pos + 16 + attrStart + i * attrSize
                        requireAxmlBounds(attrPos + 20 <= chunkEnd, "atributo $i")
                        buffer.position(attrPos)
                        buffer.int // namespace index
                        val nIdx = buffer.int
                        val rawValueIdx = buffer.int
                        val valueSize = buffer.short.toInt() and 0xFFFF
                        buffer.get() // reserved
                        val dataType = buffer.get().toInt() and 0xFF
                        val dataVal = buffer.int
                        requireAxmlBounds(valueSize == 8, "valor do atributo $i")
                        var attrName = stringPool.getOrNull(nIdx).orEmpty()
                        if (attrName.isEmpty() && nIdx in resourceMap.indices) {
                            val resId = resourceMap[nIdx]
                            attrName = KNOWN_RES_IDS[resId] ?: "res_0x${Integer.toHexString(resId)}"
                        }
                        if (attrName.isNotEmpty()) attributes[attrName] = formatValue(stringPool, rawValueIdx, dataType, dataVal)
                    }
                    events.add(AxmlEvent.StartElement(tagName, attributes))
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    requireAxmlBounds(chunkHeaderSize == 16 && chunkSize >= 24, "end element")
                    buffer.position(pos + 20)
                    val nameIdx = buffer.int
                    val tagName = stringPool.getOrNull(nameIdx) ?: throw AxmlException("Índice de tag de fechamento inválido: $nameIdx.")
                    events.add(AxmlEvent.EndElement(tagName))
                }
            }
            pos = chunkEnd
        }
        if (pos != declaredSize) throw AxmlException("Chunks AXML não cobrem o tamanho declarado.")
        if (events.isEmpty()) throw AxmlException("Nenhum elemento XML encontrado no AXML.")
        return events
    }

    private fun requireAxmlBounds(condition: Boolean, label: String) {
        if (!condition) throw AxmlException("Estrutura AXML inválida: $label.")
    }

    fun parseStringPool(data: ByteArray, pos: Int): List<String> {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        if (pos + 28 > data.size) throw AxmlException("String pool truncado.")
        buffer.position(pos + 2)
        val headerSize = buffer.short.toInt() and 0xFFFF
        val chunkSize = buffer.int
        val stringCount = buffer.int
        buffer.int // style count
        val flags = buffer.int
        val stringsStart = buffer.int
        buffer.int // styles start
        if (stringCount <= 0 || stringCount > 200_000) throw AxmlException("Contagem de strings inválida: $stringCount.")
        if (chunkSize < headerSize || pos + chunkSize > data.size) throw AxmlException("String pool com limites inválidos.")

        val offsetsStart = pos + headerSize
        if (offsetsStart.toLong() + stringCount * 4L > pos + chunkSize) throw AxmlException("Offsets do string pool truncados.")
        val offsets = IntArray(stringCount)
        buffer.position(offsetsStart)
        for (i in 0 until stringCount) offsets[i] = buffer.int

        val base = pos + stringsStart
        if (stringsStart < 0 || stringsStart > chunkSize || base > data.size) throw AxmlException("Início do string pool inválido.")
        val strings = ArrayList<String>(stringCount)
        for (offset in offsets) {
            val p = base + offset
            if (offset < 0 || p >= pos + chunkSize) throw AxmlException("Offset de string inválido no pool.")
            strings.add(decodePoolString(data, p, pos + chunkSize, isUtf8 = (flags and 0x100) != 0))
        }
        return strings
    }

    private fun decodePoolString(data: ByteArray, start: Int, end: Int, isUtf8: Boolean): String {
        var cur = start
        if (isUtf8) {
            if (cur >= end) throw AxmlException("String UTF-8 truncada.")
            var charLen = data[cur].toInt() and 0xFF
            cur++
            if ((charLen and 0x80) != 0) {
                if (cur >= end) throw AxmlException("String UTF-8 truncada.")
                charLen = ((charLen and 0x7F) shl 8) or (data[cur].toInt() and 0xFF)
                cur++
            }
            if (cur >= end) throw AxmlException("String UTF-8 truncada.")
            var byteLen = data[cur].toInt() and 0xFF
            cur++
            if ((byteLen and 0x80) != 0) {
                if (cur >= end) throw AxmlException("String UTF-8 truncada.")
                byteLen = ((byteLen and 0x7F) shl 8) or (data[cur].toInt() and 0xFF)
                cur++
            }
            if (byteLen < 0 || cur + byteLen > end) throw AxmlException("String UTF-8 excede o chunk.")
            return String(data, cur, byteLen, StandardCharsets.UTF_8)
        }
        if (cur + 2 > end) throw AxmlException("String UTF-16 truncada.")
        val buffer = ByteBuffer.wrap(data, cur, end - cur).order(ByteOrder.LITTLE_ENDIAN)
        var charLen = buffer.short.toInt() and 0xFFFF
        cur += 2
        if ((charLen and 0x8000) != 0) {
            if (cur + 2 > end) throw AxmlException("String UTF-16 truncada.")
            charLen = ((charLen and 0x7FFF) shl 16) or (buffer.short.toInt() and 0xFFFF)
            cur += 2
        }
        val byteLen = charLen * 2
        if (byteLen < 0 || cur + byteLen > end) throw AxmlException("String UTF-16 excede o chunk.")
        return String(data, cur, byteLen, StandardCharsets.UTF_16LE)
    }

    private fun formatValue(strings: List<String>, rawIdx: Int, dataType: Int, dataVal: Int): String {
        if (rawIdx != -1 && rawIdx in strings.indices) {
            val s = strings[rawIdx]
            if (s.isNotEmpty()) return s
        }
        return when (dataType) {
            TYPE_STRING -> strings.getOrElse(dataVal) { "" }
            TYPE_INT_BOOLEAN -> if (dataVal != 0) "true" else "false"
            TYPE_INT_DEC -> dataVal.toString()
            TYPE_INT_HEX -> "0x" + Integer.toHexString(dataVal)
            TYPE_REFERENCE -> "@0x" + String.format("%08x", dataVal)
            else -> "0x" + Integer.toHexString(dataVal)
        }
    }

    fun eventsToXml(events: List<AxmlEvent>): String {
        val sb = StringBuilder()
        var depth = 0

        for (event in events) {
            when (event) {
                is AxmlEvent.StartElement -> {
                    sb.append("  ".repeat(depth))
                    sb.append("<").append(event.tag)
                    for ((k, v) in event.attributes) {
                        val escaped = v.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")
                        val prefix = if (k == "package" || k == "xmlns:android") "" else "android:"
                        sb.append(" ").append(prefix).append(k).append("=\"").append(escaped).append("\"")
                    }
                    sb.append(">\n")
                    depth++
                }
                is AxmlEvent.EndElement -> {
                    depth = (depth - 1).coerceAtLeast(0)
                    sb.append("  ".repeat(depth))
                    sb.append("</").append(event.tag).append(">\n")
                }
            }
        }

        return sb.toString().trimEnd()
    }

    fun toManifest(events: List<AxmlEvent>, rawXml: String? = null): ParsedManifest {
        var packageName: String? = null
        var versionCode: String? = null
        var versionName: String? = null
        var minSdkVersion: String? = null
        var targetSdkVersion: String? = null
        var application = ManifestApplication()
        val permissions = mutableListOf<ManifestPermission>()
        val components = mutableListOf<ManifestComponent>()

        val stack = ArrayDeque<String>()

        for (event in events) {
            when (event) {
                is AxmlEvent.StartElement -> {
                    val parent = stack.lastOrNull()
                    stack.addLast(event.tag)

                    when (event.tag) {
                        "manifest" -> {
                            packageName = event.attributes["package"]
                            versionCode = event.attributes["versionCode"]
                            versionName = event.attributes["versionName"]
                        }
                        "uses-sdk" -> {
                            minSdkVersion = event.attributes["minSdkVersion"]
                            targetSdkVersion = event.attributes["targetSdkVersion"]
                        }
                        "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m" -> {
                            val name = event.attributes["name"]
                            if (!name.isNullOrBlank()) {
                                permissions.add(ManifestPermission(name, event.attributes["maxSdkVersion"]))
                            }
                        }
                        "application" -> {
                            application = ManifestApplication(
                                label = event.attributes["label"],
                                isDebuggable = event.attributes["debuggable"]?.toBooleanStrictOrNull(),
                                allowBackup = event.attributes["allowBackup"]?.toBooleanStrictOrNull(),
                                usesCleartextTraffic = event.attributes["usesCleartextTraffic"]?.toBooleanStrictOrNull()
                            )
                        }
                        "activity", "activity-alias", "service", "receiver", "provider" -> {
                            if (parent == "application") {
                                val cType = ComponentType.fromTag(event.tag)
                                val name = event.attributes["name"] ?: ""
                                val exported = event.attributes["exported"]?.toBooleanStrictOrNull()
                                val perm = event.attributes["permission"]
                                if (cType != null && name.isNotBlank()) {
                                    components.add(ManifestComponent(cType, name, exported, perm))
                                }
                            }
                        }
                    }
                }
                is AxmlEvent.EndElement -> {
                    if (stack.isNotEmpty()) {
                        stack.removeLast()
                    }
                }
            }
        }

        return ParsedManifest(
            packageName = packageName,
            versionCode = versionCode,
            versionName = versionName,
            minSdkVersion = minSdkVersion,
            targetSdkVersion = targetSdkVersion,
            permissions = permissions.sortedBy { it.name },
            application = application,
            components = components,
            rawXml = rawXml
        )
    }
}

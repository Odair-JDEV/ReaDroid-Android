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
        if (data.size < 8) {
            throw AxmlException("Arquivo pequeno demais para ser um AXML válido (${data.size} bytes).")
        }

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val magic = buffer.short.toInt() and 0xFFFF
        if (magic != 0x0003) {
            throw AxmlException("Assinatura AXML não encontrada (0x0003 esperado, encontrado 0x${magic.toString(16)}).")
        }

        val headerSize = buffer.short.toInt() and 0xFFFF
        var pos = headerSize

        var stringPool: List<String> = emptyList()
        var resourceMap: List<Int> = emptyList()
        val events = mutableListOf<AxmlEvent>()

        while (pos + 8 <= data.size) {
            buffer.position(pos)
            val chunkType = buffer.short.toInt() and 0xFFFF
            val chunkHeaderSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int

            if (chunkSize < 8) break

            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    stringPool = parseStringPool(data, pos)
                }
                RES_XML_RESOURCE_MAP_TYPE -> {
                    if (chunkHeaderSize in 8..chunkSize) {
                        val count = (chunkSize - chunkHeaderSize) / 4
                        val map = ArrayList<Int>(count.coerceAtLeast(0))
                        val mapStart = pos + chunkHeaderSize
                        if (mapStart + (count * 4) <= data.size) {
                            buffer.position(mapStart)
                            for (i in 0 until count) {
                                map.add(buffer.int)
                            }
                            resourceMap = map
                        }
                    }
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    if (pos + 36 <= data.size) {
                        buffer.position(pos + 16)
                        val nsIdx = buffer.int
                        val nameIdx = buffer.int
                        val attrStart = buffer.short.toInt() and 0xFFFF
                        val attrSize = buffer.short.toInt() and 0xFFFF
                        val attrCount = buffer.short.toInt() and 0xFFFF

                        val tagName = if (nameIdx in stringPool.indices) stringPool[nameIdx] else "?"
                        val attributes = LinkedHashMap<String, String>()

                        for (i in 0 until attrCount) {
                            val attrPos = pos + 16 + attrStart + (i * attrSize)
                            if (attrPos + 20 <= data.size) {
                                buffer.position(attrPos)
                                val attrNsIdx = buffer.int
                                val nIdx = buffer.int
                                val rawValueIdx = buffer.int
                                val size = buffer.short.toInt() and 0xFFFF
                                val res0 = buffer.get().toInt() and 0xFF
                                val dataType = buffer.get().toInt() and 0xFF
                                val dataVal = buffer.int

                                var attrName = if (nIdx in stringPool.indices) stringPool[nIdx] else ""
                                if (attrName.isEmpty() && nIdx in resourceMap.indices) {
                                    val resId = resourceMap[nIdx]
                                    attrName = KNOWN_RES_IDS[resId] ?: "res_0x${Integer.toHexString(resId)}"
                                }

                                val attrVal = formatValue(stringPool, rawValueIdx, dataType, dataVal)
                                if (attrName.isNotEmpty()) {
                                    attributes[attrName] = attrVal
                                }
                            }
                        }
                        events.add(AxmlEvent.StartElement(tagName, attributes))
                    }
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    if (pos + 24 <= data.size) {
                        buffer.position(pos + 20)
                        val nameIdx = buffer.int
                        val tagName = if (nameIdx in stringPool.indices) stringPool[nameIdx] else "?"
                        events.add(AxmlEvent.EndElement(tagName))
                    }
                }
            }

            pos += chunkSize
        }

        if (events.isEmpty()) {
            throw AxmlException("Nenhum elemento XML encontrado no AXML.")
        }

        return events
    }

    fun parseStringPool(data: ByteArray, pos: Int): List<String> {
        if (pos + 28 > data.size) return emptyList()
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        buffer.position(pos + 2)
        val headerSize = buffer.short.toInt() and 0xFFFF
        val chunkSize = buffer.int
        val stringCount = buffer.int
        val styleCount = buffer.int
        val flags = buffer.int
        val stringsStart = buffer.int
        val stylesStart = buffer.int

        val isUtf8 = (flags and 0x100) != 0
        if (stringCount <= 0 || stringCount > 200000) return emptyList()

        val offsets = IntArray(stringCount)
        val offsetsStart = pos + headerSize
        if (offsetsStart + (stringCount * 4) > data.size) return emptyList()

        buffer.position(offsetsStart)
        for (i in 0 until stringCount) {
            offsets[i] = buffer.int
        }

        val base = pos + stringsStart
        val strings = ArrayList<String>(stringCount)

        for (offset in offsets) {
            val p = base + offset
            if (p < 0 || p >= data.size) {
                strings.add("")
                continue
            }

            try {
                if (isUtf8) {
                    var cur = p
                    if (cur >= data.size) { strings.add(""); continue }
                    var charLen = data[cur].toInt() and 0xFF
                    cur++
                    if ((charLen and 0x80) != 0) {
                        if (cur >= data.size) { strings.add(""); continue }
                        charLen = ((charLen and 0x7F) shl 8) or (data[cur].toInt() and 0xFF)
                        cur++
                    }
                    if (cur >= data.size) { strings.add(""); continue }
                    var byteLen = data[cur].toInt() and 0xFF
                    cur++
                    if ((byteLen and 0x80) != 0) {
                        if (cur >= data.size) { strings.add(""); continue }
                        byteLen = ((byteLen and 0x7F) shl 8) or (data[cur].toInt() and 0xFF)
                        cur++
                    }
                    if (cur + byteLen <= data.size) {
                        strings.add(String(data, cur, byteLen, StandardCharsets.UTF_8))
                    } else {
                        strings.add("")
                    }
                } else {
                    var cur = p
                    if (cur + 2 > data.size) { strings.add(""); continue }
                    val buffer2 = ByteBuffer.wrap(data, cur, data.size - cur).order(ByteOrder.LITTLE_ENDIAN)
                    var charLen = buffer2.short.toInt() and 0xFFFF
                    cur += 2
                    if ((charLen and 0x8000) != 0) {
                        if (cur + 2 > data.size) { strings.add(""); continue }
                        val next = buffer2.short.toInt() and 0xFFFF
                        charLen = ((charLen and 0x7FFF) shl 16) or next
                        cur += 2
                    }
                    val byteLen = charLen * 2
                    if (cur + byteLen <= data.size) {
                        strings.add(String(data, cur, byteLen, StandardCharsets.UTF_16LE))
                    } else {
                        strings.add("")
                    }
                }
            } catch (e: Exception) {
                strings.add("")
            }
        }

        return strings
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

package com.readroid.app.core.editor

import com.readroid.app.core.axml.ParsedManifest
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

data class QuickEditsConfig(
    val setDebuggable: Boolean? = null,
    val setAllowBackup: Boolean? = null,
    val setCleartextTraffic: Boolean? = null,
    val addInternetPermission: Boolean = false
)

data class ManifestEditResult(
    val isModified: Boolean,
    val modifiedBytes: ByteArray,
    val appliedChanges: List<String>,
    val missingChanges: List<String> = emptyList()
)

/**
 * Editor seguro de binário AXML em memória.
 * Modifica valores literais (ex.: flags booleanas de debuggable/allowBackup/cleartext)
 * diretamente no AXML binário sem necessidade de descompilar ou recompilar com aapt2.
 */
object AxmlEditor {

    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val TYPE_INT_BOOLEAN = 0x12

    private val KNOWN_BOOLEAN_RES_IDS = mapOf(
        0x0101000F to "debuggable",
        0x01010280 to "allowBackup",
        0x010104EC to "usesCleartextTraffic"
    )

    /**
     * Aplica alterações nas flags booleanas no AXML binário existente.
     * Retorna uma cópia modificada dos bytes do AXML.
     */
    fun applyQuickEdits(originalData: ByteArray, config: QuickEditsConfig): ManifestEditResult {
        if (originalData.size < 8) {
            return ManifestEditResult(false, originalData, emptyList())
        }

        val modified = originalData.copyOf()
        val buffer = ByteBuffer.wrap(modified).order(ByteOrder.LITTLE_ENDIAN)
        val magic = buffer.short.toInt() and 0xFFFF
        if (magic != 0x0003) {
            return ManifestEditResult(false, originalData, emptyList())
        }

        val headerSize = buffer.short.toInt() and 0xFFFF
        var pos = headerSize

        var stringPool: List<String> = emptyList()
        var resourceMap: List<Int> = emptyList()
        val requestedNames = buildSet {
            if (config.setDebuggable != null) add("debuggable")
            if (config.setAllowBackup != null) add("allowBackup")
            if (config.setCleartextTraffic != null) add("usesCleartextTraffic")
        }
        val presentNames = mutableSetOf<String>()
        val changedNames = mutableSetOf<String>()
        val appliedChanges = mutableListOf<String>()

        while (pos + 8 <= modified.size) {
            buffer.position(pos)
            val chunkType = buffer.short.toInt() and 0xFFFF
            val chunkHeaderSize = buffer.short.toInt() and 0xFFFF
            val chunkSize = buffer.int

            if (chunkSize < 8) break

            when (chunkType) {
                0x0001 -> { // RES_STRING_POOL_TYPE
                    stringPool = com.readroid.app.core.axml.AxmlParser.parseStringPool(modified, pos)
                }
                0x0180 -> { // RES_XML_RESOURCE_MAP_TYPE
                    val count = (chunkSize - chunkHeaderSize) / 4
                    val map = ArrayList<Int>(count)
                    buffer.position(pos + chunkHeaderSize)
                    for (i in 0 until count) {
                        map.add(buffer.int)
                    }
                    resourceMap = map
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    buffer.position(pos + 20)
                    val nameIdx = buffer.int
                    val attrStart = buffer.short.toInt() and 0xFFFF
                    val attrSize = buffer.short.toInt() and 0xFFFF
                    val attrCount = buffer.short.toInt() and 0xFFFF

                    val tagName = stringPool.getOrElse(nameIdx) { "" }

                    if (tagName == "application") {
                        for (i in 0 until attrCount) {
                            val attrPos = pos + 16 + attrStart + (i * attrSize)
                            if (attrPos + 20 <= modified.size) {
                                buffer.position(attrPos)
                                val nsIdx = buffer.int
                                val nIdx = buffer.int
                                val rawValueIdx = buffer.int
                                val size = buffer.short.toInt() and 0xFFFF
                                val res0 = buffer.get().toInt() and 0xFF
                                val dataType = buffer.get().toInt() and 0xFF
                                val dataValPos = attrPos + 16
                                val currentVal = buffer.int

                                var attrName = stringPool.getOrElse(nIdx) { "" }
                                if (attrName.isEmpty() && nIdx < resourceMap.size) {
                                    val resId = resourceMap[nIdx]
                                    attrName = KNOWN_BOOLEAN_RES_IDS[resId] ?: ""
                                }

                                if (dataType == TYPE_INT_BOOLEAN) {
                                    when (attrName) {
                                        "debuggable" -> {
                                            config.setDebuggable?.let { newVal ->
                                                val intVal = if (newVal) 1 else 0
                                                if (currentVal != intVal) buffer.putInt(dataValPos, intVal)
                                                presentNames.add("debuggable")
                                                if (currentVal != intVal) changedNames.add("debuggable")
                                                if (currentVal != intVal) appliedChanges.add("android:debuggable = $newVal")
                                            }
                                        }
                                        "allowBackup" -> {
                                            config.setAllowBackup?.let { newVal ->
                                                val intVal = if (newVal) 1 else 0
                                                if (currentVal != intVal) buffer.putInt(dataValPos, intVal)
                                                presentNames.add("allowBackup")
                                                if (currentVal != intVal) changedNames.add("allowBackup")
                                                if (currentVal != intVal) appliedChanges.add("android:allowBackup = $newVal")
                                            }
                                        }
                                        "usesCleartextTraffic" -> {
                                            config.setCleartextTraffic?.let { newVal ->
                                                val intVal = if (newVal) 1 else 0
                                                if (currentVal != intVal) buffer.putInt(dataValPos, intVal)
                                                presentNames.add("usesCleartextTraffic")
                                                if (currentVal != intVal) changedNames.add("usesCleartextTraffic")
                                                if (currentVal != intVal) appliedChanges.add("android:usesCleartextTraffic = $newVal")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            pos += chunkSize
        }

        return ManifestEditResult(
            isModified = changedNames.isNotEmpty(),
            modifiedBytes = modified,
            appliedChanges = appliedChanges,
            missingChanges = (requestedNames - presentNames).map { "android:$it" }
        )
    }

    private fun readStringPoolSimple(data: ByteArray, pos: Int): List<String> {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        buffer.position(pos + 8)
        val stringCount = buffer.int
        buffer.position(pos + 20)
        val stringsStart = buffer.int
        val base = pos + stringsStart

        val offsets = IntArray(stringCount)
        buffer.position(pos + (buffer.short.toInt() and 0xFFFF))
        // apenas extrai offsets seguros
        val list = mutableListOf<String>()
        // Fallback simplificado de nomes
        return list
    }
}

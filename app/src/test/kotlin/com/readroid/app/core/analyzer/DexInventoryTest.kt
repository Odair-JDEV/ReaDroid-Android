package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DexInventoryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** DEX sintético mínimo válido com uma classe e métodos. */
    private fun buildSyntheticDex(): ByteArray {
        val out = ByteArrayOutputStream()
        val header = java.nio.ByteBuffer.allocate(112).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        header.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
        header.putInt(0) // checksum placeholder
        header.put(ByteArray(20)) // signature
        header.putInt(0) // file_size placeholder patched later
        header.putInt(112) // header_size
        header.putInt(0x12345678) // endian tag
        header.putInt(0) // link_size
        header.putInt(0) // link_off
        header.putInt(0) // map_off (incomplete but not required for this reader)
        header.putInt(2) // string_ids_size
        header.putInt(112) // string_ids_off
        header.putInt(1) // type_ids_size
        header.putInt(120) // type_ids_off
        header.putInt(0) // proto_ids_size
        header.putInt(0) // proto_ids_off
        header.putInt(0) // field_ids_size
        header.putInt(0) // field_ids_off
        header.putInt(0) // method_ids_size
        header.putInt(0) // method_ids_off
        header.putInt(1) // class_defs_size
        header.putInt(120 + 4) // class_defs_off
        header.putInt(0) // data_size
        header.putInt(0) // data_off
        out.write(header.array())

        // string_ids: [0]=class descriptor string offset, [1]=class name string offset
        val stringIds = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        stringIds.putInt(156).putInt(172)
        out.write(stringIds.array())
        // type_ids: [0] -> string 0
        val typeIds = java.nio.ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        typeIds.putInt(0)
        out.write(typeIds.array())
        // class_defs: 32 bytes, class 0, flags 1, super NO_INDEX, source NO_INDEX, no data
        val classDef = java.nio.ByteBuffer.allocate(32).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        classDef.putInt(0).putInt(0x1).putInt(0xFFFFFFFF.toInt()).putInt(0xFFFFFFFF.toInt())
        classDef.putInt(0).putInt(0).putInt(0).putInt(0)
        out.write(classDef.array())
        // string data at 156: uleb len=12 then "Lcom/demo/A;" nul
        val data = ByteArrayOutputStream()
        data.write(12)
        data.write("Lcom/demo/A;".toByteArray(Charsets.US_ASCII))
        data.write(0)
        // padding to second string id offset
        while (156 + data.size() < 172) data.write(0)
        // second string at 172: uleb len=1 "X" nul
        data.write(1)
        data.write("X".toByteArray(Charsets.US_ASCII))
        data.write(0)
        out.write(data.toByteArray())

        val bytes = out.toByteArray()
        // patch file_size
        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(32, bytes.size)
        return bytes
    }

    private fun apkWith(vararg entries: Pair<String, ByteArray>): java.io.File {
        val f = tmp.newFile("demo-${System.nanoTime()}.apk")
        ZipOutputStream(f.outputStream()).use { z ->
            entries.forEach { (name, bytes) ->
                z.putNextEntry(ZipEntry(name)); z.write(bytes)
            }
        }
        return f
    }

    @Test
    fun parsesSyntheticDexWithClassAndCounts() {
        val apk = apkWith("classes.dex" to buildSyntheticDex())
        val inv = DexInventoryReader.read(apk, "classes.dex")
        assertEquals(1, inv.classCount)
        assertEquals("Lcom/demo/A;", inv.classes[0].descriptor)
        assertTrue(inv.classes[0].methods.isEmpty())
        assertEquals("035", inv.version)
    }

    @Test
    fun rejectsMissingOrCorruptDexEntries() {
        val apk = apkWith("classes.dex" to buildSyntheticDex())
        assertThrows(DexInspectionException::class.java) { DexInventoryReader.read(apk, "classes2.dex") }
        val bad = apkWith("classes.dex" to "not-a-dex".toByteArray())
        assertThrows(DexInspectionException::class.java) { DexInventoryReader.read(bad, "classes.dex") }
        val truncated = apkWith("classes.dex" to buildSyntheticDex().copyOf(60))
        assertThrows(DexInspectionException::class.java) { DexInventoryReader.read(truncated, "classes.dex") }
    }

    @Test
    fun rejectsUnexpectedDexEntryNames() {
        val apk = apkWith("evil.dex" to buildSyntheticDex())
        assertThrows(DexInspectionException::class.java) { DexInventoryReader.read(apk, "evil.dex") }
    }

    @Test
    fun filterAndPaginationCombineDeterministically() {
        val apk = apkWith("classes.dex" to buildSyntheticDex())
        val inv = DexInventoryReader.read(apk, "classes.dex")
        val filtered = DexInventoryReader.filter(inv, DexFilter("demo"))
        assertEquals(inv.classes, filtered)
        assertEquals(emptyList<DexClassInfo>(), DexInventoryReader.filter(inv, DexFilter("nomatch")))
        val page = DexInventoryReader.page(inv.classes, 0)
        assertEquals(1, page.total)
        assertEquals(null, page.nextOffset)
    }
}

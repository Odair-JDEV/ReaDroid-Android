package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.Rule
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkEntryInventoryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun readsEntriesWithKindSizesMethodAndCrc() {
        val apk = tmp.newFile("a.apk")
        ZipOutputStream(apk.outputStream()).use { out ->
            out.putNextEntry(ZipEntry("AndroidManifest.xml")); out.write("m".toByteArray())
            out.putNextEntry(ZipEntry("resources.arsc")); out.write("r".toByteArray())
            out.putNextEntry(ZipEntry("classes.dex")); out.write("d".toByteArray())
            out.putNextEntry(ZipEntry("lib/arm64-v8a/libx.so")); out.write("n".toByteArray())
            out.putNextEntry(ZipEntry("res/values/strings.xml")); out.write("s".toByteArray())
            out.putNextEntry(ZipEntry("assets/data.json")); out.write("j".toByteArray())
            out.putNextEntry(ZipEntry("META-INF/x.txt")); out.write("o".toByteArray())
        }
        val inv = ApkEntryInventoryReader.read(apk)
        assertEquals(7, inv.declaredTotal)
        assertEquals(7, inv.entries.size)
        assertTrue(!inv.truncated)
        assertNull(inv.warning)
        val kinds = inv.entries.associate { it.name to it.kind }
        assertEquals(EntryKind.MANIFEST, kinds["AndroidManifest.xml"])
        assertEquals(EntryKind.ARSC, kinds["resources.arsc"])
        assertEquals(EntryKind.DEX, kinds["classes.dex"])
        assertEquals(EntryKind.NATIVE_LIB, kinds["lib/arm64-v8a/libx.so"])
        assertEquals(EntryKind.RESOURCE, kinds["res/values/strings.xml"])
        assertEquals(EntryKind.ASSET, kinds["assets/data.json"])
        assertEquals(EntryKind.OTHER, kinds["META-INF/x.txt"])
        val crc = inv.entries.first { it.name == "classes.dex" }.crc32
        val expected = java.util.zip.CRC32().apply { update("d".toByteArray()) }.value
        assertEquals(expected, crc)
    }

    @Test
    fun filterByQueryAndKindIsCaseInsensitive() {
        val inv = ApkEntryInventory(
            entries = listOf(
                ApkEntryInfo("res/values/strings.xml", EntryKind.RESOURCE, 10, 20, 8, 0),
                ApkEntryInfo("assets/Data.JSON", EntryKind.ASSET, 5, 6, 8, 0),
                ApkEntryInfo("classes.dex", EntryKind.DEX, 3, 4, 8, 0)
            ),
            declaredTotal = 3, truncated = false, warning = null
        )
        val byQuery = ApkEntryInventoryReader.apply(inv, ApkEntryFilter(query = "STRING"))
        assertEquals(listOf("res/values/strings.xml"), byQuery.map { it.name })
        val byKind = ApkEntryInventoryReader.apply(inv, ApkEntryFilter(kind = EntryKind.ASSET))
        assertEquals(listOf("assets/Data.JSON"), byKind.map { it.name })
        val combined = ApkEntryInventoryReader.apply(inv, ApkEntryFilter(query = "json", kind = EntryKind.ASSET))
        assertEquals(listOf("assets/Data.JSON"), combined.map { it.name })
    }

    @Test
    fun truncatesAtMaxEntriesWithExplicitWarning() {
        val apk = tmp.newFile("b.apk")
        ZipOutputStream(apk.outputStream()).use { out ->
            repeat(5) { i -> out.putNextEntry(ZipEntry("f$i.txt")); out.write("x".toByteArray()) }
        }
        val inv = ApkEntryInventoryReader.read(apk, maxEntries = 3)
        assertTrue(inv.truncated)
        assertEquals(3, inv.entries.size)
        assertTrue(inv.warning!!.contains("3"))
    }

    @Test
    fun rejectsOversizedNamesDeterministically() {
        val apk = tmp.newFile("c.apk")
        val longName = "n".repeat(5000) + ".txt"
        ZipOutputStream(apk.outputStream()).use { out ->
            out.putNextEntry(ZipEntry(longName)); out.write("x".toByteArray())
        }
        val inv = ApkEntryInventoryReader.read(apk)
        assertTrue(inv.truncated)
        assertNull(inv.entries.firstOrNull())
    }

    @Test
    fun invalidZipFailsClosedWithStructuredError() {
        val notZip = tmp.newFile("d.apk").apply { writeBytes(byteArrayOf(0, 1, 2, 3)) }
        val ex = assertThrows(ApkEntryInventoryException::class.java) {
            ApkEntryInventoryReader.read(notZip)
        }
        assertTrue(ex.message!!.contains("inventário"))
    }

    @Test
    fun directoriesAndDuplicateNamesAreListedAsIsWithoutPathChecks() {
        val apk = tmp.newFile("e.apk")
        ZipOutputStream(apk.outputStream()).use { out ->
            out.putNextEntry(ZipEntry("dir/"))
            out.closeEntry()
            out.putNextEntry(ZipEntry("dir/../evil.txt")); out.write("x".toByteArray())
        }
        val inv = ApkEntryInventoryReader.read(apk)
        assertTrue(inv.entries.map { it.name }.contains("dir/../evil.txt"))
    }

    @Test
    fun paginationIsDeterministicAndConcatenationMatchesFilteredList() {
        val inv = ApkEntryInventory(
            entries = (0 until 137).map { ApkEntryInfo("e$it", EntryKind.OTHER, it.toLong(), it.toLong(), 8, it.toLong()) },
            declaredTotal = 137, truncated = false, warning = null
        )
        val filtered = ApkEntryInventoryReader.apply(inv, ApkEntryFilter(query = "e1"))
        var offset = 0
        val seen = mutableListOf<ApkEntryInfo>()
        while (true) {
            val page = ApkEntryPagination.page(filtered, offset)
            seen += page.items
            offset = page.nextOffset ?: break
        }
        assertEquals(filtered, seen)
        assertTrue(seen.size in 1..137)
    }

    @Test
    fun paginationRejectsBadOffsetsAndLimits() {
        assertThrows(IllegalArgumentException::class.java) { ApkEntryPagination.page(emptyList(), offset = -1) }
        assertThrows(IllegalArgumentException::class.java) { ApkEntryPagination.page(emptyList(), offset = 0, limit = 0) }
    }

    @Test
    fun readRejectsMissingFile() {
        assertThrows(ApkEntryInventoryException::class.java) {
            ApkEntryInventoryReader.read(File(tmp.root, "missing.apk"))
        }
    }
}

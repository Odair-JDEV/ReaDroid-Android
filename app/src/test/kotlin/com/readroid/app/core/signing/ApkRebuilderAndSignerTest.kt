package com.readroid.app.core.signing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkRebuilderAndSignerTest {
    @get:Rule
    val temp = TemporaryFolder()

    @Test
    fun replaceManifestPreservesStoredEntriesCrcAndAlignment() {
        val source = File(temp.root, "source.apk")
        val output = File(temp.root, "output.apk")
        val manifest = byteArrayOf(3, 0, 8, 0, 8, 0, 0, 0)
        val resources = ByteArray(19) { it.toByte() }
        val library = byteArrayOf(0x7f, 0x45, 0x4c, 0x46)
        createApk(source, manifest, resources, library)

        ApkRebuilderAndSigner.replaceManifest(source, output, manifest + byteArrayOf(1))

        ZipFile(output).use { zip ->
            for ((name, expected) in listOf("resources.arsc" to resources, "lib/arm64-v8a/libnative.so" to library)) {
                val entry = zip.getEntry(name)!!
                assertEquals("$name must remain STORED", ZipEntry.STORED, entry.method)
                assertEquals(expected.size.toLong(), entry.size)
                assertEquals(CRC32().apply { update(expected) }.value, entry.crc)
                assertTrue(zip.getInputStream(entry).use { it.readBytes().contentEquals(expected) })
                val alignment = if (name.endsWith(".so")) 16384 else 4
                assertEquals("$name data offset alignment", 0L, dataOffset(output, name) % alignment)
            }
            assertEquals(manifest.size + 1, zip.getInputStream(zip.getEntry("AndroidManifest.xml")).use { it.readBytes().size })
        }
    }

    private fun createApk(file: File, manifest: ByteArray, resources: ByteArray, library: ByteArray) {
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(manifest)
            zip.closeEntry()
            addStored(zip, "resources.arsc", resources)
            addStored(zip, "lib/arm64-v8a/libnative.so", library)
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }
    }

    private fun addStored(zip: ZipOutputStream, name: String, bytes: ByteArray) {
        val entry = ZipEntry(name).apply {
            method = ZipEntry.STORED
            size = bytes.size.toLong()
            compressedSize = bytes.size.toLong()
            crc = CRC32().apply { update(bytes) }.value
        }
        zip.putNextEntry(entry)
        zip.write(bytes)
        zip.closeEntry()
    }

    private fun dataOffset(file: File, name: String): Long {
        val bytes = file.readBytes()
        for (offset in bytes.size - 22 downTo maxOf(0, bytes.size - 65557)) {
            if (leInt(bytes, offset) != 0x06054b50) continue
            var cursor = leInt(bytes, offset + 16)
            while (cursor + 46 <= bytes.size && leInt(bytes, cursor) == 0x02014b50) {
                val nameLen = leShort(bytes, cursor + 28)
                val extraLen = leShort(bytes, cursor + 30)
                val commentLen = leShort(bytes, cursor + 32)
                val currentName = String(bytes, cursor + 46, nameLen, Charsets.UTF_8)
                if (currentName == name) {
                    val localOffset = leInt(bytes, cursor + 42)
                    return localOffset + 30L + leShort(bytes, localOffset + 26) + leShort(bytes, localOffset + 28)
                }
                cursor += 46 + nameLen + extraLen + commentLen
            }
        }
        error("ZIP entry $name missing")
    }

    private fun leShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun leInt(bytes: ByteArray, offset: Int): Int =
        leShort(bytes, offset) or (leShort(bytes, offset + 2) shl 16)
}

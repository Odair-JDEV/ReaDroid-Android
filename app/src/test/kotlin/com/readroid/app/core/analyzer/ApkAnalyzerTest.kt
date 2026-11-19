package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkAnalyzerTest {

    @Test
    fun testSha256Calculation() {
        val input = "ReaDroid Test String".toByteArray(Charsets.UTF_8)
        val hash = ApkAnalyzer.calculateSha256(ByteArrayInputStream(input))
        // SHA-256 esperado para "ReaDroid Test String"
        assertEquals("46e7b4ac845be7cc88b1874feb25dcc8998882dade46689f4aa9c0cecedfc951", hash)
    }

    @Test
    fun testInspectZipAndStringScan() {
        val tempApk = File.createTempFile("test_sample", ".apk")
        tempApk.deleteOnExit()

        // Monta um APK/ZIP mínimo em memória
        ZipOutputStream(FileOutputStream(tempApk)).use { zipOut ->
            // classes.dex simulado com URLs e domínios
            zipOut.putNextEntry(ZipEntry("classes.dex"))
            val dexContent = "Hello World! Visit https://api.readroid.dev/v1 and http://192.168.1.100 for updates."
            zipOut.write(dexContent.toByteArray(Charsets.ISO_8859_1))
            zipOut.closeEntry()

            // lib nativa simulada
            zipOut.putNextEntry(ZipEntry("lib/arm64-v8a/libnative.so"))
            zipOut.write(byteArrayOf(0x7F, 0x45, 0x4C, 0x46)) // ELF header
            zipOut.closeEntry()
        }

        val inspection = ApkAnalyzer.inspectApk(tempApk)
        assertEquals(tempApk.name, inspection.fileName)
        assertEquals(2, inspection.zipEntryCount)
        assertEquals(listOf("classes.dex"), inspection.dexFiles)
        assertEquals(listOf("lib/arm64-v8a/libnative.so"), inspection.nativeLibraries)
        assertFalse(inspection.hasManifest)

        val stringScan = ApkAnalyzer.scanStrings(tempApk)
        assertTrue(stringScan.urls.contains("https://api.readroid.dev/v1"))
        assertTrue(stringScan.domains.contains("api.readroid.dev"))
        assertTrue(stringScan.ipv4Candidates.contains("192.168.1.100"))
        assertFalse(stringScan.isTruncated)
    }

    @Test
    fun testInspectRealApk() {
        val apkFile = File("build/outputs/apk/debug/app-debug.apk")
        if (apkFile.exists()) {
            println("Testing with real APK: ${apkFile.absolutePath} (${apkFile.length()} bytes)")
            val inspection = ApkAnalyzer.inspectApk(apkFile)
            println("Has manifest: ${inspection.hasManifest}")
            println("Manifest package: ${inspection.manifest?.packageName}")
            println("Manifest warnings: ${inspection.warnings}")
            val scan = ApkAnalyzer.scanStrings(apkFile)
            println("URLs found: ${scan.urls.size}")
        } else {
            println("app-debug.apk not found at ${apkFile.absolutePath}")
        }
    }
}

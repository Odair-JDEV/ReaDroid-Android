package com.readroid.app.core.report

import com.readroid.app.core.analyzer.ApkInspectionResult
import com.readroid.app.core.analyzer.StringScanResult
import com.readroid.app.core.axml.ComponentType
import com.readroid.app.core.axml.ManifestApplication
import com.readroid.app.core.axml.ManifestComponent
import com.readroid.app.core.axml.ManifestPermission
import com.readroid.app.core.axml.ParsedManifest
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportGeneratorTest {

    @Test
    fun testBuildMarkdownReport() {
        val manifest = ParsedManifest(
            packageName = "com.readroid.securitytest",
            versionCode = "10",
            versionName = "2.0.0",
            minSdkVersion = "26",
            targetSdkVersion = "35",
            permissions = listOf(
                ManifestPermission("android.permission.INTERNET"),
                ManifestPermission("android.permission.ACCESS_FINE_LOCATION"),
                ManifestPermission("android.permission.CAMERA")
            ),
            application = ManifestApplication(
                label = "SecurityTestApp",
                isDebuggable = true,
                allowBackup = false,
                usesCleartextTraffic = true
            ),
            components = listOf(
                ManifestComponent(ComponentType.ACTIVITY, ".MainActivity", exported = true),
                ManifestComponent(ComponentType.SERVICE, ".SecretService", exported = false)
            )
        )

        val inspection = ApkInspectionResult(
            fileName = "sample_test.apk",
            fileSizeBytes = 2048000,
            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            zipEntryCount = 45,
            dexFiles = listOf("classes.dex"),
            nativeLibraries = listOf("lib/arm64-v8a/libtest.so"),
            resourceFileCount = 20,
            assetFileCount = 5,
            hasManifest = true,
            manifest = manifest
        )

        val stringScan = StringScanResult(
            urls = setOf("https://secure.readroid.app/api"),
            domains = setOf("secure.readroid.app"),
            ipv4Candidates = setOf("10.0.0.1"),
            isTruncated = false,
            scannedBytes = 10240
        )

        val markdown = ReportGenerator.buildMarkdownReport(inspection, stringScan)

        // Verificações de integridade do relatório
        assertTrue(markdown.contains("sample_test.apk"))
        assertTrue(markdown.contains("com.readroid.securitytest"))
        assertTrue(markdown.contains("debuggable"))
        assertTrue(markdown.contains("localização precisa (GPS)"))
        assertTrue(markdown.contains("usar a câmera"))
        assertTrue(markdown.contains(".MainActivity"))
        assertTrue(markdown.contains("secure.readroid.app"))
    }
}

package com.readroid.app.core.axml

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ManifestObservationsTest {

    private fun manifest(): ParsedManifest = ParsedManifest(
        packageName = "com.example.app",
        versionCode = "7",
        versionName = "1.2.3",
        minSdkVersion = "26",
        targetSdkVersion = "36",
        permissions = listOf(
            ManifestPermission("android.permission.CAMERA"),
            ManifestPermission("android.permission.READ_SMS", maxSdkVersion = "33")
        ),
        application = ManifestApplication(label = "Demo", isDebuggable = true, allowBackup = null, usesCleartextTraffic = false),
        components = listOf(
            ManifestComponent(ComponentType.ACTIVITY, ".MainActivity", exported = true),
            ManifestComponent(ComponentType.SERVICE, ".Worker", exported = false, permission = "android.permission.BIND_JOB_SERVICE")
        )
    )

    @Test
    fun buildsObservationsForEveryManifestArea() {
        val list = ManifestObservations.build(manifest())
        val categories = list.map { it.category }.toSet()
        assertTrue(ManifestObservationCategory.IDENTITY in categories)
        assertTrue(ManifestObservationCategory.SDK in categories)
        assertTrue(ManifestObservationCategory.SECURITY in categories)
        assertTrue(ManifestObservationCategory.PERMISSION in categories)
        assertTrue(ManifestObservationCategory.COMPONENT in categories)
        assertEquals("com.example.app", list.first { it.label == "Pacote" }.value)
        assertEquals("não declarado", list.first { it.label == "allowBackup" }.value)
    }

    @Test
    fun emptyManifestYieldsNoObservations() {
        assertTrue(ManifestObservations.build(null).isEmpty())
        assertTrue(ManifestObservations.build(ParsedManifest(packageName = null, versionCode = null, versionName = null)).isNotEmpty())
    }

    @Test
    fun filterMatchesLabelOrValueCaseInsensitively() {
        val list = ManifestObservations.build(manifest())
        val byValue = ManifestObservations.filter(list, "CAMERA")
        assertTrue(byValue.all { it.category == ManifestObservationCategory.PERMISSION })
        val byLabel = ManifestObservations.filter(list, "exported")
        assertTrue(byLabel.isNotEmpty())
        assertEquals(list, ManifestObservations.filter(list, "   "))
    }

    @Test
    fun paginationIsDeterministicAndConcatenationMatchesList() {
        val observations = (0 until 173).map {
            ManifestObservation(ManifestObservationCategory.PERMISSION, "label-$it", "value-$it")
        }
        var offset = 0
        val seen = mutableListOf<ManifestObservation>()
        while (true) {
            val page = ManifestObservations.page(observations, offset)
            seen += page.items
            offset = page.nextOffset ?: break
        }
        assertEquals(observations, seen)
    }

    @Test
    fun pageBoundsAreEnforced() {
        val observations = ManifestObservations.build(manifest())
        assertThrows(IllegalArgumentException::class.java) { ManifestObservations.page(observations, -1) }
        assertThrows(IllegalArgumentException::class.java) { ManifestObservations.page(observations, 0, 0) }
        val page = ManifestObservations.page(observations, offset = 500)
        assertTrue(page.items.isEmpty())
        assertNull(page.nextOffset)
    }

    @Test
    fun securityFlagsHighlightOnlyWhenTrue() {
        val list = ManifestObservations.build(manifest())
        assertTrue(list.first { it.label == "debuggable" }.highlight)
        assertTrue(!list.first { it.label == "usesCleartextTraffic" }.highlight)
        val exportedRow = list.first { it.label == "activity" }
        assertTrue(exportedRow.highlight)
    }
}

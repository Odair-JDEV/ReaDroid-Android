package com.readroid.app.core.project

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File

class ApkProjectStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val fixedClock: () -> Long = { 1_700_000_000_000L }

    private fun store() = ApkProjectStore(temp.root, fixedClock)

    private fun apkBytes(seed: Int = 1): ByteArray = ByteArray(128) { ((it * seed) and 0xFF).toByte() }

    @Test
    fun importCreatesImmutableOriginalAndMetadata() {
        val project = store().importProject(ByteArrayInputStream(apkBytes()), "app.apk")
        assertEquals(project.originalSha256, project.projectId)
        assertTrue(project.projectId.matches(Regex("[0-9a-f]{64}")))
        assertEquals(apkBytes().size.toLong(), project.originalSizeBytes)
        assertTrue(store().originalFile(project).isFile)
        assertTrue(store().verifyOriginalIntegrity(project))
    }

    @Test
    fun reimportReusesSameOriginalWithoutOverwriting() {
        val store = store()
        val first = store.importProject(ByteArrayInputStream(apkBytes()), "one.apk")
        val originalBefore = store.originalFile(first).readBytes()
        val second = store.importProject(ByteArrayInputStream(apkBytes()), "two.apk")
        assertEquals(first.projectId, second.projectId)
        assertTrue(store.originalFile(second).readBytes().contentEquals(originalBefore))
        assertEquals(first.importedAt, second.importedAt)
    }

    @Test
    fun differentBytesCreateDifferentProjects() {
        val first = store().importProject(ByteArrayInputStream(apkBytes(1)), "a.apk")
        val second = store().importProject(ByteArrayInputStream(apkBytes(2)), "b.apk")
        assertTrue(first.projectId != second.projectId)
    }

    @Test
    fun successfulImportLeavesNoStagingFiles() {
        val store = store()
        store.importProject(ByteArrayInputStream(apkBytes()), "ok.apk")
        val leftovers = File(temp.root, "projects").listFiles { f -> f.name.startsWith(".import-") } ?: emptyArray()
        assertTrue("staging deve ser limpo: ${leftovers.joinToString { it.name }}", leftovers.isEmpty())
    }

    @Test
    fun importRejectsSourceAboveQuota() {
        val huge = object : java.io.InputStream() {
            var remaining = ApkProjectStore.MAX_IMPORT_BYTES + 1
            override fun read(): Int {
                if (remaining <= 0) return -1
                remaining--
                return 0x41
            }
        }
        try {
            store().importProject(huge, "huge.apk")
            assertFalse("importação acima da cota deve falhar", true)
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("limite"))
        }
    }

    @Test
    fun tamperedOriginalFailsIntegrityCheck() {
        val store = store()
        val project = store.importProject(ByteArrayInputStream(apkBytes()), "app.apk")
        val original = store.originalFile(project)
        val bytes = original.readBytes()
        bytes[0] = (bytes[0].toInt() xor 0x55).toByte()
        original.writeBytes(bytes)
        assertFalse(store.verifyOriginalIntegrity(project))
    }

    @Test
    fun projectIdValidationBlocksPathTraversal() {
        val store = store()
        for (malicious in listOf("../x", "a/b", "..", "AAAA", "")) {
            try {
                store.projectDirectory(malicious)
                assertFalse("id $malicious deve ser recusado", true)
            } catch (_: IllegalArgumentException) { }
        }
    }

    @Test
    fun workspaceIsSeparatedFromOriginal() {
        val store = store()
        val project = store.importProject(ByteArrayInputStream(apkBytes()), "app.apk")
        val workspace = store.workspaceDirectory(project)
        assertFalse(workspace.path == store.originalFile(project).parentFile!!.path)
        assertTrue(workspace.path.startsWith(store.projectDirectory(project.projectId).path))
        assertEquals(File::class.java, workspace.javaClass)
    }
}

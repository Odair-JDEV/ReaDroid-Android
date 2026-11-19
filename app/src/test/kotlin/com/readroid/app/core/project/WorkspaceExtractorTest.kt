package com.readroid.app.core.project

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class WorkspaceExtractorTest {
    @get:Rule val temp = TemporaryFolder()

    private fun projectWithApk(vararg entries: Pair<String, ByteArray>): Pair<ApkProjectStore, ApkProject> {
        val store = ApkProjectStore(temp.root, { 1234L })
        val apk = File(temp.root, "fixture.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            for ((name, bytes) in entries) {
                val entry = ZipEntry(name).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = bytes.size.toLong()
                    crc = CRC32().apply { update(bytes) }.value
                }
                zip.putNextEntry(entry); zip.write(bytes); zip.closeEntry()
            }
        }
        val project = store.importProject(apk.inputStream(), "fixture.apk")
        return store to project
    }

    @Test
    fun extractsSelectedEntryAndRecordsOperation() {
        val (store, project) = projectWithApk("assets/note.txt" to "hello".toByteArray())
        val log = OperationLog(File(store.projectDirectory(project.projectId), "operations"), { 77L })
        val extracted = WorkspaceExtractor(store, log).extract(project, listOf("assets/note.txt"))
        assertEquals("hello", extracted.single().readText())
        assertEquals("WORKSPACE_EXTRACT", log.readAll().single().type)
        assertEquals("COMMITTED", log.readAll().single().status)
    }

    @Test
    fun rejectsTraversalAbsoluteDriveUncAndMalformedPathsBeforeWriting() {
        val (store, project) = projectWithApk("safe.txt" to byteArrayOf(1))
        val extractor = WorkspaceExtractor(store, OperationLog(File(store.projectDirectory(project.projectId), "operations")))
        val hostile = listOf("../escape", "a/../../escape", "/absolute", "C:\\temp", "\\\\server\\share", "a\\b", "a//b", "./x", "a/./b", "a/../b", "", "bad\u0000name")
        for (path in hostile) {
            try {
                extractor.extract(project, listOf(path))
                assertFalse("path '$path' must be rejected", true)
            } catch (_: IllegalArgumentException) { }
        }
        assertFalse(File(temp.root, "escape").exists())
        assertTrue(store.workspaceDirectory(project).walkTopDown().none { it.isFile })
    }

    @Test
    fun rejectsDuplicateNormalizedAndCaseInsensitiveCollision() {
        val (store, project) = projectWithApk("a.txt" to byteArrayOf(1), "A.txt" to byteArrayOf(2))
        val extractor = WorkspaceExtractor(store, OperationLog(File(store.projectDirectory(project.projectId), "operations")))
        for (paths in listOf(listOf("a.txt", "a.txt"), listOf("a.txt", "A.txt"))) {
            try { extractor.extract(project, paths); assertFalse("duplicates must fail", true) }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test
    fun rejectsPathDepthAndLengthLimits() {
        val (store, project) = projectWithApk("safe.txt" to byteArrayOf(1))
        val extractor = WorkspaceExtractor(store, OperationLog(File(store.projectDirectory(project.projectId), "operations")))
        val tooDeep = (0..16).joinToString("/") { "x" }
        val tooLongSegment = "x".repeat(129)
        for (path in listOf(tooDeep, tooLongSegment, "x".repeat(513))) {
            try { extractor.extract(project, listOf(path)); assertFalse("oversized path must fail", true) }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test
    fun extractionMeasuresActualBytesAndRemovesPartialFileOnLimit() {
        val payload = ByteArray(32) { 7 }
        val (store, project) = projectWithApk("large.bin" to payload)
        val extractor = WorkspaceExtractor(store, OperationLog(File(store.projectDirectory(project.projectId), "operations")), maxEntryBytes = 16, maxTotalBytes = 64)
        try { extractor.extract(project, listOf("large.bin")); assertFalse("quota must fail", true) }
        catch (expected: IllegalArgumentException) { assertTrue(expected.message!!.contains("limite")) }
        assertFalse(File(store.workspaceDirectory(project), "large.bin").exists())
    }

    @Test
    fun rejectsMissingOrAlreadyExtractedEntries() {
        val (store, project) = projectWithApk("x.txt" to byteArrayOf(1))
        val extractor = WorkspaceExtractor(store, OperationLog(File(store.projectDirectory(project.projectId), "operations")))
        try { extractor.extract(project, listOf("missing.txt")); assertFalse("missing entry must fail", true) }
        catch (_: IllegalArgumentException) { }
        extractor.extract(project, listOf("x.txt"))
        try { extractor.extract(project, listOf("x.txt")); assertFalse("existing target must fail", true) }
        catch (_: IllegalArgumentException) { }
    }
}

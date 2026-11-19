package com.readroid.app.core.project

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class WorkspaceBrowserTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun newProject(): Pair<ApkProjectStore, ApkProject> {
        val filesDir = tmp.newFolder("files-${System.nanoTime()}")
        val store = ApkProjectStore(filesDir, clock = { 1_000L })
        val apk = tmp.newFile("src-${System.nanoTime()}.apk")
        ZipOutputStream(apk.outputStream()).use { out ->
            out.putNextEntry(ZipEntry("assets/config.json")); out.write("""{"flag":true}""".toByteArray())
            out.putNextEntry(ZipEntry("res/values/strings.xml")); out.write("<resources/>".toByteArray())
            out.putNextEntry(ZipEntry("lib/arm64/libn.so")); out.write(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 0, 1, 2, 3))
        }
        val project = apk.inputStream().use { store.importProject(it, "demo.apk") }
        return store to project
    }

    private fun browser(store: ApkProjectStore): WorkspaceBrowser {
        val projectId = File(store.projectDirectory("0".repeat(64)).parent, "x").parentFile
            .let { projRoot -> projRoot.list()!!.filter { it.matches(Regex("[0-9a-f]{64}")) }.first() }
        val project = store.readProject(projectId)
        val facade = object : WorkspaceExtractorFacade {
            override fun extract(project: ApkProject, requestedPaths: Collection<String>): List<File> =
                WorkspaceExtractor(store, store.operationLog(project)).extract(project, requestedPaths)
        }
        return WorkspaceBrowser(store, facade)
    }

    @Test
    fun extractsSelectedEntriesAndListsWorkspace() {
        val (store, project) = newProject()
        val browser = browser(store)
        val extracted = browser.extract(project, listOf("assets/config.json", "res/values/strings.xml"))
        assertEquals(2, extracted.size)
        val entries = browser.listEntries(project)
        assertEquals(listOf("assets/config.json", "res/values/strings.xml"), entries.map { it.relativePath })
        assertTrue(entries.all { it.sizeBytes > 0 })
    }

    @Test
    fun extractFailsClosedOnTraversalAndOversize() {
        val (store, project) = newProject()
        val browser = browser(store)
        assertThrows(IllegalArgumentException::class.java) {
            browser.extract(project, listOf("../outside.txt"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            browser.extract(project, listOf("assets/config.json", "assets/config.json"))
        }
        // Nada foi extraído
        assertTrue(browser.listEntries(project).isEmpty())
    }

    @Test
    fun reExtractionOfSamePathIsRefused() {
        val (store, project) = newProject()
        val browser = browser(store)
        browser.extract(project, listOf("assets/config.json"))
        assertThrows(IllegalArgumentException::class.java) {
            browser.extract(project, listOf("assets/config.json"))
        }
    }

    @Test
    fun readsTextPageAcrossBoundariesWithUtf8Alignment() {
        val (store, project) = newProject()
        val browser = browser(store)
        browser.extract(project, listOf("assets/config.json"))
        val page0 = browser.readTextPage(project, "assets/config.json")
        assertTrue(page0.text.startsWith("{"))
        assertTrue(page0.endedAtEof)
        assertEquals(page0.totalBytes, page0.returnedBytes.toLong())

        // Arquivo maior que uma página: força borda de offset
        val big = File(store.workspaceDirectory(project), "big.txt")
        big.parentFile.mkdirs()
        val payload = buildString { repeat(6000) { append("çãé") } } // multibyte
        big.writeText(payload, Charsets.UTF_8)
        var seen = StringBuilder()
        var offset = 0L
        while (true) {
            val page = browser.readTextPage(project, "big.txt", offset)
            seen.append(page.text)
            offset = page.nextOffset ?: break
        }
        assertEquals(payload, seen.toString())
    }

    @Test
    fun readTextPageRejectsTraversalAndOversize() {
        val (store, project) = newProject()
        val browser = browser(store)
        assertThrows(IllegalArgumentException::class.java) { browser.readTextPage(project, "../secret.txt") }
        assertThrows(IllegalArgumentException::class.java) { browser.readTextPage(project, "/etc/passwd") }
        assertThrows(IllegalArgumentException::class.java) { browser.readTextPage(project, "a/../b.txt") }
        val big = File(store.workspaceDirectory(project), "big.bin")
        big.writeBytes(ByteArray((WorkspaceBrowser.MAX_FILE_BYTES + 1).toInt()))
        assertThrows(IllegalArgumentException::class.java) { browser.readTextPage(project, "big.bin") }
        assertThrows(IllegalArgumentException::class.java) { browser.readHexPage(project, "big.bin") }
    }

    @Test
    fun readsHexPageWithAlignmentAndAscii() {
        val (store, project) = newProject()
        val browser = browser(store)
        browser.extract(project, listOf("lib/arm64/libn.so"))
        val page = browser.readHexPage(project, "lib/arm64/libn.so", offset = 0, rows = 1)
        assertEquals(1, page.lines.size)
        assertTrue(page.lines[0].startsWith("00000000"))
        assertTrue(page.lines[0].contains("|.ELF"))
        assertEquals(8L, page.totalBytes)
    }

    @Test
    fun textPagingPreservesCharactersSplitAcrossPageBoundary() {
        val (store, project) = newProject()
        val browser = browser(store)
        // Sequências de 4 bytes (emoji) para atravessar a borda de 16 KiB de várias fases.
        val payload = "🚀".repeat(4000) + "fim"
        val big = File(store.workspaceDirectory(project), "emoji.txt")
        big.parentFile.mkdirs()
        big.writeText(payload, Charsets.UTF_8)
        var seen = StringBuilder()
        var offset = 0L
        while (true) {
            val page = browser.readTextPage(project, "emoji.txt", offset)
            seen.append(page.text)
            offset = page.nextOffset ?: break
        }
        assertEquals(payload, seen.toString())
    }

    @Test
    fun workspaceListingRejectsMoreThanMaxEntries() {
        val (store, project) = newProject()
        val browser = browser(store)
        val dir = store.workspaceDirectory(project).resolve("many")
        dir.mkdirs()
        repeat(WorkspaceBrowser.MAX_ENTRIES + 1) { i ->
            java.nio.file.Files.createFile(dir.resolve("f$i.txt").toPath())
        }
        val ex = assertThrows(IllegalArgumentException::class.java) { browser.listEntries(project) }
        assertTrue(ex.message!!.contains("${WorkspaceBrowser.MAX_ENTRIES}"))
    }

    @Test
    fun hasEntryOnlyForExistingWorkspaceFiles() {
        val (store, project) = newProject()
        val browser = browser(store)
        assertFalse(browser.hasEntry(project, "assets/config.json"))
        browser.extract(project, listOf("assets/config.json"))
        assertTrue(browser.hasEntry(project, "assets/config.json"))
        assertFalse(browser.hasEntry(project, "missing.txt"))
    }
}

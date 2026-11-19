package com.readroid.app.core.project

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream

class ManifestSnapshotStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun project(): ApkProject {
        val store = ApkProjectStore(tmp.root)
        return store.importProject(ByteArrayInputStream("apk".toByteArray()), "demo.apk")
    }

    @Test
    fun savesAndLoadsVerifiedManifestBytes() {
        val store = ApkProjectStore(tmp.root)
        val project = project()
        val snapshots = ManifestSnapshotStore(store)
        val bytes = byteArrayOf(1, 2, 3, 4)
        val saved = snapshots.save(project, "edit-1", bytes)
        assertEquals(saved, snapshots.find(project, "edit-1"))
        assertArrayEquals(bytes, snapshots.load(saved))
    }

    @Test
    fun rejectsCorruptedSnapshot() {
        val store = ApkProjectStore(tmp.root)
        val project = project()
        val snapshot = ManifestSnapshotStore(store).save(project, "edit-2", byteArrayOf(9))
        snapshot.file.writeBytes(byteArrayOf(8))
        assertThrows(IllegalArgumentException::class.java) { ManifestSnapshotStore(store).load(snapshot) }
    }

    @Test
    fun rejectsUnsafeOperationId() {
        val store = ApkProjectStore(tmp.root)
        val project = project()
        assertThrows(IllegalArgumentException::class.java) {
            ManifestSnapshotStore(store).save(project, "../escape", byteArrayOf(1))
        }
    }
}

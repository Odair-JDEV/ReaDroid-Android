package com.readroid.app.core.project

import java.io.File
import java.security.MessageDigest

/**
 * Guarda a versão anterior do AndroidManifest.xml antes de uma edição.
 * O original.apk nunca é sobrescrito; snapshots são privados ao projeto,
 * identificados por digest e ligados ao OperationLog pelo operationId.
 */
data class ManifestSnapshot(
    val operationId: String,
    val manifestSha256: String,
    val file: File
)

class ManifestSnapshotStore(private val projectStore: ApkProjectStore) {
    private val snapshotDirName = "manifest-snapshots"

    fun save(project: ApkProject, operationId: String, manifestBytes: ByteArray): ManifestSnapshot {
        require(operationId.matches(Regex("[A-Za-z0-9._-]{1,128}"))) { "operationId inválido." }
        require(manifestBytes.isNotEmpty()) { "Manifesto vazio não pode ser salvo." }
        val digest = sha256(manifestBytes)
        val directory = File(projectStore.projectDirectory(project.projectId), snapshotDirName).also { it.mkdirs() }
        val target = File(directory, "$operationId-$digest.axml")
        val temporary = File(directory, ".$operationId.tmp")
        temporary.writeBytes(manifestBytes)
        require(sha256(temporary.readBytes()) == digest) { "Falha ao verificar snapshot do manifesto." }
        if (!temporary.renameTo(target)) {
            target.delete()
            require(temporary.renameTo(target)) { "Não foi possível persistir snapshot do manifesto." }
        }
        return ManifestSnapshot(operationId, digest, target)
    }

    fun load(snapshot: ManifestSnapshot): ByteArray {
        require(snapshot.file.isFile) { "Snapshot do manifesto não encontrado." }
        val bytes = snapshot.file.readBytes()
        require(sha256(bytes) == snapshot.manifestSha256) { "Snapshot do manifesto corrompido." }
        return bytes
    }

    fun find(project: ApkProject, operationId: String): ManifestSnapshot? {
        val directory = File(projectStore.projectDirectory(project.projectId), snapshotDirName)
        return directory.listFiles()?.firstOrNull { it.name.startsWith("$operationId-") && it.extension == "axml" }?.let { file ->
            val digest = file.name.removePrefix("$operationId-").removeSuffix(".axml")
            if (digest.matches(Regex("[0-9a-f]{64}"))) ManifestSnapshot(operationId, digest, file) else null
        }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
}

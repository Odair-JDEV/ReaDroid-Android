package com.readroid.app.core.project

/**
 * Projeto de engenharia reversa criado a partir de um APK importado.
 * O identificador é o SHA-256 do arquivo original: dois imports do mesmo
 * arquivo convergem para o mesmo projeto e o mesmo original imutável.
 */
data class ApkProject(
    val projectId: String,
    val displayName: String,
    val originalSha256: String,
    val originalSizeBytes: Long,
    val packageName: String?,
    val versionName: String?,
    val importedAt: Long,
    val lastOpenedAt: Long
)

package com.readroid.app.core.axml

/**
 * Observações estruturadas e pagináveis do AndroidManifest.xml.
 * Cada linha é uma observação de campo decodificado; nada aqui é XML-fonte
 * ou garantia de fidelidade ao documento original.
 */
data class ManifestObservation(
    val category: ManifestObservationCategory,
    val label: String,
    val value: String?,
    val highlight: Boolean = false
)

enum class ManifestObservationCategory(val title: String) {
    IDENTITY("Identidade"),
    SDK("Compatibilidade"),
    SECURITY("Configurações de segurança"),
    PERMISSION("Permissões"),
    COMPONENT("Componentes")
}

data class ManifestObservationPage(
    val items: List<ManifestObservation>,
    val total: Int,
    val offset: Int,
    val limit: Int,
    val nextOffset: Int?
)

object ManifestObservations {

    const val DEFAULT_PAGE_SIZE = 60

    fun build(manifest: ParsedManifest?): List<ManifestObservation> {
        if (manifest == null) return emptyList()
        val out = mutableListOf<ManifestObservation>()

        out += ManifestObservation(ManifestObservationCategory.IDENTITY, "Pacote", manifest.packageName)
        out += ManifestObservation(ManifestObservationCategory.IDENTITY, "versionCode", manifest.versionCode)
        out += ManifestObservation(ManifestObservationCategory.IDENTITY, "versionName", manifest.versionName)
        out += ManifestObservation(ManifestObservationCategory.SDK, "minSdkVersion", manifest.minSdkVersion, highlight = true)
        out += ManifestObservation(ManifestObservationCategory.SDK, "targetSdkVersion", manifest.targetSdkVersion, highlight = true)

        manifest.application.let { app ->
            out += ManifestObservation(ManifestObservationCategory.SECURITY, "label", app.label)
            out += ManifestObservation(ManifestObservationCategory.SECURITY, "debuggable", app.isDebuggable?.toString() ?: "não declarado", highlight = app.isDebuggable == true)
            out += ManifestObservation(ManifestObservationCategory.SECURITY, "allowBackup", app.allowBackup?.toString() ?: "não declarado", highlight = app.allowBackup == true)
            out += ManifestObservation(ManifestObservationCategory.SECURITY, "usesCleartextTraffic", app.usesCleartextTraffic?.toString() ?: "não declarado", highlight = app.usesCleartextTraffic == true)
        }

        manifest.permissions.forEach { permission ->
            out += ManifestObservation(ManifestObservationCategory.PERMISSION, "uses-permission", permission.name, highlight = true)
            permission.maxSdkVersion?.let {
                out += ManifestObservation(ManifestObservationCategory.PERMISSION, "maxSdkVersion", it)
            }
        }

        manifest.components.forEach { component ->
            out += ManifestObservation(
                ManifestObservationCategory.COMPONENT,
                component.type.xmlTag,
                component.name,
                highlight = component.exported == true
            )
            component.exported?.let {
                out += ManifestObservation(ManifestObservationCategory.COMPONENT, "${component.type.xmlTag} · exported", it.toString())
            }
            component.permission?.let {
                out += ManifestObservation(ManifestObservationCategory.COMPONENT, "${component.type.xmlTag} · permission", it)
            }
        }
        return out
    }

    fun filter(observations: List<ManifestObservation>, query: String): List<ManifestObservation> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return observations
        return observations.filter {
            it.label.lowercase().contains(q) || (it.value?.lowercase()?.contains(q) == true)
        }
    }

    fun page(observations: List<ManifestObservation>, offset: Int, limit: Int = DEFAULT_PAGE_SIZE): ManifestObservationPage {
        require(offset >= 0) { "offset deve ser não negativo." }
        require(limit > 0) { "limit deve ser positivo." }
        val total = observations.size
        val start = offset.coerceAtMost(total)
        val end = (start + limit).coerceAtMost(total)
        return ManifestObservationPage(
            items = observations.subList(start, end),
            total = total,
            offset = start,
            limit = limit,
            nextOffset = end.takeIf { it < total }
        )
    }
}

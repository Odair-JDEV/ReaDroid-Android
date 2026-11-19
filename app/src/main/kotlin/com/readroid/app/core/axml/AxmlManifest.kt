package com.readroid.app.core.axml

/**
 * Representa os dados essenciais decodificados de um AndroidManifest.xml.
 */
data class ParsedManifest(
    val packageName: String?,
    val versionCode: String?,
    val versionName: String?,
    val minSdkVersion: String? = null,
    val targetSdkVersion: String? = null,
    val permissions: List<ManifestPermission> = emptyList(),
    val application: ManifestApplication = ManifestApplication(),
    val components: List<ManifestComponent> = emptyList(),
    val rawXml: String? = null,
    val decodedBy: String = "ReaDroid (leitor AXML nativo)"
)

data class ManifestPermission(
    val name: String,
    val maxSdkVersion: String? = null
)

data class ManifestApplication(
    val label: String? = null,
    val isDebuggable: Boolean? = null,
    val allowBackup: Boolean? = null,
    val usesCleartextTraffic: Boolean? = null
)

enum class ComponentType(val xmlTag: String) {
    ACTIVITY("activity"),
    ACTIVITY_ALIAS("activity-alias"),
    SERVICE("service"),
    RECEIVER("receiver"),
    PROVIDER("provider");

    companion object {
        fun fromTag(tag: String): ComponentType? = entries.find { it.xmlTag == tag }
    }
}

data class ManifestComponent(
    val type: ComponentType,
    val name: String,
    val exported: Boolean?,
    val permission: String? = null
)

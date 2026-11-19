package com.readroid.app.core.analyzer

/** A bounded presentation page over the already-limited resource string inventory. */
data class ResourceStringPage(
    val items: List<ResourceString>,
    val total: Int,
    val offset: Int,
    val limit: Int,
    val nextOffset: Int?,
    val sourceTruncated: Boolean,
    val sourceWarnings: List<String>
)

object ResourceTablePagination {
    fun page(
        inspection: ResourceTableInspection,
        offset: Int,
        limit: Int = DEFAULT_PAGE_SIZE
    ): ResourceStringPage {
        require(offset >= 0) { "offset deve ser não negativo." }
        require(limit > 0) { "limit deve ser positivo." }

        val total = inspection.strings.size
        val start = offset.coerceAtMost(total)
        val end = (start + limit).coerceAtMost(total)
        return ResourceStringPage(
            items = inspection.strings.subList(start, end),
            total = total,
            offset = start,
            limit = limit,
            nextOffset = end.takeIf { it < total },
            sourceTruncated = inspection.isTruncated,
            sourceWarnings = inspection.warnings
        )
    }

    const val DEFAULT_PAGE_SIZE = 40
}

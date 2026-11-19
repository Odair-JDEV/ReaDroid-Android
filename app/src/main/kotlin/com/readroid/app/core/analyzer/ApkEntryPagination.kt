package com.readroid.app.core.analyzer

/** Deterministic pagination over the filtered ZIP entry inventory. */
data class ApkEntryPage(
    val items: List<ApkEntryInfo>,
    val total: Int,
    val offset: Int,
    val limit: Int,
    val nextOffset: Int?
)

object ApkEntryPagination {
    fun page(filtered: List<ApkEntryInfo>, offset: Int, limit: Int = DEFAULT_PAGE_SIZE): ApkEntryPage {
        require(offset >= 0) { "offset deve ser não negativo." }
        require(limit > 0) { "limit deve ser positivo." }
        val total = filtered.size
        val start = offset.coerceAtMost(total)
        val end = (start + limit).coerceAtMost(total)
        return ApkEntryPage(
            items = filtered.subList(start, end),
            total = total,
            offset = start,
            limit = limit,
            nextOffset = end.takeIf { it < total }
        )
    }

    const val DEFAULT_PAGE_SIZE = 50
}

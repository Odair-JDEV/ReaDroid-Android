package com.readroid.app.core.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ResourceTablePaginationTest {

    private fun inspection(count: Int, truncated: Boolean = false, warnings: List<String> = emptyList()) =
        ResourceTableInspection(
            stringPoolPresent = true,
            strings = (0 until count).map { ResourceString(index = it, value = "value-$it") },
            packageCount = 1,
            chunkCount = 2,
            isTruncated = truncated,
            warnings = warnings
        )

    @Test
    fun firstPageHasOffsetZeroAndNextOffset() {
        val page = ResourceTablePagination.page(inspection(100), offset = 0, limit = 40)
        assertEquals(0, page.offset)
        assertEquals(40, page.items.size)
        assertEquals(40, page.nextOffset)
        assertEquals(100, page.total)
        assertEquals(0, page.items.first().index)
        assertEquals(39, page.items.last().index)
    }

    @Test
    fun middlePagePreservesOrderAndBounds() {
        val page = ResourceTablePagination.page(inspection(100), offset = 40, limit = 40)
        assertEquals(40, page.offset)
        assertEquals(40, page.items.size)
        assertEquals(40, page.items.first().index)
        assertEquals(79, page.items.last().index)
        assertEquals(80, page.nextOffset)
    }

    @Test
    fun finalPageIsShorterAndHasNoNext() {
        val page = ResourceTablePagination.page(inspection(100), offset = 80, limit = 40)
        assertEquals(20, page.items.size)
        assertEquals(99, page.items.last().index)
        assertNull(page.nextOffset)
    }

    @Test
    fun offsetBeyondTotalCoercesToEmptyPage() {
        val page = ResourceTablePagination.page(inspection(10), offset = 500, limit = 40)
        assertTrue(page.items.isEmpty())
        assertEquals(10, page.offset)
        assertNull(page.nextOffset)
        assertEquals(10, page.total)
    }

    @Test
    fun emptyInventoryYieldsEmptyPageWithoutNext() {
        val page = ResourceTablePagination.page(inspection(0), offset = 0)
        assertTrue(page.items.isEmpty())
        assertNull(page.nextOffset)
        assertEquals(0, page.total)
    }

    @Test
    fun defaultLimitIsForty() {
        val page = ResourceTablePagination.page(inspection(5), offset = 0)
        assertEquals(5, page.items.size)
        assertEquals(ResourceTablePagination.DEFAULT_PAGE_SIZE, page.limit)
    }

    @Test
    fun concatenationOfPagesEqualsFullList() {
        val total = 137
        var offset = 0
        val collected = mutableListOf<ResourceString>()
        while (true) {
            val page = ResourceTablePagination.page(inspection(total), offset = offset)
            collected += page.items
            offset = page.nextOffset ?: break
        }
        assertEquals(total, collected.size)
        assertEquals((0 until total).toList(), collected.map { it.index })
    }

    @Test
    fun sourceTruncationAndWarningsArePropagated() {
        val page = ResourceTablePagination.page(
            inspection(3, truncated = true, warnings = listOf("Limite de chunks atingido.")),
            offset = 0
        )
        assertTrue(page.sourceTruncated)
        assertEquals(listOf("Limite de chunks atingido."), page.sourceWarnings)
    }

    @Test
    fun negativeOffsetAndZeroLimitAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            ResourceTablePagination.page(inspection(1), offset = -1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ResourceTablePagination.page(inspection(1), offset = 0, limit = 0)
        }
    }

    @Test
    fun hostileStringValuesAreReturnedVerbatimWithoutTransformation() {
        val hostile = listOf(
            "# Heading\n- forged list\n```code```",
            "\u0000null-ish",
            "‮reversed‮",
            "x".repeat(4096),
            "\n\n   "
        )
        val table = inspection(0).copy(strings = hostile.mapIndexed { i, v -> ResourceString(i, v) })
        val page = ResourceTablePagination.page(table, offset = 0, limit = 2)
        assertEquals(2, page.items.size)
        assertEquals(hostile[0], page.items[0].value)
        assertEquals(hostile[1], page.items[1].value)
    }
}

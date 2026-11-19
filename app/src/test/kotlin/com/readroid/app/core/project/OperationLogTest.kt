package com.readroid.app.core.project

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OperationLogTest {
    @get:Rule val temp = TemporaryFolder()
    private val baseHash = "a".repeat(64)

    @Test
    fun appendAndReadRecordsPreserveChainAndDeterministicTimestamp() {
        var now = 10L
        val log = OperationLog(temp.root, { now++ })
        val first = log.append("op-1", "IMPORT", baseHash, status = "COMMITTED")
        val second = log.append("op-2", "EDIT", baseHash, inputSha256 = baseHash, outputSha256 = "b".repeat(64), status = "COMMITTED")
        val records = log.readAll()
        assertEquals(1L, first.seq)
        assertEquals(10L, first.timestamp)
        assertEquals(11L, second.timestamp)
        assertEquals(first.recordHash, second.prevRecordHash)
        assertEquals(2, records.size)
        assertEquals(second.recordHash, records.last().recordHash)
    }

    @Test
    fun tamperingWithRecordIsDetectedAtExactSequence() {
        val log = OperationLog(temp.root, { 42L })
        log.append("op-1", "IMPORT", baseHash, status = "COMMITTED")
        log.append("op-2", "EDIT", baseHash, status = "COMMITTED")
        val file = temp.root.resolve("log.jsonl")
        val text = file.readText().replace("\"EDIT\"", "\"TAMPER\"")
        file.writeText(text)
        try {
            log.readAll()
            throw AssertionError("log tampering must fail closed")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("sequência 2"))
        }
    }

    @Test
    fun malformedJsonFailsClosed() {
        temp.root.resolve("log.jsonl").writeText("{bad json}\n")
        try {
            OperationLog(temp.root).readAll()
            throw AssertionError("malformed log must fail closed")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("linha 1"))
        }
    }
}

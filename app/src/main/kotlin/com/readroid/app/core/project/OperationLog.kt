package com.readroid.app.core.project

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/** Registro append-only de operações que altera ou materializa dados do projeto. */
data class OperationRecord(
    val seq: Long,
    val operationId: String,
    val type: String,
    val timestamp: Long,
    val baseSha256: String,
    val inputSha256: String?,
    val outputPath: String?,
    val outputSha256: String?,
    val status: String,
    val message: String?,
    val prevRecordHash: String?,
    val recordHash: String
)

class OperationLog(
    private val directory: File,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val logFile = File(directory, "log.jsonl")

    @Synchronized
    fun append(
        operationId: String,
        type: String,
        baseSha256: String,
        inputSha256: String? = null,
        outputPath: String? = null,
        outputSha256: String? = null,
        status: String,
        message: String? = null
    ): OperationRecord {
        require(operationId.isNotBlank() && type.isNotBlank() && status.isNotBlank())
        require(baseSha256.matches(Regex("[0-9a-f]{64}"))) { "Hash base inválido." }
        val previous = readAllInternal().lastOrNull()
        val record = OperationRecord(
            seq = (previous?.seq ?: 0L) + 1L,
            operationId = operationId,
            type = type,
            timestamp = clock(),
            baseSha256 = baseSha256,
            inputSha256 = inputSha256,
            outputPath = outputPath,
            outputSha256 = outputSha256,
            status = status,
            message = message,
            prevRecordHash = previous?.recordHash,
            recordHash = ""
        )
        val hash = sha256(canonical(record))
        val finalized = record.copy(recordHash = hash)
        directory.mkdirs()
        logFile.appendText(toJson(finalized).toString() + "\n", Charsets.UTF_8)
        return finalized
    }

    @Synchronized
    fun readAll(): List<OperationRecord> = readAllInternal()

    private fun readAllInternal(): List<OperationRecord> {
        if (!logFile.exists()) return emptyList()
        var previous: OperationRecord? = null
        return logFile.readLines(Charsets.UTF_8).filter { it.isNotBlank() }.mapIndexed { index, line ->
            val json = try { JSONObject(line) } catch (e: Exception) {
                throw IllegalStateException("Registro de operação inválido na linha ${index + 1}.", e)
            }
            val record = fromJson(json)
            require(record.seq == index + 1L) { "Sequência de operação inválida na linha ${index + 1}." }
            require(record.prevRecordHash == previous?.recordHash) {
                "Encadeamento de operações quebrado na sequência ${record.seq}."
            }
            require(record.recordHash == sha256(canonical(record.copy(recordHash = "")))) {
                "Hash do registro inválido na sequência ${record.seq}."
            }
            previous = record
            record
        }
    }

    private fun canonical(record: OperationRecord): String = listOf(
        record.seq.toString(), record.operationId, record.type, record.timestamp.toString(),
        record.baseSha256, record.inputSha256.orEmpty(), record.outputPath.orEmpty(),
        record.outputSha256.orEmpty(), record.status, record.message.orEmpty(), record.prevRecordHash.orEmpty()
    ).joinToString("\u001f")

    private fun toJson(record: OperationRecord) = JSONObject().apply {
        put("seq", record.seq); put("operationId", record.operationId); put("type", record.type)
        put("timestamp", record.timestamp); put("baseSha256", record.baseSha256)
        put("inputSha256", record.inputSha256 ?: JSONObject.NULL); put("outputPath", record.outputPath ?: JSONObject.NULL)
        put("outputSha256", record.outputSha256 ?: JSONObject.NULL); put("status", record.status)
        put("message", record.message ?: JSONObject.NULL); put("prevRecordHash", record.prevRecordHash ?: JSONObject.NULL)
        put("recordHash", record.recordHash)
    }

    private fun fromJson(json: JSONObject) = OperationRecord(
        seq = json.getLong("seq"), operationId = json.getString("operationId"), type = json.getString("type"),
        timestamp = json.getLong("timestamp"), baseSha256 = json.getString("baseSha256"),
        inputSha256 = json.optString("inputSha256").takeIf { it.isNotEmpty() && it != "null" },
        outputPath = json.optString("outputPath").takeIf { it.isNotEmpty() && it != "null" },
        outputSha256 = json.optString("outputSha256").takeIf { it.isNotEmpty() && it != "null" },
        status = json.getString("status"), message = json.optString("message").takeIf { it.isNotEmpty() && it != "null" },
        prevRecordHash = json.optString("prevRecordHash").takeIf { it.isNotEmpty() && it != "null" },
        recordHash = json.getString("recordHash")
    )

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}

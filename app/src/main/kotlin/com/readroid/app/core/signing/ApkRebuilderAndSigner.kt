package com.readroid.app.core.signing

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.FilterOutputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * Motor completo de reconstrução de APK e assinatura com a biblioteca oficial Google apksig.
 */
object ApkRebuilderAndSigner {

    /**
     * Substitui o AndroidManifest.xml binário dentro de um APK e gera um novo arquivo não assinado.
     */
    fun replaceManifest(sourceApk: File, outputApk: File, newManifestBytes: ByteArray) {
        require(sourceApk.isFile) { "O APK de origem não existe." }
        require(!outputApk.exists() || outputApk.delete()) { "Não foi possível substituir o APK temporário." }
        val buffer = ByteArray(64 * 1024)
        ZipFile(sourceApk).use { zipIn ->
            val offsetCounter = CountingOutputStream(outputApk.outputStream().buffered())
            ZipOutputStream(offsetCounter).use { zipOut ->
                val entries = zipIn.entries()
                var manifestSeen = false
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (isSignatureEntry(entry.name)) continue
                    val isManifest = entry.name == "AndroidManifest.xml"
                    if (isManifest) manifestSeen = true
                    val newEntry = if (isManifest) buildReplacementEntry(entry, newManifestBytes) else ZipEntry(entry)
                    val needs16k = newEntry.name.endsWith(".so", ignoreCase = true)
                    val needs4 = newEntry.name == "resources.arsc"
                    if ((needs16k || needs4) && newEntry.method == ZipEntry.STORED) {
                        padToAlignment(offsetCounter, newEntry, if (needs16k) 16384L else 4L)
                    }
                    zipOut.putNextEntry(newEntry)
                    if (isManifest) {
                        zipOut.write(newManifestBytes)
                    } else {
                        zipIn.getInputStream(entry).use { input ->
                            while (true) {
                                val length = input.read(buffer)
                                if (length < 0) break
                                zipOut.write(buffer, 0, length)
                            }
                        }
                    }
                    zipOut.closeEntry()
                }
                require(manifestSeen) { "O APK não contém AndroidManifest.xml." }
            }
        }
        validateInstallCriticalEntries(outputApk)
    }

    private fun buildReplacementEntry(original: ZipEntry, bytes: ByteArray): ZipEntry {
        val replacement = if (original.method == ZipEntry.STORED) {
            ZipEntry(original)
        } else {
            ZipEntry(original.name).apply {
                time = original.time
                comment = original.comment
                extra = original.extra
                method = ZipEntry.DEFLATED
            }
        }
        if (replacement.method == ZipEntry.STORED) {
            replacement.size = bytes.size.toLong()
            replacement.compressedSize = bytes.size.toLong()
            replacement.crc = java.util.zip.CRC32().apply { update(bytes) }.value
        }
        return replacement
    }

    private fun padToAlignment(counter: CountingOutputStream, entry: ZipEntry, alignment: Long) {
        val nameBytes = entry.name.toByteArray(Charsets.UTF_8)
        val baseOffset = counter.count + 30L + nameBytes.size
        val existing = entry.extra ?: byteArrayOf()
        val extra = existing.copyOf()
        var padding = ((alignment - (baseOffset + extra.size) % alignment) % alignment).toInt()
        if (padding in 1..3) padding += alignment.toInt()
        if (padding > 0) {
            val fieldLength = padding - 4
            val padded = extra + byteArrayOf(0xD935.toByte(), 0xA7.toByte(), fieldLength.toByte(), (fieldLength ushr 8).toByte()) + ByteArray(fieldLength)
            entry.extra = padded
        }
    }

    private class CountingOutputStream(output: OutputStream) : FilterOutputStream(output) {
        var count: Long = 0
            private set

        override fun write(value: Int) {
            out.write(value)
            count++
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            out.write(bytes, offset, length)
            count += length
        }
    }

    private fun isSignatureEntry(name: String): Boolean {
        if (!name.startsWith("META-INF/", ignoreCase = true)) return false
        val leaf = name.substringAfterLast('/').uppercase()
        return leaf == "MANIFEST.MF" || leaf.endsWith(".SF") || leaf.endsWith(".RSA") ||
            leaf.endsWith(".DSA") || leaf.endsWith(".EC") || leaf.startsWith("SIG-")
    }

    private fun validateInstallCriticalEntries(apk: File) {
        ZipFile(apk).use { zip ->
            val resources = zip.getEntry("resources.arsc")
            if (resources != null) {
                require(resources.method == ZipEntry.STORED) {
                    "Reconstrução recusada: resources.arsc precisa permanecer STORED para instalação segura."
                }
                require(entryDataOffset(apk, "resources.arsc") % 4L == 0L) {
                    "Reconstrução recusada: resources.arsc não está alinhado a 4 bytes."
                }
            }
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.name.endsWith(".so", ignoreCase = true)) {
                    require(entry.method == ZipEntry.STORED) {
                        "Reconstrução recusada: bibliotecas nativas precisam permanecer STORED."
                    }
                    require(entryDataOffset(apk, entry.name) % 16384L == 0L) {
                        "Reconstrução recusada: biblioteca nativa sem alinhamento de 16 KiB."
                    }
                }
            }
        }
    }

    private fun entryDataOffset(apk: File, entryName: String): Long {
        java.io.RandomAccessFile(apk, "r").use { file ->
            val bytes = java.nio.file.Files.readAllBytes(apk.toPath())
            for (offset in bytes.size - 22 downTo maxOf(0, bytes.size - 65557)) {
                if (readLeInt(bytes, offset) == 0x06054b50) {
                    val centralOffset = readLeInt(bytes, offset + 16)
                    var cursor = centralOffset
                    while (readLeInt(bytes, cursor) == 0x02014b50) {
                        val nameLength = readLeShort(bytes, cursor + 28)
                        val extraLength = readLeShort(bytes, cursor + 30)
                        val commentLength = readLeShort(bytes, cursor + 32)
                        val name = String(bytes, cursor + 46, nameLength, Charsets.UTF_8)
                        if (name == entryName) {
                            val localOffset = readLeInt(bytes, cursor + 42)
                            val localNameLength = readLeShort(bytes, localOffset + 26)
                            val localExtraLength = readLeShort(bytes, localOffset + 28)
                            return localOffset + 30L + localNameLength + localExtraLength
                        }
                        cursor += 46 + nameLength + extraLength + commentLength
                    }
                }
            }
        }
        throw IllegalStateException("Não foi possível localizar $entryName no diretório ZIP.")
    }

    private fun readLeShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun readLeInt(bytes: ByteArray, offset: Int): Int =
        readLeShort(bytes, offset) or (readLeShort(bytes, offset + 2) shl 16)

    /**
     * Assina o APK de entrada gerando o APK final via apksig (v1, v2 e v3 habilitados).
     */
    fun signApk(
        unsignedApk: File,
        signedApk: File,
        keyStore: KeyStore,
        config: KeystoreConfig
    ): SigningResult {
        return try {
            val privateKey = keyStore.getKey(config.alias, config.keyPass) as PrivateKey
            val cert = keyStore.getCertificate(config.alias) as X509Certificate

            val signerConfig = ApkSigner.SignerConfig.Builder(
                config.alias,
                privateKey,
                listOf(cert)
            ).build()

            val apkSigner = ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(unsignedApk)
                .setOutputApk(signedApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()

            apkSigner.sign()
            require(signedApk.isFile && signedApk.length() > 0L) { "apksig não gerou um APK de saída válido." }
            val verification = ApkVerifier.Builder(signedApk).build().verify()
            require(verification.isVerified) {
                "Verificação da assinatura falhou: ${verification.errors.joinToString("; ") { it.toString() }}"
            }
            require(verification.isVerifiedUsingV2Scheme || verification.isVerifiedUsingV3Scheme) {
                "APK verificado sem esquema v2 ou v3; resultado recusado."
            }

            val sha256 = signedApk.inputStream().use {
                com.readroid.app.core.analyzer.ApkAnalyzer.calculateSha256(it)
            }

            SigningResult(
                isSuccess = true,
                outputApkPath = signedApk.absolutePath,
                sha256 = sha256,
                message = "APK assinado com sucesso via apksig (v1/v2/v3)!"
            )
        } catch (e: Exception) {
            SigningResult(
                isSuccess = false,
                outputApkPath = null,
                sha256 = null,
                message = "Falha ao assinar APK: ${e.message}"
            )
        }
    }
}

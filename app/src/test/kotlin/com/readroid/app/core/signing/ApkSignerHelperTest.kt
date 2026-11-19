package com.readroid.app.core.signing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate

/**
 * O apksig só aceita assinar quando o certificado e a chave privada formam um par
 * real. A versão anterior guardava um certificado PEM fixo no código, que não
 * correspondia à chave gerada — este teste trava essa regressão.
 */
class ApkSignerHelperTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun generatedCertificateMatchesThePrivateKeyItIsStoredWith() {
        val keystoreFile = File(tempFolder.root, "signing.p12")
        val config = KeystoreConfig(storePass = "teste123".toCharArray(), keyPass = "teste123".toCharArray())

        val keyStore = ApkSignerHelper.getOrCreateLocalKeystore(keystoreFile, config)

        val privateKey = keyStore.getKey(config.alias, config.keyPass) as PrivateKey
        val certificate = keyStore.getCertificate(config.alias) as X509Certificate

        assertTrue("a keystore deve ser gravada em disco", keystoreFile.exists())
        assertNotNull(privateKey)
        assertNotNull(certificate)

        // Assinar e verificar com a chave pública do certificado prova o pareamento.
        val payload = "readroid-signing-check".toByteArray(Charsets.UTF_8)
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(payload)
        val signature = signer.sign()

        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(certificate.publicKey)
        verifier.update(payload)

        assertTrue("o certificado deve validar o que a chave privada assinou", verifier.verify(signature))
    }

    @Test
    fun reopeningTheKeystoreReusesTheSameIdentity() {
        val keystoreFile = File(tempFolder.root, "reuse.p12")
        val config = KeystoreConfig(storePass = "teste123".toCharArray(), keyPass = "teste123".toCharArray())

        val first = (ApkSignerHelper.getOrCreateLocalKeystore(keystoreFile, config)
            .getCertificate(config.alias) as X509Certificate).encoded
        val second = (ApkSignerHelper.getOrCreateLocalKeystore(keystoreFile, config)
            .getCertificate(config.alias) as X509Certificate).encoded

        assertArrayEqualsMessage(first, second)
    }

    @Test
    fun certificateIsSelfSignedAndCurrentlyValid() {
        val keystoreFile = File(tempFolder.root, "validity.p12")
        val config = KeystoreConfig(storePass = "teste123".toCharArray(), keyPass = "teste123".toCharArray())

        val certificate = ApkSignerHelper.getOrCreateLocalKeystore(keystoreFile, config)
            .getCertificate(config.alias) as X509Certificate

        certificate.checkValidity()
        assertEquals(certificate.subjectX500Principal, certificate.issuerX500Principal)
        assertFalse("o certificado não deve expirar antes do APK", certificate.notAfter.time <= System.currentTimeMillis())
    }

    @Test
    fun storedKeystoreIsPkcs12AndHoldsTheKeyEntry() {
        val keystoreFile = File(tempFolder.root, "type.p12")
        val config = KeystoreConfig(storePass = "teste123".toCharArray(), keyPass = "teste123".toCharArray())
        ApkSignerHelper.getOrCreateLocalKeystore(keystoreFile, config)

        val reloaded = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { reloaded.load(it, config.storePass) }

        assertEquals("PKCS12", reloaded.type)
        assertTrue(reloaded.isKeyEntry(config.alias))
    }

    private fun assertArrayEqualsMessage(expected: ByteArray, actual: ByteArray) {
        assertTrue("a mesma keystore deve devolver o mesmo certificado", expected.contentEquals(actual))
    }
}

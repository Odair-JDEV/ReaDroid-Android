package com.readroid.app.core.signing

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Provider
import java.security.cert.X509Certificate
import java.util.Date

data class KeystoreConfig(
    val alias: String = "readroid",
    val storePass: CharArray,
    val keyPass: CharArray
)

data class SigningResult(
    val isSuccess: Boolean,
    val outputApkPath: String? = null,
    val sha256: String? = null,
    val message: String
)

/**
 * Gerenciamento de chaves e assinatura de APK dentro do dispositivo.
 *
 * O certificado precisa ser autoassinado pela mesma chave privada guardada no
 * keystore: o apksig rejeita a assinatura quando certificado e chave não formam
 * um par válido, então o certificado é derivado da chave gerada, nunca copiado.
 */
object ApkSignerHelper {

    private const val KEY_ALGORITHM = "RSA"
    private const val LEGACY_PASSWORD = "readroid123"

    fun randomPassword(): CharArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it) }.toCharArray()

    private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
    private const val VALIDITY_DAYS = 10_000L

    /**
     * Instância usada diretamente pelos builders, sem registro global por nome.
     * O Android já traz um provider "BC" próprio e reduzido, que não tem as
     * classes de `org.bouncycastle.operator` usadas aqui; pedir o provider pelo
     * nome poderia resolver para esse "BC" e falhar.
     */
    private val provider: Provider by lazy { BouncyCastleProvider() }

    private const val SIGNING_PREFS = "readroid_signing_credentials"
    private const val STORE_PASSWORD = "store_password"
    private const val KEY_PASSWORD = "key_password"

    fun getOrCreateProductionKeystore(context: Context, keystoreFile: File): Pair<KeyStore, KeystoreConfig> {
        val masterKey = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val prefs = EncryptedSharedPreferences.create(
            SIGNING_PREFS, masterKey, context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        var storePassword = prefs.getString(STORE_PASSWORD, null)
        var keyPassword = prefs.getString(KEY_PASSWORD, null)
        if (keystoreFile.exists() && (storePassword == null || keyPassword == null)) {
            val legacy = legacyConfig()
            val legacyStore = KeyStore.getInstance("PKCS12")
            keystoreFile.inputStream().use { legacyStore.load(it, legacy.storePass) }
            if (legacyStore.containsAlias(legacy.alias)) {
                storePassword = LEGACY_PASSWORD
                keyPassword = LEGACY_PASSWORD
            }
        }
        if (storePassword == null || keyPassword == null) {
            storePassword = randomPassword().concatToString()
            keyPassword = storePassword
        }
        check(prefs.edit().putString(STORE_PASSWORD, storePassword).putString(KEY_PASSWORD, keyPassword).commit()) {
            "Não foi possível persistir com segurança a credencial da chave de assinatura."
        }
        val config = KeystoreConfig(storePass = storePassword.toCharArray(), keyPass = keyPassword.toCharArray())
        return getOrCreateLocalKeystore(keystoreFile, config) to config
    }

    private fun legacyConfig(alias: String = "readroid"): KeystoreConfig = KeystoreConfig(
        alias, LEGACY_PASSWORD.toCharArray(), LEGACY_PASSWORD.toCharArray()
    )

    /**
     * Cria ou obtém uma Keystore PKCS12 persistente no diretório interno do aplicativo.
     */
    fun getOrCreateLocalKeystore(keystoreFile: File, config: KeystoreConfig): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        if (keystoreFile.exists()) {
            keystoreFile.inputStream().use { input -> ks.load(input, config.storePass) }
            if (ks.containsAlias(config.alias)) return ks
        } else {
            ks.load(null, config.storePass)
        }

        val keyPair = generateKeyPair()
        val cert = generateSelfSignedCertificate(keyPair, config.alias)

        ks.setKeyEntry(config.alias, keyPair.private, config.keyPass, arrayOf(cert))
        keystoreFile.parentFile?.mkdirs()
        FileOutputStream(keystoreFile).use { out -> ks.store(out, config.storePass) }

        return ks
    }

    private fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        generator.initialize(2048, SecureRandom())
        return generator.generateKeyPair()
    }

    private fun generateSelfSignedCertificate(keyPair: KeyPair, alias: String): X509Certificate {
        val distinguishedName = X500Name("CN=$alias, O=ReaDroid, C=BR")
        val notBefore = Date()
        val notAfter = Date(notBefore.time + VALIDITY_DAYS * 24 * 60 * 60 * 1000)
        val serial = BigInteger(64, SecureRandom()).abs().max(BigInteger.ONE)

        val builder = JcaX509v3CertificateBuilder(
            distinguishedName,
            serial,
            notBefore,
            notAfter,
            distinguishedName,
            keyPair.public
        )

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
            .setProvider(provider)
            .build(keyPair.private)

        return JcaX509CertificateConverter()
            .setProvider(provider)
            .getCertificate(builder.build(signer))
    }
}

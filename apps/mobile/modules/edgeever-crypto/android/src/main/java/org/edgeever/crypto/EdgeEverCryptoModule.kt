package org.edgeever.crypto

import android.util.Base64
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val GCM_TAG_LENGTH_BITS = 128
private const val GCM_IV_LENGTH_BYTES = 12
private const val AES_KEY_LENGTH_BYTES = 32

class EdgeEverCryptoModule : Module() {
  private val secureRandom = SecureRandom()

  override fun definition() = ModuleDefinition {
    Name("EdgeEverCrypto")

    AsyncFunction("randomBytes") { length: Int ->
      if (length < 1 || length > 1024 * 1024) {
        throw CodedException("ERR_CRYPTO_INVALID_ARG", "randomBytes length must be between 1 and 1048576.", null)
      }
      val bytes = ByteArray(length)
      try {
        secureRandom.nextBytes(bytes)
        Base64.encodeToString(bytes, Base64.NO_WRAP)
      } finally {
        Arrays.fill(bytes, 0.toByte())
      }
    }

    AsyncFunction("pbkdf2Sha256") { passphrase: String, saltBase64: String, iterations: Int, keyLengthBytes: Int ->
      if (passphrase.isEmpty()) {
        throw CodedException("ERR_CRYPTO_INVALID_ARG", "Passphrase must be non-empty.", null)
      }
      if (iterations < 1) {
        throw CodedException("ERR_CRYPTO_INVALID_ARG", "PBKDF2 iterations must be positive.", null)
      }
      if (keyLengthBytes < 1 || keyLengthBytes > 1024) {
        throw CodedException("ERR_CRYPTO_INVALID_ARG", "keyLengthBytes is out of range.", null)
      }
      val salt = decodeBase64Strict(saltBase64)
      val chars = passphrase.toCharArray()
      val spec = PBEKeySpec(chars, salt, iterations, keyLengthBytes * 8)
      var derived: ByteArray? = null
      try {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        derived = factory.generateSecret(spec).encoded
        Base64.encodeToString(derived, Base64.NO_WRAP)
      } catch (error: Exception) {
        throw CodedException("ERR_CRYPTO_KDF_FAILED", error.message ?: "PBKDF2 key derivation failed.", error)
      } finally {
        spec.clearPassword()
        Arrays.fill(chars, '\u0000')
        Arrays.fill(salt, 0.toByte())
        derived?.let { Arrays.fill(it, 0.toByte()) }
      }
    }

    AsyncFunction("aesGcmEncrypt") { keyBase64: String, ivBase64: String, plaintextBase64: String, aadBase64: String ->
      val key = decodeBase64Strict(keyBase64)
      val iv = decodeBase64Strict(ivBase64)
      val plaintext = decodeBase64Strict(plaintextBase64)
      val aad = decodeBase64Strict(aadBase64)
      try {
        if (key.size != AES_KEY_LENGTH_BYTES) {
          throw CodedException("ERR_CRYPTO_INVALID_KEY", "AES-256-GCM requires a 32-byte key.", null)
        }
        if (iv.size != GCM_IV_LENGTH_BYTES) {
          throw CodedException("ERR_CRYPTO_INVALID_IV", "AES-256-GCM requires a 12-byte IV.", null)
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) {
          cipher.updateAAD(aad)
        }
        val ciphertext = cipher.doFinal(plaintext)
        Base64.encodeToString(ciphertext, Base64.NO_WRAP)
      } catch (error: CodedException) {
        throw error
      } catch (error: Exception) {
        throw CodedException("ERR_CRYPTO_ENCRYPT_FAILED", error.message ?: "AES-GCM encryption failed.", error)
      } finally {
        Arrays.fill(key, 0.toByte())
        Arrays.fill(iv, 0.toByte())
        Arrays.fill(plaintext, 0.toByte())
        Arrays.fill(aad, 0.toByte())
      }
    }

    AsyncFunction("aesGcmDecrypt") { keyBase64: String, ivBase64: String, ciphertextBase64: String, aadBase64: String ->
      val key = decodeBase64Strict(keyBase64)
      val iv = decodeBase64Strict(ivBase64)
      val ciphertext = decodeBase64Strict(ciphertextBase64)
      val aad = decodeBase64Strict(aadBase64)
      var plaintext: ByteArray? = null
      try {
        if (key.size != AES_KEY_LENGTH_BYTES) {
          throw CodedException("ERR_CRYPTO_INVALID_KEY", "AES-256-GCM requires a 32-byte key.", null)
        }
        if (iv.size != GCM_IV_LENGTH_BYTES) {
          throw CodedException("ERR_CRYPTO_INVALID_IV", "AES-256-GCM requires a 12-byte IV.", null)
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        if (aad.isNotEmpty()) {
          cipher.updateAAD(aad)
        }
        plaintext = cipher.doFinal(ciphertext)
        Base64.encodeToString(plaintext, Base64.NO_WRAP)
      } catch (error: CodedException) {
        throw error
      } catch (error: Exception) {
        throw CodedException("ERR_CRYPTO_DECRYPT_FAILED", error.message ?: "AES-GCM decryption failed.", error)
      } finally {
        Arrays.fill(key, 0.toByte())
        Arrays.fill(iv, 0.toByte())
        Arrays.fill(ciphertext, 0.toByte())
        Arrays.fill(aad, 0.toByte())
        plaintext?.let { Arrays.fill(it, 0.toByte()) }
      }
    }
  }

  private fun decodeBase64Strict(input: String): ByteArray {
    if (input.isEmpty()) return ByteArray(0)
    return try {
      Base64.decode(input, Base64.DEFAULT)
    } catch (error: IllegalArgumentException) {
      throw CodedException("ERR_CRYPTO_INVALID_BASE64", "Invalid Base64 input.", error)
    }
  }
}

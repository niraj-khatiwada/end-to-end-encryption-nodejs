const crypto = require('crypto')

const ENCRYPTION_ALGORITHM = 'aes-256-gcm'
const IV = crypto.randomBytes(16)

const DEFAULT_OPTIONS = {
  encrypt: {
    secretKey: null,
  },
  decrypt: {
    secretKey: null,
  },
}

class EncryptionService {
  encrypt(text, options = DEFAULT_OPTIONS.encrypt) {
    options = { ...DEFAULT_OPTIONS.encrypt, ...options }

    const cipher = crypto.createCipheriv(
      ENCRYPTION_ALGORITHM,
      Buffer.from(options.secretKey, 'hex'),
      IV
    )
    let encryptedText = cipher.update(text, 'utf8', 'hex')
    encryptedText += cipher.final('hex')

    const iv = IV.toString('hex')
    const authTag = cipher.getAuthTag().toString('hex')

    const payload = iv + encryptedText + authTag
    return Buffer.from(payload, 'hex').toString('base64')
  }

  decrypt(hash, options = DEFAULT_OPTIONS.decrypt) {
    options = { ...DEFAULT_OPTIONS.decrypt, ...options }

    const payload = Buffer.from(hash, 'base64').toString('hex')

    let iv = payload.slice(0, 32)
    let encryptedText = payload.slice(32, -32)
    let authTag = payload.slice(-32)

    let decipher = crypto.createDecipheriv(
      ENCRYPTION_ALGORITHM,
      Buffer.from(options.secretKey, 'hex'),
      Buffer.from(iv, 'hex')
    )
    decipher.setAuthTag(Buffer.from(authTag, 'hex'))
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }
}

module.exports = EncryptionService

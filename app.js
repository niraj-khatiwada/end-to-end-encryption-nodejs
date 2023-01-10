const crypto = require('crypto')
const EncryptionService = require('./EncryptionService')

const es = new EncryptionService()

const server = crypto.createECDH('secp256k1')
const device = crypto.createECDH('secp256k1')

server.generateKeys()
device.generateKeys()

const serverPublicKey = server.getPublicKey().toString('base64')
const devicePublicKey = device.getPublicKey().toString('base64')

const serverSecret = server.computeSecret(devicePublicKey, 'base64', 'hex')
const deviceSecret = device.computeSecret(serverPublicKey, 'base64', 'hex')

const encryptedData = es.encrypt(
  JSON.stringify({ date: new Date().toISOString() }),
  {
    secretKey: deviceSecret,
  }
)

console.log('ENCRYPTED', encryptedData)

const decryptData = es.decrypt(encryptedData, { secretKey: serverSecret })

console.log('DECRYPTED', decryptData)

console.log(crypto.randomBytes(32).toString('hex'))

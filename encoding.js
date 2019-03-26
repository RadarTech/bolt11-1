const bech32 = require('bech32')
const bs58check = require('bs58check')
const typeforce = require('typeforce')
const types = require('./types')
const Buffer = require('safe-buffer').Buffer

function fromBase58Check (address) {
  const payload = bs58check.decode(address)

  if (payload.length < 21) throw new TypeError(address + ' is too short')
  if (payload.length > 21) throw new TypeError(address + ' is too long')

  const version = payload.readUInt8(0)
  const hash = payload.slice(1)

  return { version: version, hash: hash }
}

function toBase58Check (hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments)

  const payload = Buffer.allocUnsafe(21)
  payload.writeUInt8(version, 0)
  hash.copy(payload, 1)

  return bs58check.encode(payload)
}

function fromBech32 (address) {
  const result = bech32.decode(address)
  const data = bech32.fromWords(result.words.slice(1))

  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data)
  }
}

function toBech32 (data, version, prefix) {
  const words = bech32.toWords(data)
  words.unshift(version)

  return bech32.encode(prefix, words)
}

module.exports = {
  fromBase58Check,
  toBase58Check,
  fromBech32,
  toBech32
}

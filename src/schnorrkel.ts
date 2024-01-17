import { Transcript } from '@rmf1723/merlin'
import { Point, Scalar } from '@rmf1723/ristretto255'
import nacl from '@rmf1723/tweetnacl'

const ctorKey: unique symbol = Symbol()

export { Transcript as SigningContext } from '@rmf1723/merlin'

export type KeySeed = Uint8Array

export function randomKeySeed(): KeySeed {
  return nacl.randomBytes(32)
}

export function expandKey(seed: KeySeed): SecretKey {
  if (seed.byteLength != 32) {
    throw new Error('invalid key seed length')
  }

  const t = new Transcript('ExpandSecretKeys')
  t.appendMessage('mini', seed)

  const key = t.challengeBytes('sk', 64)
  const nonce = t.challengeBytes('no', 32)

  return new SecretKey(ctorKey, Scalar.fromHash(key), nonce)
}

export default {
  randomKeySeed,
  expandKey,
}

export class SecretKey {
  #exponent: Scalar
  #nonce: Uint8Array

  constructor(key: typeof ctorKey, exponent: Scalar, nonce: Uint8Array) {
    if (key != ctorKey) {
      throw new Error('expand a key seed to construct a secret key')
    }

    if (nonce.byteLength != 32) {
      throw new Error('invalid nonce length')
    }

    this.#exponent = exponent
    this.#nonce = new Uint8Array(nonce)
  }

  get publicKey(): PublicKey {
    return new PublicKey(Point.BASE.mul(this.#exponent))
  }

  get exponent(): Scalar {
    return this.#exponent.clone()
  }

  get nonce(): Uint8Array {
    return this.#nonce.slice()
  }

  toBytes(): Uint8Array {
    const buf = new Uint8Array(64)
    buf.set(this.#exponent.toBytes(), 0)
    buf.set(this.#nonce, 32)
    return buf
  }

  static fromBytes(buf: ArrayBufferView): SecretKey {
    if (buf.byteLength != 64) {
      throw new Error('invalid secret key length')
    }
    const exponent = new Scalar(new Uint8Array(buf.buffer, buf.byteOffset, 32))
    const nonce = new Uint8Array(buf.buffer, buf.byteOffset + 32, 32)
    return new SecretKey(ctorKey, exponent, nonce)
  }

  sign(context: Transcript): Signature {
    context.appendMessage('proto-name', 'Schnorr-sig')
    context.appendMessage('sign:pk', this.publicKey.point.toBytes())

    const r = Scalar.fromHash(
      context
        .buildRng()
        .rekeyWithWitnessBytes('signing', this.#nonce)
        .finalize()
        .fillBytes(64)
    )
    const R = r.mulBase()
    context.appendMessage('sign:R', R.toBytes())

    const k = Scalar.fromHash(context.challengeBytes('sign:c', 64))
    const s = k.mul(this.#exponent).add(r)

    return new Signature(R, s)
  }
}

export class PublicKey {
  #point: Point

  constructor(point: Point) {
    this.#point = point.clone()
  }

  get point(): Point {
    return this.#point
  }

  toBytes(): Uint8Array {
    const buf = new Uint8Array(32)
    buf.set(this.#point.toBytes(), 0)
    return buf
  }

  static fromBytes(buf: ArrayBufferView): PublicKey {
    if (buf.byteLength != 32) {
      throw new Error('invalid public key length')
    }
    const point = new Point(new Uint8Array(buf.buffer, buf.byteOffset, 32))
    return new PublicKey(point)
  }

  verify(context: Transcript, sig: Signature): typeof ACCEPT {
    context.appendMessage('proto-name', 'Schnorr-sig')
    context.appendMessage('sign:pk', this.#point.toBytes())
    context.appendMessage('sign:R', sig.R.toBytes())

    const k = Scalar.fromHash(context.challengeBytes('sign:c', 64))
    const R = k.mul(this.#point.mul(Scalar.ONE.negate())).add(sig.s.mulBase())

    if (!R.equals(sig.R)) {
      throw new SignatureError()
    }

    return ACCEPT
  }
}

export class Signature {
  #R: Point
  #s: Scalar

  constructor(R: Point, s: Scalar) {
    this.#R = R
    this.#s = s
  }

  get R() {
    return this.#R
  }
  get s() {
    return this.#s
  }

  toBytes(): Uint8Array {
    const buf = new Uint8Array(64)
    buf.set(this.#R.toBytes(), 0)
    buf.set(this.#s.toBytes(), 32)
    return buf
  }

  static fromBytes(buf: ArrayBufferView): Signature {
    if (buf.byteLength != 64) {
      throw new Error('invalid signature length')
    }
    const R = new Point(new Uint8Array(buf.buffer, buf.byteOffset, 32))
    const s = new Scalar(new Uint8Array(buf.buffer, buf.byteOffset + 32, 32))
    return new Signature(R, s)
  }
}

export const ACCEPT = 'ACCEPT' as const

export class SignatureError extends Error {
  constructor() {
    super('invalid signature')
    this.name = 'SignatureError'
  }
}

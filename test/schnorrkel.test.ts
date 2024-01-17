import { test, expect } from 'vitest'
import schnorrkel, { SignatureError, SigningContext } from '../src/schnorrkel'

test('sign/verify', () => {
  const sk = schnorrkel.expandKey(schnorrkel.randomKeySeed())
  const pk = sk.publicKey

  const good = new SigningContext('test')
  const bad = good.clone()
  good.appendMessage('message', 'test message')
  bad.appendMessage('message', 'wrong message')

  const goodSig = sk.sign(good.clone())
  const badSig = sk.sign(bad.clone())

  expect(goodSig.toBytes()).not.toEqual(badSig.toBytes())

  expect(() => pk.verify(good, goodSig)).not.toThrow()
  expect(() => pk.verify(bad, badSig)).not.toThrow()
  expect(() => pk.verify(good, badSig)).toThrow(SignatureError)
  expect(() => pk.verify(bad, goodSig)).toThrow(SignatureError)
})

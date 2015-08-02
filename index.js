var crypto = require('crypto')
var sodium = require('chloride').api

function run (op) {

  var start = Date.now(), i = 0, end = Date.now()

  while((end = Date.now()) < start + 1000)
    op(++i)

  return i
}

var random = crypto.randomBytes(32)

function pad (n) {
  var s = ''
  while(n--) s += ' '
  return s
}

function even (left, right, size) {
  return left + pad(size - (left.length + right.length)) + right

}

function print (name, ops, standard) {
  console.log(
    even(name, ''+ops, 40), (standard/ops).toPrecision(3)
  )
}

console.log(even('operation', 'ops/sec', 40), 'ops/ops(hash)')

var hashes
print('hash_sha256', hashes = run(function () {
  return sodium.crypto_hash_sha256(random)
}), hashes)

print('hash', run(function () {
  return sodium.crypto_hash(random)
}), hashes)

var key = crypto.randomBytes(32)

print('auth', run(function () {
  return sodium.crypto_auth(random, key)
}), hashes)

var mac = sodium.crypto_auth(random, key)

print('verify', run(function () {
  return sodium.crypto_auth_verify(mac, random, key)
}), hashes)


print('randomBytes(32)', run(function () {
  return crypto.randomBytes(32)
}), hashes)


print('randombytes(new Buffer(32))', run(function () {
  return sodium.randombytes(new Buffer(32))
}), hashes)

var b = new Buffer(32)
print('randombytes(b)', run(function () {
  return sodium.randombytes(b)
}), hashes)



print('box_keypair', run(function () {
  return sodium.crypto_box_keypair()
}), hashes)

var alice = sodium.crypto_box_keypair()
var bob = sodium.crypto_box_keypair()

print('scalarmult', run(function () {
  return sodium.crypto_scalarmult(alice.secretKey, bob.publicKey)
}), hashes)


//print('box_keypair_seed', run(function () {
//  return sodium.crypto_box_keypair_seed(random)
//}))

print('sign_keypair', run(function () {
  return sodium.crypto_sign_keypair()
}), hashes)

//print('sign_keypair_seed', run(function () {
//  return sodium.crypto_sign_keypair_seed(random)
//}))

var keys = sodium.crypto_sign_keypair()
print('ed25519_pk_to_curve25519', run(function () {
  return sodium.crypto_sign_ed25519_pk_to_curve25519(keys.publicKey)
}), hashes)

print('ed25519_sk_to_curve25519', run(function () {
  return sodium.crypto_sign_ed25519_sk_to_curve25519(keys.secretKey)
}), hashes)


function encrypt_perf (msg) {
  var nonce = crypto.randomBytes(24)

  var key = crypto.randomBytes(32)
  var key2 = crypto.randomBytes(32)

  console.log('--- encrypting ' + msg.length + ' byte buffers ---')

  print('hash_sha256', hashes = run(function () {
    return sodium.crypto_hash_sha256(msg)
  }), hashes)

  print('hash', run(function () {
    return sodium.crypto_hash(msg)
  }), hashes)

  var key = crypto.randomBytes(32)

  print('auth', run(function () {
    return sodium.crypto_auth(msg, key)
  }), hashes)

  var mac = sodium.crypto_auth(msg, key)

  print('auth_verify', run(function () {
    return sodium.crypto_auth_verify(mac, msg, key)
  }), hashes)

  print('sign', run(function () {
    return sodium.crypto_sign(msg, keys.secretKey)
  }), hashes)

  var sig_box = sodium.crypto_sign(msg, keys.secretKey)

  print('sign_open', run(function () {
    return sodium.crypto_sign_open(sig_box, keys.publicKey)
  }), hashes)

  print('sign_detached', run(function () {
    return sodium.crypto_sign_detached(msg, keys.secretKey)
  }), hashes)

  var sig = sodium.crypto_sign_detached(msg, keys.secretKey)

  print('sign_verify_detached', run(function () {
    return sodium.crypto_sign_verify_detached(sig, msg, keys.publicKey)
  }), hashes)

  print('secretbox_easy', run(function () {
    return sodium.crypto_secretbox_easy(msg, nonce, key)
  }), hashes)

  var ctxt = sodium.crypto_secretbox_easy(msg, nonce, key)
  print('secretbox_open_easy', run(function () {
    return sodium.crypto_secretbox_open_easy(ctxt, nonce, key)
  }), hashes)

  print('secretbox_open_easy (fail)', run(function () {
    return sodium.crypto_secretbox_open_easy(ctxt, nonce, key2)
  }), hashes)

  var alice = sodium.crypto_box_keypair()
  var bob = sodium.crypto_box_keypair()

  print('box_easy', run(function () {
    return sodium.crypto_box_easy(msg, nonce, bob.publicKey, alice.secretKey)
  }), hashes)

  var ctxt2 = sodium.crypto_box_easy(msg, nonce, bob.publicKey, alice.secretKey)

  print('box_open_easy', run(function () {
    return sodium.crypto_box_open_easy(ctxt2, nonce, bob.publicKey, alice.secretKey)
  }), hashes)

  print('box_open_easy (fail)', run(function () {
    return sodium.crypto_box_open_easy(ctxt, nonce, bob.publicKey, alice.secretKey)
  }), hashes)

}

encrypt_perf(crypto.randomBytes(32))
encrypt_perf(crypto.randomBytes(1024))
encrypt_perf(crypto.randomBytes(1024*8))
encrypt_perf(crypto.randomBytes(1024*1024))



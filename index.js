
window = {}
crypto = window.crypto || {}

crypto.getRandomValues = function (buffer) {
  for(var i = 0; i < buffer.length; i++)
  buffer[i] = ~~(Math.random()*256)
  return buffer
}

function log () {
  var args = [].slice.call(arguments)
  //we are web worker!
  if('undefined' === typeof document) {
    postMessage(args)
  }
  else if(process.title === 'browser') {
    var pre = document.createElement('pre')
    pre.textContent = args.join(' ')
    document.body.appendChild(pre)
    console.log
  }
  console.log.apply(console, args)
}

//PSUEDORANDOM, not cryptographically random.
//this is acceptable because this isn't what we are benchmarking.
//this script just creates a lot of random numbers and firefox errors.
function randomBytes (n) {
  var b = new Buffer(n)
  for(var i = 0; i < n; i++)
    b[i] = ~~(Math.random()*256)
  return b
}

module.exports = function (sodium) {

  function run (op) {

    var start = Date.now(), i = 0, end = Date.now()

    while((end = Date.now()) < start + 1000)
      op(++i)

    return ((end-start)/1000) * i
  }

  var random = randomBytes(32)

  function pad (n) {
    var s = ''
    while(n--) s += ' '
    return s
  }

  function even (left, right, size) {
    return left + pad(size - (left.length + right.length)) + right
  }

  function round(num) {
    return ~~(num*1000)/1000
  }

  function print (name, ops, standard) {
    var rate = (standard/ops).toPrecision(3)
    log(
      even(name, ''+round(ops), 40), /e/.test(rate) ? ~~(standard/ops) : rate
    )
  }


  var key = randomBytes(32)
  sodium.crypto_auth(random, key)

  log(even('operation', 'ops/sec', 40), 'ops/ops(hash)')

  var hashes


  print('hash_sha256', hashes = run(function () {
    return sodium.crypto_hash_sha256(random)
  }), hashes)

  print('hash', run(function () {
    return sodium.crypto_hash(random)
  }), hashes)


  print('auth', run(function () {
    return sodium.crypto_auth(random, key)
  }), hashes)

  var mac = sodium.crypto_auth(random, key)

  print('verify', run(function () {
    return sodium.crypto_auth_verify(mac, random, key)
  }), hashes)

  /*
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

  */

  /*
  print('box_keypair', run(function () {
    return sodium.crypto_box_keypair()
  }), hashes)

  var alice = sodium.crypto_box_keypair()
  var bob = sodium.crypto_box_keypair()

  print('scalarmult', run(function () {
    return sodium.crypto_scalarmult(alice.secretKey, bob.publicKey)
  }), hashes)
  */

  //print('box_keypair_seed', run(function () {
  //  return sodium.crypto_box_keypair_seed(random)
  //}))

  /*
  print('sign_keypair', run(function () {
    return sodium.crypto_sign_keypair()
  }), hashes)
  */

  print('sign_seed_keypair', run(function () {
    return sodium.crypto_sign_seed_keypair(random)
  }), hashes)

  var keys = sodium.crypto_sign_seed_keypair(random)
  print('ed25519_pk_to_curve25519', run(function () {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(keys.publicKey)
  }), hashes)

  print('ed25519_sk_to_curve25519', run(function () {
    return sodium.crypto_sign_ed25519_sk_to_curve25519(keys.secretKey)
  }), hashes)


  function encrypt_perf (msg) {
    var nonce = randomBytes(24)

    var key = randomBytes(32)
    var key2 = randomBytes(32)

    console.log('--- encrypting ' + msg.length + ' byte buffers ---')

    print('hash_sha256', hashes = run(function () {
      return sodium.crypto_hash_sha256(msg)
    }), hashes)

    print('hash', run(function () {
      return sodium.crypto_hash(msg)
    }), hashes)

    var key = randomBytes(32)

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

  encrypt_perf(randomBytes(32))
  encrypt_perf(randomBytes(1024))
  encrypt_perf(randomBytes(1024*8))
  //encrypt_perf(crypto.randomBytes(1024*1024))

}

if(!module.parent) {
  module.exports(
    process.argv[2] === 'browser' || process.title === 'browser'
    ? require('chloride/browser')
    : ((require))('chloride/bindings')
  )
}

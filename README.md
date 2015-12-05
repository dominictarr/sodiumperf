# sodiumperf

compare the performance of various cryptoprimitives in [sodium](https://github.com/paixaop/node-sodium)

(by the way, using my [secretbox_easy](https://github.com/paixaop/node-sodium/pull/45)
branch)

## Method

This runs a script that runs an operation as many times as possible
within 1 second. The total operations is then output,
along with the number of operations/second compared to a sha256 hash.
(i.e, how many sha256 hashes you could have done in the time to perform
one operation)

first asymmetric primitives are tested, and then encryption/decryption
is tested for inputs of increasing size. (32, 1024, 8096, 1048576 bytes)

## Results

* [sodium bindings](./results/bindings.txt)
* [libsodium emscripten to javascript](./results/browser.txt)

note that the time to fail to decrypt a box is also measured.
(this means calculate the poly1305 one time auth, but not calculating
the keystream)


## License

MIT

# cryptonight-multi-miner (forked from wolf-xmr-miner)

BenDroid's OpenCL/CPU miner for CryptoNight and CryptoNight-lite based coins like Monero (XMR) and AEON.

The fork is based on [Wolf's](https://github.com/wolf9466) OpenCL XMR Miner for AMD GPUs and the CPU-mining integration done by [hyc](https://github.com/hyc).

## Main features:

* High performance
* CryptoNight support for coins like Monero (XMR).
* CryptoNight-Lite support for coins like AEON.
* Support for mining with AMD GPU's (OpenCL)
* Support for mining with x86/x64 CPU's with or without AES-NI
* Mining with GPU's and CPU at the same time
* Solo/Pool mining

## Donations
Donations for the work done in this fork are accepted :

```
BTC: 128qLZCaGdoWhBTfaS7rytpbvG4mNTyAQm
XMR: 46FkYo7x6LqYjLQo4Jd84UTGBybW7tsWqJaQVLPhbUSK19ajSTMY9T2Sa2LH6CfWhSingjvQARtfeM4Feekpp2yFR1wsFNT
AEON: Wmtm4S2cQ8uEBBAVjvbiaVAPv2d6gA1mAUmBmjna4VF7VixLxLRUYag5cvsym3WnuzdJ9zvhQ3Xwa8gWxPDPRfcQ3AUkYra3W
```

## Credits
wolf-multi-miner was forked from Wolf9466's wolf-xmr-miner where hyc added CPU mining.

* [Wolf9466](https://github.com/wolf9466)
* [hyc](https://github.com/hyc)



## Building

```
./make
```

## Configuration

* TBD

## Running

As with the original CPU miner, you can gain a performance boost by configuring huge pages.
Check current setting with `sysctl vm.nr_hugepages` then set it to at least 3 times the
total number of threads you're using, as root.

    sudo sysctl -w vm.nr_hugepages=num

```
./miner xmr.conf
```

## Solo mining

Use a URL of "daemon+tcp://<host>:<port>" - requires bitmonerod v0.9.3.1 or newer

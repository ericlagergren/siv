# AES-GCM-SIV

[![Go Reference](https://pkg.go.dev/badge/github.com/ericlagergren/siv.svg)](https://pkg.go.dev/github.com/ericlagergren/siv)

Nonce misuse-resistant AEAD

- https://datatracker.ietf.org/doc/html/rfc8452
- https://eprint.iacr.org/2017/168.pdf
- https://eprint.iacr.org/2015/102.pdf

## Installation

```bash
go get github.com/ericlagergren/siv@latest
```

## Performance

The performance of HCTR2 is determined by two things: AES-CTR and
POLYVAL. This module provides ARMv8 and x86-64 assembly AES-CTR
implementations and uses a hardware-accelerated POLYVAL
implementation (see [github.com/ericlagergren/polyval](https://pkg.go.dev/github.com/ericlagergren/polyval)).

The ARMv8 assembly implementation of AES-CTR-256 with
hardware-accelerated POLYVAL runs at about X cycle per byte.

The x86-64 assembly implementation of AES-CTR-256 with
hardware-accelerated POLYVAL runs at about X cycles per byte.

The `crypto/aes` implementation of AES-CTR-256 with
hardware-accelerated POLYVAL runs at about X cycles per byte.

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.

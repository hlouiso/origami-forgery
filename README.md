# A universal forgery on Origami, from the public key alone

Reproduction code for the paper *A Universal Forgery Attack on the Origami
Signature Scheme from the Public Key Alone*. Origami is candidate `sign-18` of
the NGCC round-1 public-key call.

> **Status.** Academic cryptanalysis of a submitted post-quantum signature
> candidate, disclosed under coordination with the authors and the programme.
> The code here forges signatures **only against keys you generate yourself**;
> it targets a proposal, not any deployed system.

## What it shows

Origami is a layered oil-and-vinegar (UOV/Rainbow-style) multivariate signature
over `F16`. Its stated aim is to keep the signing trapdoor secret while
publishing only a compressed description of an ordinary MQ verification map.

The published verification map is the signing map itself in a **public**
coordinate order, carrying **no secret linear transformation**. As the
submission's own security analysis states, the construction "does not
instantiate external input/output linear hiding maps `T_in` and `T_out`."
Consequently anyone holding a public key can sign any message: the forgery is
the signer's own zone-by-zone linear solve, run without the secret key, at the
cost of one verification. It succeeds on all four parameter sets, including the
official test vectors. See the paper for the argument that this is a property of
the specification, not of the implementation.

## Layout

```
src/
  forge_from_pk.c   forge a signature from a PUBLIC KEY + message only (CLI)
  verify_pk.c       thin wrapper over the shipped sig_verify + 3 negative controls
  keygen_pk.c       generate a keypair; print only the public key + a message
  forge_demo.c      batch harness: random keys, official KAT cross-check, controls
scripts/
  build.sh          build the tools against an official submission tree
  run.sh            build + run the batch forgery demonstration for one level
  blind_challenge.sh  trust-separated check: forge against a key whose seed you never see
docs/
  REPRODUCE.md      step-by-step, pinned to the official submission hash
  EXPECTED_OUTPUT.md  what a successful run looks like
```

## Requirements

- A C11 compiler (`gcc` or `clang`) and a POSIX shell.
- The **official Origami submission package** (not included here — see below).

## The Origami submission is not bundled here

This repository contains only our own attack code. The Origami reference
implementation is the designers' work under their own licence, so we do not
redistribute it. Download the official package and verify it:

```
# Origami.zip from the NGCC round-1 candidate list
sha256sum Origami.zip
# expected: e34f18832e968681dd0c51ce0d4b29d80e01ad29daa83dfb805718b76fdffa80
unzip Origami.zip
```

The tools build against the unpacked
`Implementations/Reference_Implementation` tree.

## Build and reproduce

```
export SUBMISSION=/path/to/Origami/Implementations/Reference_Implementation
./scripts/build.sh 128            # or 256, 384, 512
./scripts/run.sh 128              # random keys + KAT cross-check + negative controls
```

A successful run reports every forged signature accepted by the unmodified
verifier, every negative control rejected, and zero false accepts. The official
known-answer test key of each level is among the forged targets. See
[docs/EXPECTED_OUTPUT.md](docs/EXPECTED_OUTPUT.md).

## Trust-separated check

`scripts/blind_challenge.sh` demonstrates the core claim under separation of
roles: a keypair is generated, only the public key and a message are exposed to
the forger, the forger produces a signature from that public key alone, and the
unmodified verifier accepts it while three negative controls are rejected. See
[docs/REPRODUCE.md](docs/REPRODUCE.md#trust-separated-check).

## Licence

Our code is released under the MIT licence ([LICENSE](LICENSE)). It builds
against, but does not include, the separately licensed Origami submission.

## Citing

```bibtex
@misc{origami-forgery,
  title  = {A Universal Forgery Attack on the Origami Signature Scheme from the Public Key Alone},
  year   = {2026},
  note   = {Reproduction code: https://github.com/hlouiso/origami-forgery}
}
```

# Reproducing the forgery

## 1. Prerequisites

- A C11 compiler (`gcc` or `clang`) and a POSIX shell.
- The official Origami submission package.

## 2. Get and verify the submission

The Origami reference implementation is not included in this repository (it is
the designers' separately licensed code). Download the official `Origami.zip`
from the NGCC round-1 candidate list and check its hash:

```
sha256sum Origami.zip
# e34f18832e968681dd0c51ce0d4b29d80e01ad29daa83dfb805718b76fdffa80
unzip Origami.zip
export SUBMISSION="$PWD/Origami/Implementations/Reference_Implementation"
```

## 3. Build

```
./scripts/build.sh 128        # and/or 256, 384, 512
```

This compiles the submission's own units locally and links them with our tools
into `build/Origami-<level>/`. Nothing from the submission is written back into
the repository.

## 4. Run the demonstration

```
./scripts/run.sh 128 100 3    # 100 keys x 3 messages
```

For each fresh keypair and message the forger builds a signature **from the
public key alone** and hands it to the unmodified `sig_verify`. Every forgery is
accepted, every negative control is rejected, and the official known-answer test
key of the level is among the forged targets. See
[EXPECTED_OUTPUT.md](EXPECTED_OUTPUT.md).

Forgery cost is about that of one verification: roughly `0.01 s` at Origami-128,
a few seconds at Origami-512 (dominated by re-deriving the public coefficient
stream, not by the linear algebra).

## Trust-separated check

`scripts/blind_challenge.sh <level>` makes the "public key only" property
explicit: a keypair is generated with its secret written to a private file, only
the public key and a message are handed to the forger, and the forged signature
is then verified.

```
./scripts/blind_challenge.sh 128
```

For a check that does not rely on a single machine, split the roles across two
independent parties:

1. Party A runs `keygen_pk secret.private 56`, keeps `secret.private`, and sends
   Party B only the printed `PK=` and `MSG=` lines.
2. Party B runs `forge_from_pk <PK> <MSG>` and returns the printed signature.
3. Party A runs `verify_pk <PK> <SIG> <MSG> <MSG2>`.

Party B never receives the seed or the secret key, so acceptance shows a forgery
against a key whose trapdoor the forger did not hold. As a further check, Party A
may verify with an independently built `sig_verify` (rebuilt from the official
submission sources, confirmed to reproduce the official KAT files).

## What each tool does

| tool | input | output |
|---|---|---|
| `keygen_pk` | a private-file path | prints only `PK` and `MSG`; secret goes to the private file |
| `forge_from_pk` | `PK`, `MSG` (+ optional salt) | a forged signature, from public data only |
| `verify_pk` | `PK`, `SIG`, `MSG` (+ optional 2nd message) | shipped `sig_verify` result + 3 controls |
| `forge_demo` | key count, messages per key | batch forgery + KAT cross-check + controls |

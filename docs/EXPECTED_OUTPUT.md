# Expected output

## Batch demonstration (`scripts/run.sh`)

`forge_demo` prints one summary line and one controls line per level. A
successful Origami-128 run of 100 keys x 3 messages looks like:

```
Origami  keys=100 msgs/key=3  forged_accepted=300/300  keyfail=0
  negative controls (must all reject): A_sig=300/300 B_salt=300/300 C_othermsg=300/300  [FALSE-ACCEPTS A=0 B=0 C=0]
```

- `forged_accepted=300/300` — every signature forged from the public key alone
  is accepted by the unmodified verifier.
- `A/B/C=300/300` — every negative control is rejected, so acceptance is
  specific to a valid (pk, signature, message) triple, not an always-accept
  verifier.
- `FALSE-ACCEPTS A=0 B=0 C=0` — no control was ever wrongly accepted.

The larger levels are run with fewer keys because each forgery re-derives the
public coefficient stream (seconds per forgery at Origami-512); the outcome is
the same.

## Trust-separated check (`scripts/blind_challenge.sh`)

```
published: pk (5992 hex), msg (112 hex); secret kept in a file the forger never opens
forged:    sig (232 hex) from pk + msg only
== verification (unmodified sig_verify) ==
MAIN  sig_verify(pk, forged_sig, msg) = 0  -> ACCEPTED (forgery valid)
CTRL-A flip sig byte           = -1  -> rejected (good)
CTRL-B flip salt byte          = -1  -> rejected (good)
CTRL-C other message           = -1  -> rejected (good)
```

`MAIN = 0` is acceptance; `-1` is rejection. The hex lengths above are for
Origami-128 (public key 2996 bytes, signature 116 bytes); they scale with the
level.

## A note on the tail zone

The forger occasionally restarts. The last ("tail") zone is a square 8x8 system
over `F16` with no vinegar to resample, so it is singular with probability about
6.6% (the singular probability of a random 8x8 matrix over `F16`); the forger
then restarts from the first zone. Every forgery still completes. This is a
property of the parameters, discussed in the paper.

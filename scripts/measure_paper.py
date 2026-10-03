#!/usr/bin/env python3
"""Reproduce the paper's C measurements and official KAT checks.

From the repository root:
    export SUBMISSION=/path/to/Implementations/Reference_Implementation
    python3 scripts/measure_paper.py
    python3 scripts/measure_paper.py --quick       # one key/message per level
    python3 scripts/measure_paper.py --levels 128  # one level, paper sample size

Requires Python 3.10+, gcc, and the official Origami reference sources. Results are
written to measurements/run-<UTC timestamp>/ unless --out is given. The paper
sample sizes are 100x3, 15x3, 8x3 and 5x3 for 128/256/384/512 respectively.
Use --old-forger to also compare the old and corrected tail retry on a fixed input.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEVELS = (128, 256, 384, 512)
PAPER_SIZES = {128: 100, 256: 15, 384: 8, 512: 5}
UNITS = ("origami_ref", "symmetric_iccs", "auxfunc", "aes", "drng", "SIG_AlgorithmInstance")
METRIC_RE = re.compile(r"^METRICS (.+)$", re.MULTILINE)
SUMMARY_RE = re.compile(
    r"keys=(\d+) msgs/key=(\d+)\s+forged_accepted=(\d+)/(\d+)\s+keyfail=(\d+)"
)
CONTROLS_RE = re.compile(
    r"A_sig=(\d+)/(\d+) B_salt=(\d+)/(\d+) C_othermsg=(\d+)/(\d+)"
    r"\s+\[FALSE-ACCEPTS A=(\d+) B=(\d+) C=(\d+)\]"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_run(command: list[str], *, timeout: int = 1200,
                cwd: Path | None = None) -> tuple[str, float]:
    start = time.perf_counter()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, check=False, cwd=cwd)
    elapsed = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError(
            f"Commande échouée (code {result.returncode}): {command[0]}\n"
            f"{result.stdout[-4000:]}"
        )
    return result.stdout, elapsed


def build(level: int, source: Path, submission: Path, build_dir: Path,
          *, measured: bool, log: list[str]) -> Path:
    instance = submission / f"Origami-{level}"
    if not instance.is_dir():
        raise FileNotFoundError(f"Sources officielles introuvables : {instance}")
    build_dir.mkdir(parents=True, exist_ok=True)
    flags = ["gcc", "-std=c11", "-O2", f"-I{instance}", "-DORIGAMI_OPT=REF"]
    objects = []
    for unit in UNITS:
        obj = build_dir / f"{unit}.o"
        command = flags + ["-c", str(instance / f"{unit}.c"), "-o", str(obj)]
        output, _ = checked_run(command)
        log.append(" ".join(command) + "\n" + output)
        objects.append(str(obj))
    exe = build_dir / ("forge_demo_measured" if measured else "forge_demo_old")
    command = flags + (["-DORIGAMI_MEASURE"] if measured else [])
    command += [str(source), *objects, "-o", str(exe)]
    output, _ = checked_run(command)
    log.append(" ".join(command) + "\n" + output)
    return exe


def build_kat(level: int, submission: Path, build_dir: Path,
              log: list[str]) -> Path:
    instance = submission / f"Origami-{level}"
    obj = build_dir / "KAT_SIG.o"
    flags = ["gcc", "-std=c11", "-O2", f"-I{instance}",
             "-DORIGAMI_OPT=REF", "-DKAT_NUM_TESTS=1"]
    command = flags + ["-c", str(instance / "KAT_SIG.c"), "-o", str(obj)]
    output, _ = checked_run(command)
    log.append(" ".join(command) + "\n" + output)
    objects = [str(build_dir / f"{unit}.o") for unit in UNITS]
    exe = build_dir / "KAT_SIG"
    command = flags + [str(obj), *objects, "-o", str(exe)]
    output, _ = checked_run(command)
    log.append(" ".join(command) + "\n" + output)
    return exe


def build_old(level: int, source: Path, submission: Path, build_dir: Path,
              log: list[str]) -> Path:
    instance = submission / f"Origami-{level}"
    objects = [str(build_dir / f"{unit}.o") for unit in UNITS]
    exe = build_dir / "forge_demo_old"
    command = ["gcc", "-std=c11", "-O2", f"-I{instance}", "-DORIGAMI_OPT=REF",
               str(source), *objects, "-o", str(exe)]
    output, _ = checked_run(command)
    log.append(" ".join(command) + "\n" + output)
    return exe


def kat_row(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line.strip() and fields:
            break
        if " = " in line:
            key, value = line.split(" = ", 1)
            fields[key] = value.strip()
    for key in ("SK", "M", "Sn", "PK"):
        value = fields.get(key, "")
        if not value or len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            raise ValueError(f"Champ KAT {key} absent ou invalide dans {path}")
        length = fields.get(f"{key}_Len")
        if length is not None and len(value) != 2 * int(length):
            raise ValueError(f"Longueur KAT {key} incorrecte dans {path}")
    return fields


def metrics(output: str) -> dict[str, int | float]:
    match = METRIC_RE.search(output)
    if not match:
        raise ValueError("L'instrumentation METRICS est absente de la sortie")
    result: dict[str, int | float] = {}
    for item in match.group(1).split():
        key, value = item.split("=", 1)
        result[key] = float(value) if key.endswith("_s") else int(value)
    return result


def batch_result(output: str, keys: int, msgs: int) -> dict:
    summary = SUMMARY_RE.search(output)
    controls = CONTROLS_RE.search(output)
    if not summary or not controls:
        raise ValueError(f"Sortie du lot inattendue :\n{output[-4000:]}")
    k, m, accepted, total, keyfail = map(int, summary.groups())
    a, aden, b, bden, c, cden, bad_a, bad_b, bad_c = map(int, controls.groups())
    if (k, m, accepted, total, keyfail) != (keys, msgs, keys * msgs, keys * msgs, 0):
        raise ValueError(f"Succès du lot incomplet : {summary.group(0)}")
    if (a, aden, b, bden, c, cden, bad_a, bad_b, bad_c) != (
        total, total, total, total, total, total, 0, 0, 0
    ):
        raise ValueError(f"Contrôles négatifs incorrects : {controls.group(0)}")
    perf = metrics(output)
    if perf["calls"] != total or perf["outer_passes"] != (
        perf["calls"] + perf["tail_restarts"] + perf["main_restarts"]
    ):
        raise ValueError(f"Compteurs de relance incohérents : {perf}")
    if perf["verify_calls"] != 4 * total or perf["verify_accepted_calls"] != total:
        raise ValueError(f"Nombre de vérifications inattendu : {perf}")
    return {
        "keys": keys, "messages_per_key": msgs, "accepted": accepted, "total": total,
        "controls_rejected": {"A": a, "B": b, "C": c},
        "false_accepts": {"A": bad_a, "B": bad_b, "C": bad_c},
        **perf,
        "mean_forge_s": perf["forge_s"] / perf["calls"],
        "mean_verify_s": perf["verify_accepted_s"] / perf["verify_accepted_calls"],
        "mean_verify_all_s": perf["verify_s"] / perf["verify_calls"],
    }


def signature(output: str) -> str:
    match = re.search(r"^forged Sn = ([0-9A-F]+)$", output, re.MULTILINE)
    if not match:
        raise ValueError("Signature forgée introuvable")
    return match.group(1)


def check_kat(output: str) -> dict:
    checks = (
        "sig_verify(pk,forged_sn,m) = 0  (ACCEPTED)",
        "KAT Sn under regenerated pk = 0 (verifies",
        "forged==KAT ? NO (a new signature)",
        "KAT pk matches regenerated pk = YES",
    )
    if not all(check in output for check in checks):
        raise ValueError(f"Vérification KAT incomplète :\n{output[-4000:]}")
    return {"accepted": True, "original_signature_verified": True,
            "different_signature": True, "public_key_matches": True,
            "metrics": metrics(output)}


def find_tail_witness(exe: Path, seed_bytes: int, output_dir: Path) -> tuple[str, str, str, float, dict]:
    # Deterministic public test inputs make the old/new comparison reproducible.
    for index in range(1000):
        seed = hashlib.shake_256(f"origami-tail-seed-{index}".encode()).digest(seed_bytes).hex().upper()
        msg = hashlib.shake_256(f"origami-tail-msg-{index}".encode()).digest(56).hex().upper()
        output, wall = checked_run([str(exe), "--one", seed, msg], timeout=120)
        data = metrics(output)
        if data["tail_restarts"]:
            (output_dir / "tail_corrected.txt").write_text(output)
            return seed, msg, signature(output), wall, data
    raise RuntimeError("Aucun redémarrage de queue observé après 1000 entrées fixes")


def cpu_model() -> str:
    path = Path("/proc/cpuinfo")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--levels", nargs="+", type=int, choices=LEVELS, default=list(LEVELS))
    parser.add_argument("--quick", action="store_true", help="1 clé et 1 message par niveau")
    parser.add_argument("--out", type=Path, help="Répertoire de sortie")
    parser.add_argument("--submission", type=Path, default=os.environ.get("SUBMISSION"),
                        help="Reference_Implementation directory (default: SUBMISSION environment variable)")
    parser.add_argument("--vectors", type=Path,
                        help="Official Test_Vectors directory (default: ../../Test_Vectors from --submission)")
    parser.add_argument("--forger", type=Path, default=ROOT / "src/forge_demo.c")
    parser.add_argument("--old-forger", type=Path,
                        help="Earlier forge_demo.c; enables the optional fixed-input tail comparison")
    parser.add_argument("--skip-tail-check", action="store_true",
                        help="Ignorer le témoin 128 ancien/nouveau (utile pour un essai rapide)")
    args = parser.parse_args()
    if args.submission is None:
        parser.error("Indiquer --submission ou définir la variable SUBMISSION")
    submission = args.submission.resolve()
    vectors = (args.vectors or submission.parent.parent / "Test_Vectors").resolve()
    old_source = args.old_forger.resolve() if args.old_forger else None
    if old_source is not None and not old_source.is_file():
        parser.error(f"Ancienne version introuvable pour la comparaison fixe : {old_source}")
    levels = sorted(set(args.levels))
    out = args.out or ROOT / "measurements" / ("run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    out = out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error(f"Le répertoire de sortie existe déjà et n'est pas vide : {out}")
    out.mkdir(parents=True, exist_ok=True)
    source = args.forger.resolve()
    if "max_local_attempts=zn->flat_v>0?256:1" not in source.read_text():
        parser.error("Le code de falsification sélectionné n'intègre pas la correction de relance")
    report: dict = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"node": platform.node(), "cpu": cpu_model(), "platform": platform.platform()},
        "configuration": {"levels": levels, "quick": args.quick, "submission": str(submission),
                          "forger": str(source), "vectors": str(vectors)},
        "sha256": {"forger": sha256(source)},
        "levels": {},
    }
    if old_source is not None:
        report["sha256"]["old_forger"] = sha256(old_source)
    build_log: list[str] = []
    try:
        for level in levels:
            print(f"Origami-{level} : compilation, KAT, puis lot...", flush=True)
            build_dir = out / "build" / str(level)
            exe = build(level, source, submission, build_dir, measured=True, log=build_log)
            report["sha256"][f"reference_{level}"] = sha256(
                submission / f"Origami-{level}" / "origami_ref.c")
            report["sha256"][f"params_{level}"] = sha256(
                submission / f"Origami-{level}" / "origami_params.h")
            kat = kat_row(vectors / f"KAT_SIG_Origami-{level}.txt")
            report["sha256"][f"kat_{level}"] = sha256(vectors / f"KAT_SIG_Origami-{level}.txt")
            kat_exe = build_kat(level, submission, build_dir, build_log)
            kat_regen_output, kat_regen_wall = checked_run([str(kat_exe)], cwd=build_dir)
            (out / f"kat_regen_{level}.txt").write_text(kat_regen_output)
            generated_kat = build_dir / "output" / f"KAT_SIG_Origami-{level}.txt"
            if generated_kat.read_bytes() != (vectors / f"KAT_SIG_Origami-{level}.txt").read_bytes():
                raise ValueError(f"KAT officiel {level} non reproduit octet pour octet")
            kat_output, kat_wall = checked_run(
                [str(exe), "--one", kat["SK"], kat["M"], kat["Sn"], kat["PK"]])
            (out / f"kat_{level}.txt").write_text(kat_output)
            kat_data = check_kat(kat_output)
            kat_data["wall_s"] = kat_wall
            kat_data["regenerated_byte_for_byte"] = True
            kat_data["regeneration_wall_s"] = kat_regen_wall
            keys = 1 if args.quick else PAPER_SIZES[level]
            msgs = 1 if args.quick else 3
            batch_output, batch_wall = checked_run([str(exe), str(keys), str(msgs)])
            (out / f"batch_{level}.txt").write_text(batch_output)
            batch = batch_result(batch_output, keys, msgs)
            batch["wall_s"] = batch_wall
            report["levels"][str(level)] = {"kat": kat_data, "batch": batch}
            print(f"  {batch['accepted']}/{batch['total']} acceptées ; "
                  "KAT=OK ; "
                  f"A/B/C {batch['controls_rejected']} ; "
                  f"forge {batch['mean_forge_s']:.4f} s ; "
                  f"verify {batch['mean_verify_s']:.4f} s", flush=True)
        if old_source is not None and 128 in levels and not args.skip_tail_check:
            print("Origami-128 : recherche d'une queue singulière et comparaison fixe...", flush=True)
            exe = out / "build" / "128" / "forge_demo_measured"
            kat = kat_row(vectors / "KAT_SIG_Origami-128.txt")
            seed, msg, corrected_sig, corrected_wall, tail_metrics = find_tail_witness(
                exe, len(kat["SK"]) // 2, out)
            old_exe = build_old(128, old_source, submission, out / "build" / "128", build_log)
            old_output, old_wall = checked_run([str(old_exe), "--one", seed, msg], timeout=300)
            (out / "tail_old.txt").write_text(old_output)
            old_sig = signature(old_output)
            if corrected_sig != old_sig or "sig_verify(pk,forged_sn,m) = 0  (ACCEPTED)" not in old_output:
                raise ValueError("Les deux versions produisent des signatures différentes sur l'entrée fixe")
            report["tail_fixed_input"] = {
                "seed": seed, "message": msg, "tail_restarts": tail_metrics["tail_restarts"],
                "corrected_wall_s": corrected_wall, "old_wall_s": old_wall,
                "same_signature": True, "accepted_by_both": True,
            }
            print(f"  {tail_metrics['tail_restarts']} relance(s), même signature ; "
                  f"ancien {old_wall:.3f} s, corrigé {corrected_wall:.3f} s", flush=True)
        rows = []
        for level in levels:
            item = report["levels"][str(level)]
            b = item["batch"]
            rows.append({
                "level": level, "keys": b["keys"], "messages_per_key": b["messages_per_key"],
                "kat_reproduced": item["kat"]["regenerated_byte_for_byte"],
                "kat_forgery_accepted": item["kat"]["accepted"],
                "accepted": b["accepted"], "total": b["total"],
                "control_A_rejected": b["controls_rejected"]["A"],
                "control_B_rejected": b["controls_rejected"]["B"],
                "control_C_rejected": b["controls_rejected"]["C"],
                "false_accepts_A": b["false_accepts"]["A"],
                "false_accepts_B": b["false_accepts"]["B"],
                "false_accepts_C": b["false_accepts"]["C"],
                "tail_restarts": b["tail_restarts"], "main_restarts": b["main_restarts"],
                "mean_forge_s": b["mean_forge_s"], "mean_verify_s": b["mean_verify_s"],
                "mean_verify_all_s": b["mean_verify_all_s"],
                "batch_wall_s": b["wall_s"], "kat_wall_s": item["kat"]["wall_s"],
            })
        with (out / "summary.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Résultats : {out / 'summary.csv'}", flush=True)
    finally:
        (out / "build.log").write_text("\n".join(build_log))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        sys.exit(1)

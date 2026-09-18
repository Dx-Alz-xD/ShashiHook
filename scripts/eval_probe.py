"""Measure the model against contemporary threats it was never trained on."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval.modern_probe import BENIGN, MALICIOUS
from sentinel.analyzer import ThreatAnalyzer


def main() -> None:
    az = ThreatAnalyzer()
    print("=" * 96)
    print("MODERN THREAT PROBE  --  contemporary attacks absent from the 2001-2008 corpora")
    print("=" * 96)
    print(f"{'expected vector':22} {'description':34} {'P(mal)':>7} {'sev':>6} "
          f"{'band':>14} {'vector resolved':>22}")
    print("-" * 96)
    missed, by_vector = [], {}
    for want, desc, e in MALICIOUS:
        a = az.analyze(e)
        ok_intent = a.probability >= 0.5
        ok_vec = a.vector_key == want
        by_vector.setdefault(want, []).append(ok_intent)
        mark = " " if ok_intent else "X"
        vmark = "" if ok_vec else f" (want {want})"
        print(f"{mark}{want:21} {desc[:33]:34} {a.probability:7.3f} {a.severity.score:6.1f} "
              f"{a.severity.band:>14} {a.vector_key:>22}{vmark}")
        if not ok_intent:
            missed.append((want, desc, a.probability, a.severity.score))

    print("\n" + "-" * 96)
    print(f"{'benign control':22} {'description':34} {'P(mal)':>7} {'sev':>6} {'band':>14}")
    print("-" * 96)
    fps = []
    for desc, e in BENIGN:
        a = az.analyze(e)
        mark = "X" if a.probability >= 0.5 else " "
        print(f"{mark}{'benign':21} {desc[:33]:34} {a.probability:7.3f} {a.severity.score:6.1f} "
              f"{a.severity.band:>14}")
        if a.probability >= 0.5:
            fps.append((desc, a.probability))

    n_mal, n_hit = len(MALICIOUS), len(MALICIOUS) - len(missed)
    print("\n" + "=" * 96)
    print(f"Detection on modern threats: {n_hit}/{n_mal} ({n_hit/n_mal:.0%})   "
          f"False positives on modern benign mail: {len(fps)}/{len(BENIGN)}")
    print("\nPer-vector recall:")
    for v, res in sorted(by_vector.items()):
        print(f"  {v:22} {sum(res)}/{len(res)}")
    if missed:
        print("\nMISSED (P < 0.5) -- these would reach the inbox:")
        for want, desc, p, s in missed:
            print(f"  [{want}] {desc}  P={p:.3f} severity={s}")
    if fps:
        print("\nFALSE POSITIVES on legitimate mail:")
        for desc, p in fps:
            print(f"  {desc}  P={p:.3f}")


if __name__ == "__main__":
    main()

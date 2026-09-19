"""Build the entropy reference table, and record why the classifier is not used.

The audit is in sentinel/pe.py's docstring: the malware dataset's two classes
come from different collection processes, so a model trained on it separates
VirusShare from a Windows install rather than hostile from harmless. This
script therefore does NOT train a classifier. It extracts the one property that
is a fact about the bytes rather than about the collection -- entropy -- and
writes the distribution so a real file can be placed against it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, PROJECT_ROOT
from sentinel.pe import PERCENTILE_PATH

SRC = PROJECT_ROOT / "malware" / "malware.csv"
GRID = [1, 5, 10, 25, 50, 75, 90, 95, 97.5, 99, 99.5, 99.9]
FIELDS = {"max_entropy": "SectionsMaxEntropy", "mean_entropy": "SectionsMeanEntropy"}


def main() -> None:
    if not SRC.exists():
        print(f"{SRC} not found")
        return
    df = pd.read_csv(SRC, sep="|", on_bad_lines="skip")
    legit = df["legitimate"] == 1
    print(f"{len(df):,} binaries, {int(legit.sum()):,} legitimate "
          f"(the reference population)")

    out: dict = {}
    for name, col in FIELDS.items():
        v = pd.to_numeric(df[col][legit], errors="coerce").dropna().to_numpy()
        m = pd.to_numeric(df[col][~legit], errors="coerce").dropna().to_numpy()
        out[name] = {
            "legitimate": {str(p): float(np.percentile(v, p)) for p in GRID},
            "legitimate_n": int(len(v)),
            "malicious_mean": float(m.mean()),
            "legitimate_mean": float(v.mean()),
        }
        print(f"\n  {name} across {len(v):,} legitimate binaries:")
        for p in (50, 90, 95, 99, 99.9):
            print(f"    p{p:<5} {np.percentile(v, p):.3f}")
        print(f"    legitimate mean {v.mean():.2f} vs malicious mean {m.mean():.2f}")

    out["_provenance"] = (
        "Percentiles over the legitimate class of malware/malware.csv, which is "
        "a set of Windows program files. A percentile here means 'compared with "
        "ordinary Windows binaries', not 'probability of being malware'. The "
        "classifier trained on this dataset is deliberately unused: see "
        "sentinel/pe.py."
    )
    PERCENTILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PERCENTILE_PATH.write_text(json.dumps(out, indent=2))
    print(f"\n  written to {PERCENTILE_PATH}")


if __name__ == "__main__":
    main()

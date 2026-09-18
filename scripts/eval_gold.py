"""Score the weak rules and the vector model against human labels."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import EVAL_DIR


def main() -> None:
    path = EVAL_DIR / "gold_set_labelled.csv"
    if not path.exists():
        print(f"No labelled gold set at {path}.")
        print("Run scripts/build_gold_set.py, fill in `true_vector`, save as "
              "gold_set_labelled.csv.")
        return
    df = pd.read_csv(path)
    df = df[df["true_vector"].astype(str).str.strip() != ""]
    if df.empty:
        print("Gold set has no completed `true_vector` values yet.")
        return

    print(f"Scoring {len(df):,} human-labelled messages\n")
    print("Weak labelling rules vs. human ground truth:")
    print(classification_report(df["true_vector"], df["vector"], digits=4,
                                zero_division=0))
    labels = sorted(set(df["true_vector"]) | set(df["vector"]))
    cm = confusion_matrix(df["true_vector"], df["vector"], labels=labels)
    print("confusion (rows = human, cols = rules):")
    print(pd.DataFrame(cm, index=labels, columns=labels).to_string())
    print("\nPer sampling bucket:")
    for b, g in df.groupby("sample_bucket"):
        acc = (g["true_vector"] == g["vector"]).mean()
        print(f"  {b:18} n={len(g):>4}  rule accuracy {acc:.3f}")


if __name__ == "__main__":
    main()

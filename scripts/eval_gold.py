"""Score the weak rules against labels produced independently of them.

The vector model's own report says 98.8% and means "agrees with the weak rules
it was trained on". That number cannot fall, because the rule is the target.
This is the only place the rules themselves are graded.

Two sources are accepted, in order:

    eval/gold_set_labelled.csv   human labels. Gold, and what to trust.
    eval/gold_set_silver.csv     two models labelling independently, keeping
                                 only what they agreed on. Silver.

Silver is not gold. Two models can be wrong in the same direction, and the
output says so on every run. What silver is good for is scale and triage: it
grades every message at once, and the messages the two models disagreed about
are precisely the ones worth a person's afternoon.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import EVAL_DIR


def load() -> tuple[pd.DataFrame, str]:
    """Human labels if they exist, otherwise the model-agreed silver set."""
    human = EVAL_DIR / "gold_set_labelled.csv"
    if human.exists():
        df = pd.read_csv(human)
        df = df[df["true_vector"].astype(str).str.strip() != ""]
        if not df.empty:
            return df, "human"
    silver = EVAL_DIR / "gold_set_silver.csv"
    if silver.exists():
        df = pd.read_csv(silver)
        df = df[df.get("agree", False) == True]          # noqa: E712
        df = df[df["silver_vector"].astype(str).str.strip() != ""]
        if not df.empty:
            df = df.assign(true_vector=df["silver_vector"])
            return df, "silver"
    return pd.DataFrame(), ""


def main() -> None:
    df, kind = load()
    if df.empty:
        print("No labels yet. Either:")
        print("  scripts/build_gold_set.py, fill in `true_vector`, save as "
              "eval/gold_set_labelled.csv   (gold)")
        print("  scripts/label_gold_set.py                                  "
              "            (silver)")
        return

    if kind == "silver":
        full = pd.read_csv(EVAL_DIR / "gold_set_silver.csv")
        answered = full[(full.a_vector.notna()) & (full.b_vector.notna())]
        print("=" * 66)
        print("SILVER LABELS — two models agreeing, not human ground truth")
        print("=" * 66)
        print(f"  {len(df):,} of {len(answered):,} messages where both models "
              f"chose the same category ({len(df)/max(len(answered),1):.1%})")
        print(f"  the other {len(answered)-len(df):,} are the ones a human "
              f"should label; they are in the same file with agree=False\n")
    else:
        print(f"Scoring {len(df):,} human-labelled messages\n")

    print(f"Weak labelling rules vs. {kind} labels:")
    print(classification_report(df["true_vector"], df["vector"], digits=4,
                                zero_division=0))
    labels = sorted(set(df["true_vector"]) | set(df["vector"]))
    cm = confusion_matrix(df["true_vector"], df["vector"], labels=labels)
    print(f"confusion (rows = {kind} label, cols = rules):")
    print(pd.DataFrame(cm, index=labels, columns=labels).to_string())
    print("\nPer sampling bucket:")
    for b, g in df.groupby("sample_bucket"):
        acc = (g["true_vector"] == g["vector"]).mean()
        print(f"  {b:18} n={len(g):>4}  rule accuracy {acc:.3f}")


if __name__ == "__main__":
    main()

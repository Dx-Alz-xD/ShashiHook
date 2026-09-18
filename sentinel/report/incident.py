"""Incident report generation -- the artefact a SOC actually consumes.

Two renderings of one analysis: JSON for a SIEM or case-management system, and
Markdown for a human. Both are produced from the same Analysis object, so the
ticket a person reads and the record a machine ingests cannot disagree.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..analyzer import Analysis
from ..config import W_EXPLOIT, W_IMPACT, W_TARGET

BAND_ACTION = {
    "CRITICAL": "Contain now. Purge from all mailboxes, block the indicators and "
                "open a P1 incident before further analysis.",
    "HIGH": "Contain within the hour. Purge, block indicators, and check whether "
            "anyone interacted with the message.",
    "MEDIUM": "Queue for analyst review this shift. Quarantine pending a decision.",
    "LOW": "Quarantine. No active response needed unless a user reports interaction.",
    "INFORMATIONAL": "Filter to junk. No incident.",
}


def _ioc_block(analysis: Analysis) -> list[str]:
    lines: list[str] = []
    for kind, values in analysis.iocs().items():
        for v in values:
            if v:
                lines.append(f"| {kind} | `{v}` |")
    return lines


def to_dict(analysis: Analysis) -> dict:
    ev, sev, b = analysis.evidence, analysis.severity, analysis.explanation
    return {
        "schema": "sentinel.incident.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "message": {
            "id": analysis.email.message_id or analysis.email.uid,
            "subject": analysis.email.subject,
            "sender": analysis.email.sender,
            "recipient": analysis.email.receiver,
            "date": analysis.email.date,
        },
        "verdict": {
            "label": analysis.verdict,
            "probability_malicious": round(analysis.probability, 6),
            "severity_score": sev.score,
            "severity_band": sev.band,
            "recommended_posture": BAND_ACTION[sev.band],
            "decided_by": analysis.decided_by,
            "model_probability": round(analysis.model_probability, 6),
            "prior_adjusted_probability": round(analysis.prior_adjusted, 6),
            "deterministic_floors": [
                {"rule": f.name, "minimum_confidence": f.minimum, "reason": f.why,
                 "binding": f in analysis.floors_binding}
                for f in analysis.floors_fired],
        },
        "attack_vector": {
            "key": analysis.vector_key,
            "name": analysis.vector.name,
            "description": analysis.vector.description,
            "confidence": round(analysis.vector_confidence, 4),
            "resolved_by": analysis.vector_source,
            "mitre_attack": list(analysis.vector.mitre),
            "kill_chain_phase": analysis.vector.kill_chain,
        },
        "severity_breakdown": {
            "formula": f"100 x intent x ({W_IMPACT} x impact + {W_EXPLOIT} x "
                       f"exploitability + {W_TARGET} x targeting) + escalators",
            "substituted": sev.arithmetic(),
            "intent": sev.intent,
            "intent_source": ("deterministic_floor" if analysis.floors_binding else "model"),
            "impact": sev.impact,
            "exploitability": sev.exploitability,
            "targeting": sev.targeting,
            "base_score": sev.base_score,
            "exploitability_signals": [
                {"signal": c.name, "weight": c.value, "reason": c.why} for c in sev.exploit_parts],
            "targeting_signals": [
                {"signal": c.name, "weight": c.value, "reason": c.why} for c in sev.target_parts],
            "escalators": [
                {"name": c.name, "points": c.value, "reason": c.why} for c in sev.escalators],
        },
        "model_attribution": {
            "structural_logit": round(b.structural_logit, 4),
            "wording_logit": round(b.wording_logit, 4),
            "blend_weights": {k: round(v, 4) for k, v in b.blend.items()},
            "share_of_verdict": {"structural": round(b.share["structural"], 4),
                                 "wording": round(b.share["wording"], 4)},
            "shap_additivity_error": float(f"{b.additivity_error():.3e}"),
            "shap_base_value": round(b.structural_base, 4),
        },
        "why_flagged": {
            "raising": [
                {"feature": f.feature, "claim": f.headline, "detail": f.detail,
                 "shap_log_odds": round(f.contribution, 4), "evidence": f.quotes,
                 "kind": f.kind}
                for f in analysis.findings_up],
            "lowering": [
                {"feature": f.feature, "claim": f.headline, "detail": f.detail,
                 "shap_log_odds": round(f.contribution, 4), "evidence": f.quotes,
                 "kind": f.kind}
                for f in analysis.findings_down],
            "wording_signal": analysis.wording_summary,
            "top_tokens": [{"token": t.token, "log_odds": round(t.weight, 4)}
                           for t in b.top_tokens_up[:10]],
            "counterfactuals": analysis.counterfactuals,
        },
        "rules_fired": [
            {"rule": v.lf, "votes_for": v.vector, "weight": v.weight, "reason": v.why}
            for v in analysis.rule_votes],
        "indicators": analysis.iocs(),
        "sender_analysis": {
            "display_name": ev.sender.display_name,
            "address": ev.sender.address,
            "registrable_domain": ev.sender.registrable,
            "claimed_brand": ev.sender.claimed_brand,
            "brand_mismatch": ev.sender.brand_mismatch,
            "lookalike_of": ev.sender.lookalike_of,
            "is_freemail": ev.sender.is_freemail,
            "notes": ev.sender.notes,
            "mailbox_history": analysis.history_note,
            "domain_age": analysis.domain_age_note,
            "reply_to": analysis.email.reply_to,
            "return_path": analysis.email.return_path,
            "authentication_results": analysis.email.auth_results,
        },
        "link_analysis": [
            {"url": u.raw, "host": u.host, "registrable_domain": u.registrable,
             "anchor_text": u.anchor_text, "flags": u.flags} for u in ev.urls],
        "response_plan": list(analysis.vector.default_actions),
    }


def to_markdown(analysis: Analysis) -> str:
    ev, sev, b = analysis.evidence, analysis.severity, analysis.explanation
    L: list[str] = []
    A = L.append

    A(f"# Incident report — {sev.band} ({sev.score}/100)")
    A("")
    A(f"**Verdict:** {analysis.verdict}  ·  "
      f"**Confidence this is hostile:** {analysis.probability:.1%}  ·  "
      f"**Attack vector:** {analysis.vector.name}")
    A("")
    A(f"> {BAND_ACTION[sev.band]}")
    A("")

    A("## Message")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Subject | {analysis.email.subject or '_(none)_'} |")
    A(f"| From | `{analysis.email.sender or '(no sender header)'}` |")
    A(f"| To | `{analysis.email.receiver or '(not recorded)'}` |")
    A(f"| Date | {analysis.email.date or '_(none)_'} |")
    A(f"| Message ID | `{analysis.email.message_id or analysis.email.uid}` |")
    A("")

    if analysis.floors_binding:
        A("## Detected by rule, not by the model")
        A("")
        A(f"The intent model scored this message at "
          f"**{analysis.model_probability:.1%}**. Deterministic detections raised "
          f"confidence to **{analysis.probability:.1%}** because the following "
          f"conditions are unambiguous regardless of what the model learned:")
        A("")
        for f in analysis.floors_binding:
            A(f"- **`{f.name}`** (floor {f.minimum:.0%}) — {f.why}")
        A("")
        A("> This matters for triage: the model is trained on 2001-2008 corpora "
          "and is measurably blind to business email compromise and modern "
          "malware containers. Where a floor fires, trust the rule.")
        A("")
    elif analysis.floors_fired:
        A("_Deterministic detections also matched but did not change the verdict: "
          + ", ".join(f"`{f.name}`" for f in analysis.floors_fired) + "._")
        A("")
    A("## Why it was scored this way")
    A("")
    A(f"Severity is not a model output — it is computed by a published rubric so "
      f"that every point is traceable:")
    A("")
    A("```")
    A(f"100 x intent x ({W_IMPACT} x impact + {W_EXPLOIT} x exploitability + "
      f"{W_TARGET} x targeting) + escalators")
    A(f"{sev.arithmetic()}")
    A("```")
    A("")
    A("| Term | Value | Where it comes from |")
    A("|---|---|---|")
    intent_src = (f"raised to a deterministic floor (`{analysis.floors_binding[0].name}`); "
                  f"the model itself scored {analysis.model_probability:.1%}"
                  if analysis.floors_binding
                  else "calibrated P(malicious) from the intent model")
    A(f"| intent | {sev.intent:.3f} | {intent_src} |")
    A(f"| impact | {sev.impact:.2f} | taxonomy weight for *{analysis.vector.name}*"
      + (f", adjusted x{sev.recipient_multiplier:.2f} for this recipient"
         if sev.recipient_multiplier != 1.0 else "") + " |")
    A(f"| exploitability | {sev.exploitability:.2f} | {len(sev.exploit_parts)} signal(s), listed below |")
    A(f"| targeting | {sev.targeting:.2f} | {len(sev.target_parts)} signal(s), listed below |")
    A("")
    if sev.recipient_reason:
        A(f"**Recipient exposure** — {sev.recipient_reason}")
        A("")
    if sev.exploit_parts:
        A("**Exploitability — how directly this can be acted on:**")
        A("")
        for c in sev.exploit_parts:
            A(f"- `+{c.value:.2f}` {c.why}")
        A("")
    if sev.target_parts:
        A("**Targeting — how specifically aimed it is:**")
        A("")
        for c in sev.target_parts:
            A(f"- `+{c.value:.2f}` {c.why}")
        A("")
    if sev.escalators:
        A("**Escalators:**")
        A("")
        for c in sev.escalators:
            A(f"- `+{c.value:.0f}` **{c.name}** — {c.why}")
        A("")

    A("## Why it was flagged")
    A("")
    A(f"The verdict combines two independent views. Structural evidence "
      f"contributed {b.share['structural']:.0%} of the pull and wording "
      f"{b.share['wording']:.0%} "
      f"(structural log-odds {b.structural_logit:+.2f}, wording {b.wording_logit:+.2f}; "
      f"blend weights {b.blend['structural']:.3f} / {b.blend['wording']:.3f}).")
    A("")
    A("### Evidence that raised the score")
    A("")
    A("SHAP contributions are exact Shapley values over the structural model, in "
      "log-odds. They sum with the base value to reproduce that model's output "
      f"(reconstruction error {b.additivity_error():.1e}).")
    A("")
    A("Signals marked *indicator* name a concrete property you can hunt or block "
      "on. Signals marked *statistical* are real contributors the model learned, "
      "but they describe the shape of the text rather than anything actionable.")
    A("")
    for f in analysis.findings_up:
        A(f"- **{f.headline}** `{f.contribution:+.3f}` *({f.kind})*  \n  {f.detail}")
        for q in f.quotes:
            A(f'  > "{q}"')
    A("")
    if analysis.findings_down:
        A("### Evidence that argued against")
        A("")
        for f in analysis.findings_down:
            A(f"- **{f.headline}** `{f.contribution:+.3f}` *({f.kind})*  \n  {f.detail}")
        A("")
    A(f"### Wording")
    A("")
    A(analysis.wording_summary)
    A("")
    if analysis.counterfactuals:
        A("### What would change the verdict")
        A("")
        for s in analysis.counterfactuals:
            A(f"- {s}")
        A("")

    if analysis.rule_votes:
        A("### Detection rules that fired")
        A("")
        A("| Rule | Votes for | Weight | Reason |")
        A("|---|---|---|---|")
        for v in analysis.rule_votes:
            A(f"| `{v.lf}` | {v.vector} | {v.weight} | {v.why} |")
        A("")

    A("## Attack vector")
    A("")
    A(f"**{analysis.vector.name}** — confidence {analysis.vector_confidence:.0%}, "
      f"resolved by {analysis.vector_source}.")
    A("")
    A(analysis.vector.description)
    A("")
    if analysis.vector.mitre:
        A(f"**MITRE ATT&CK:** {', '.join(analysis.vector.mitre)}  ·  "
          f"**Kill-chain phase:** {analysis.vector.kill_chain}")
        A("")

    A("## Indicators")
    A("")
    ioc_lines = _ioc_block(analysis)
    if ioc_lines:
        A("| Type | Indicator |")
        A("|---|---|")
        L.extend(ioc_lines)
    else:
        A("_No extractable indicators._")
    A("")

    if (ev.sender.notes or analysis.email.reply_to or analysis.email.auth_results
            or analysis.history_note or analysis.domain_age_note):
        A("### Sender")
        A("")
        for n in ev.sender.notes:
            A(f"- {n}")
        if analysis.domain_age_note:
            A(f"- Domain age: {analysis.domain_age_note}")
        if analysis.history_note:
            A(f"- Mailbox history: {analysis.history_note}")
        if analysis.email.reply_to:
            A(f"- Reply-To: `{analysis.email.reply_to}`")
        if analysis.email.return_path:
            A(f"- Return-Path: `{analysis.email.return_path}`")
        if analysis.email.auth_results:
            A(f"- Authentication-Results: `{analysis.email.auth_results}`")
        A("")
    if ev.urls:
        A("### Links")
        A("")
        for u in ev.urls[:12]:
            A(f"- `{u.raw[:140]}`")
            for fl in u.flags:
                A(f"  - {fl}")
        A("")

    A("## Response plan")
    A("")
    if analysis.vector.default_actions:
        for i, step in enumerate(analysis.vector.default_actions, 1):
            A(f"{i}. {step}")
    else:
        A("No response actions required for this vector.")
    A("")
    A("---")
    A("")
    A("_Generated by Sentinel. Severity is rubric-derived, not learned; "
      "attributions are exact TreeSHAP over the structural model and exact "
      "linear contributions over the wording model._")
    return "\n".join(L)


def to_json(analysis: Analysis, indent: int = 2) -> str:
    return json.dumps(to_dict(analysis), indent=indent, ensure_ascii=False)

"""Attack-vector taxonomy, MITRE ATT&CK mapping, and per-vector impact weights.

Impact weight answers one question only: assuming this email succeeds, how bad
is the outcome for the organisation? It is an business-impact judgement, not a
model output, so it is declared here in the open and cited in every report.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Vector:
    key: str
    name: str
    description: str
    impact: float               # 0..1, business damage if the lure succeeds
    mitre: tuple[str, ...]      # ATT&CK technique IDs
    kill_chain: str             # Lockheed Martin phase this email represents
    default_actions: tuple[str, ...] = field(default=())


TAXONOMY: dict[str, Vector] = {
    "bec_payment_fraud": Vector(
        key="bec_payment_fraud",
        name="Business Email Compromise / payment fraud",
        description=(
            "Impersonates an executive, supplier or internal finance contact to "
            "redirect a payment, payroll deposit or gift-card purchase. Usually "
            "carries no link or attachment, which defeats URL and sandbox controls."
        ),
        impact=1.00,
        mitre=("T1566.002", "T1534", "T1656"),
        kill_chain="delivery",
        default_actions=(
            "Freeze any outbound payment referencing this thread and confirm the "
            "request by a phone number already on file — never one from the email.",
            "Search the mail estate for other messages from the same sender or "
            "reply-to address in the last 30 days.",
            "Check whether the spoofed executive's real mailbox shows a new "
            "forwarding rule or unfamiliar sign-in.",
        ),
    ),
    "vendor_invoice_fraud": Vector(
        key="vendor_invoice_fraud",
        name="Vendor / invoice fraud",
        description=(
            "Poses as a known supplier announcing changed bank details, or attaches "
            "a fraudulent invoice. Often follows a genuine compromise of the "
            "supplier's own mailbox, so the sending domain can be legitimate."
        ),
        impact=0.92,
        mitre=("T1566.001", "T1656"),
        kill_chain="delivery",
        default_actions=(
            "Verify the bank-detail change out-of-band with the supplier's known "
            "accounts-payable contact before any transfer.",
            "Pull the last 90 days of invoices from this supplier and compare "
            "remittance accounts.",
        ),
    ),
    "malware_delivery": Vector(
        key="malware_delivery",
        name="Malware delivery",
        description=(
            "Carries or links to an executable payload, macro-enabled document, "
            "password-protected archive, ISO/LNK container or script dropper."
        ),
        impact=0.95,
        mitre=("T1566.001", "T1204.002", "T1027"),
        kill_chain="weaponization",
        default_actions=(
            "Detonate the attachment in a sandbox and extract hashes, C2 domains "
            "and dropped-file paths.",
            "Block the file hash at the endpoint and the delivery domain at the "
            "proxy before releasing any quarantine.",
            "Hunt for execution of the payload on any host whose user received it.",
        ),
    ),
    "credential_phishing": Vector(
        key="credential_phishing",
        name="Credential phishing",
        description=(
            "Drives the recipient to a counterfeit sign-in page to harvest "
            "usernames, passwords and increasingly MFA codes via reverse proxy."
        ),
        impact=0.85,
        mitre=("T1566.002", "T1056.003", "T1111"),
        kill_chain="delivery",
        default_actions=(
            "Block the landing domain and every URL in the message at the proxy "
            "and DNS layer.",
            "Identify recipients who clicked; force password reset and revoke "
            "active sessions and refresh tokens for those accounts.",
            "Review sign-in logs for those users for impossible-travel or new-device "
            "authentications since delivery.",
        ),
    ),
    "extortion": Vector(
        key="extortion",
        name="Extortion / sextortion",
        description=(
            "Claims compromising material or a prior breach and demands "
            "cryptocurrency. Almost always a bluff sent in bulk, but corrosive to "
            "staff and occasionally backed by a real credential-dump reference."
        ),
        impact=0.55,
        mitre=("T1657",),
        kill_chain="actions-on-objectives",
        default_actions=(
            "Reassure the recipient; confirm no payment was made.",
            "If the message quotes a real password, treat it as a breach-corpus hit "
            "and force a reset wherever that password was reused.",
        ),
    ),
    "advance_fee_fraud": Vector(
        key="advance_fee_fraud",
        name="Advance-fee fraud (419)",
        description=(
            "Long-form narrative promising an inheritance, lottery win, contract "
            "windfall or fund transfer that requires an up-front fee or bank details."
        ),
        impact=0.45,
        mitre=("T1566.002",),
        kill_chain="delivery",
        default_actions=(
            "Quarantine and report to the mail provider; no host-side action needed.",
        ),
    ),
    "recon_probe": Vector(
        key="recon_probe",
        name="Reconnaissance probe",
        description=(
            "Contentless opener — 'Are you available?', a blank read-receipt bait, "
            "or a tracking pixel — used to confirm a live mailbox and a responsive "
            "human before the real lure is sent."
        ),
        impact=0.40,
        mitre=("T1598", "T1597"),
        kill_chain="reconnaissance",
        default_actions=(
            "Do not reply. Watch the sender and the recipient for a follow-up "
            "message within 72 hours — that is where the payload arrives.",
        ),
    ),
    "callback_phishing": Vector(
        key="callback_phishing",
        name="Callback phishing (TOAD)",
        description=(
            "A billing or renewal pretext with no link and no attachment -- only "
            "a phone number. The victim calls, and the attacker talks them into "
            "installing remote-access software or making a bank transfer. Every "
            "URL and sandbox control is bypassed because there is nothing to scan."
        ),
        impact=0.85,
        mitre=("T1566", "T1598.004", "T1219"),
        kill_chain="delivery",
        default_actions=(
            "Do not call the number. Confirm any subscription directly in the "
            "vendor's own app or website.",
            "Block the number and the sending domain; search the mail estate for "
            "other messages carrying the same number.",
            "If anyone called, treat the endpoint as compromised: hunt for "
            "AnyDesk, TeamViewer, UltraViewer or ScreenConnect installs and "
            "review bank activity.",
        ),
    ),
    "tech_support_scam": Vector(
        key="tech_support_scam",
        name="Tech-support scam",
        description=(
            "Claims the device is infected or a security licence has lapsed, and "
            "steers the victim to a phone number or remote-access tool."
        ),
        impact=0.75,
        mitre=("T1566", "T1219"),
        kill_chain="delivery",
        default_actions=(
            "Do not call or install anything. Legitimate vendors never warn you "
            "by email that your machine is infected.",
            "If remote access was granted, isolate the host and reset every "
            "credential entered while it was connected.",
        ),
    ),
    "investment_fraud": Vector(
        key="investment_fraud",
        name="Investment / crypto fraud",
        description=(
            "Promises guaranteed or outsized returns, often via a fake trading "
            "platform that shows fabricated gains and then demands a fee before "
            "withdrawal. Includes long-con 'pig butchering' approaches."
        ),
        impact=0.70,
        mitre=("T1566.002", "T1657"),
        kill_chain="delivery",
        default_actions=(
            "Do not deposit. A platform that requires a fee before releasing "
            "your own funds is fraudulent by definition.",
            "If money was sent, report to the bank immediately -- recovery "
            "windows are measured in hours.",
        ),
    ),
    "job_scam": Vector(
        key="job_scam",
        name="Employment / task scam",
        description=(
            "A fake job or paid-task offer used to collect identity documents, "
            "charge up-front fees, or recruit the victim as a money mule. Often "
            "moves the conversation to WhatsApp or Telegram immediately."
        ),
        impact=0.60,
        mitre=("T1566.002", "T1598"),
        kill_chain="delivery",
        default_actions=(
            "No legitimate employer charges a registration, training or security "
            "fee, and none needs bank details before an offer letter.",
            "If documents were sent, treat it as identity exposure and monitor "
            "for credit applications.",
        ),
    ),
    "government_impersonation": Vector(
        key="government_impersonation",
        name="Government / tax impersonation",
        description=(
            "Impersonates a tax authority, immigration office or court to extract "
            "payment or identity documents, usually with a threat of arrest, "
            "penalty or deportation."
        ),
        impact=0.65,
        mitre=("T1566.002", "T1656"),
        kill_chain="delivery",
        default_actions=(
            "Tax and immigration authorities do not demand payment by email, "
            "gift card or crypto. Verify via the official portal, never a link "
            "in the message.",
        ),
    ),
    "delivery_scam": Vector(
        key="delivery_scam",
        name="Parcel / delivery scam",
        description=(
            "Claims a package is held pending a small customs or redelivery fee. "
            "The fee is trivial by design -- the goal is the card details entered "
            "to pay it."
        ),
        impact=0.50,
        mitre=("T1566.002",),
        kill_chain="delivery",
        default_actions=(
            "Track the parcel from the courier's own site using the original "
            "order reference, never a link in the message.",
            "If card details were entered, cancel the card -- these feed directly "
            "into subscription-fraud rings.",
        ),
    ),
    "romance_fraud": Vector(
        key="romance_fraud",
        name="Romance fraud",
        description=(
            "Builds an emotional relationship over weeks before introducing a "
            "financial emergency or an investment opportunity. Losses per victim "
            "are among the highest of any scam type."
        ),
        impact=0.60,
        mitre=("T1566.003", "T1585"),
        kill_chain="reconnaissance",
        default_actions=(
            "Do not send money or intimate images to someone never met in person.",
            "Reverse-image-search the profile photographs; they are almost always "
            "stolen.",
        ),
    ),
    "charity_fraud": Vector(
        key="charity_fraud",
        name="Charity fraud",
        description=(
            "Solicits donations for a disaster, medical appeal or cause that "
            "either does not exist or will never receive the money. Spikes within "
            "days of any major news event."
        ),
        impact=0.40,
        mitre=("T1566.002",),
        kill_chain="delivery",
        default_actions=(
            "Donate through the charity's own website, found independently, "
            "never through a link or a phone number in an unsolicited message.",
        ),
    ),
    "spam_unwanted": Vector(
        key="spam_unwanted",
        name="Spam / unwanted bulk mail",
        description=(
            "Unsolicited commercial mail: pharmacy, counterfeit goods, adult, SEO "
            "and stock-pump content. A nuisance and a policy matter, not an intrusion."
        ),
        impact=0.15,
        mitre=(),
        kill_chain="delivery",
        default_actions=("Quarantine; no incident response required.",),
    ),
    "malicious_unclassified": Vector(
        key="malicious_unclassified",
        name="Malicious, vector unresolved",
        description=(
            "The intent model is confident the message is hostile, but no vector "
            "rule or the vector classifier reached the confidence floor. Treated as "
            "credential phishing for containment because that is the commonest "
            "unresolved case, and flagged for analyst review."
        ),
        impact=0.70,
        mitre=("T1566",),
        kill_chain="delivery",
        default_actions=(
            "Manual analyst triage required — the vector could not be resolved "
            "automatically.",
        ),
    ),
    "benign": Vector(
        key="benign",
        name="Benign",
        description="No hostile intent detected.",
        impact=0.00,
        mitre=(),
        kill_chain="none",
        default_actions=(),
    ),
}

MALICIOUS_VECTORS = tuple(k for k in TAXONOMY if k != "benign")
VECTOR_KEYS = tuple(TAXONOMY.keys())
VECTOR_INDEX = {k: i for i, k in enumerate(VECTOR_KEYS)}


def impact_of(vector_key: str) -> float:
    return TAXONOMY[vector_key].impact if vector_key in TAXONOMY else 0.70


def describe(vector_key: str) -> Vector:
    return TAXONOMY.get(vector_key, TAXONOMY["malicious_unclassified"])

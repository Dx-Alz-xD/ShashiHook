"""A hand-written probe set of contemporary email threats and modern benign mail.

The six training corpora date from 2001-2008. This set exists to measure what
that vintage costs on the traffic a SOC actually sees today: BEC, gift-card
fraud, MFA fatigue, QR-code phishing, thread hijacking, vendor bank-change
fraud and modern malware containers -- none of which are meaningfully present
in the training data.

It is small and hand-built, so it measures a blind spot rather than certifying
accuracy. Every message here was written for this test; none is real mail.
"""
from __future__ import annotations

from sentinel.features.extractor import Email

MALICIOUS: list[tuple[str, str, Email]] = [
    ("bec_payment_fraud", "gift card request from spoofed CEO", Email(
        subject="Are you available?",
        sender='"Mark Hale" <markhale.ceo@gmail.com>', receiver="alex.chen@acme.com",
        date="Mon, 8 Sep 2025 09:12:00 +0000",
        body="Alex,\n\nI am in back-to-back meetings and cannot take calls. I need you to "
             "get some gift cards for a client appreciation gift. Let me know how quickly "
             "you can get this done and I will reimburse you.\n\nSent from my iPhone")),
    ("bec_payment_fraud", "payroll diversion", Email(
        subject="Direct deposit update",
        sender='"Dana Whitfield" <d.whitfield@acme-hr.co>', receiver="payroll@acme.com",
        date="Tue, 9 Sep 2025 07:40:00 +0000",
        body="Hello,\n\nI recently changed banks. Could you please update my direct deposit "
             "details before the next payroll run? I can provide the new routing number and "
             "account number. Please confirm once updated.\n\nThanks,\nDana")),
    ("bec_payment_fraud", "urgent confidential wire", Email(
        subject="Re: Confidential",
        sender='"Mark Hale" <m.hale@acrne-corp.com>', receiver="finance@acme.com",
        date="Wed, 10 Sep 2025 11:02:00 +0000",
        body="On Tue 9 Sep, Finance wrote:\n> Noted, thanks\n\nWe are finalising an "
             "acquisition and I need a wire transfer processed today. Keep this between us "
             "until the announcement. I will send the beneficiary account details shortly. "
             "This is time-sensitive.")),
    ("vendor_invoice_fraud", "supplier bank change", Email(
        subject="Updated remittance details - invoice INV-88213",
        sender='"Northgate Supplies AP" <accounts@northgate-supplies.net>',
        receiver="ap@acme.com", date="Thu, 11 Sep 2025 14:20:00 +0000",
        body="Dear valued customer,\n\nPlease note our bank details have changed following "
             "a group restructure. Kindly direct payment for the attached invoice to our new "
             "account. Our records show an outstanding balance on your account.\n\n"
             "Accounts Receivable, Northgate Supplies",
        attachments=["INV-88213.pdf"])),
    ("credential_phishing", "MFA fatigue pretext", Email(
        subject="Unusual sign-in attempt blocked",
        sender='"Microsoft account team" <account-security@microsoft-secure.help>',
        auth_results=("mx.google.com; dkim=pass header.i=@microsoft-secure.help; "
                      "spf=pass smtp.mailfrom=microsoft-secure.help"),
        receiver="jane.doe@acme.com", date="Fri, 12 Sep 2025 06:30:00 +0000",
        body='We blocked a sign-in from Lagos, Nigeria. If this was not you, secure your '
             'account now.\n\n<a href="https://microsoft-secure.help/auth/verify?u=jane.doe">'
             'https://login.microsoftonline.com</a>\n\nYou will be asked to approve a '
             'notification on your authenticator app to confirm your identity.')),
    ("credential_phishing", "docusign lure", Email(
        subject="Priya Raman sent you a document to review and sign",
        sender='"DocuSign" <dse@docusign-e.net>', receiver="legal@acme.com",
        date="Fri, 12 Sep 2025 10:05:00 +0000",
        body='<p>You have received a document to review and sign.</p>'
             '<p><a href="https://docusign-e.net/d/9f2a1c">REVIEW DOCUMENT</a></p>'
             '<p>Please sign in with your email password to access this secure document.</p>')),
    ("credential_phishing", "QR-code phish", Email(
        subject="Your MFA enrolment expires today",
        sender='"IT Service Desk" <servicedesk@acme-it.support>', receiver="staff@acme.com",
        date="Mon, 15 Sep 2025 08:00:00 +0000",
        body="Your multi-factor authentication enrolment expires today. Scan the QR code "
             "below with your phone to re-validate your account. Failure to complete this "
             "will result in your account being suspended.\n[QR CODE IMAGE]")),
    ("credential_phishing", "shared file lure", Email(
        subject="Q3 Budget_Final.xlsx has been shared with you",
        sender='"SharePoint" <no-reply@sharepoint-notify.co>', receiver="finance@acme.com",
        date="Mon, 15 Sep 2025 09:15:00 +0000",
        body='<a href="http://sharepoint-notify.co/open?id=q3budget">Open in SharePoint</a>'
             '\nSign in to continue. This link expires in 24 hours.')),
    ("malware_delivery", "ISO container", Email(
        subject="Purchase order 4471 confirmation",
        sender='"Orders" <orders@globex-trading.icu>', receiver="procurement@acme.com",
        date="Tue, 16 Sep 2025 12:00:00 +0000",
        body="Please find attached our purchase order for your review. Open the attached "
             "file to view the order details.",
        attachments=["PO_4471.iso"])),
    ("malware_delivery", "macro lure", Email(
        subject="Remittance advice",
        sender='"Accounts" <remit@billing-notice.top>', receiver="ap@acme.com",
        date="Tue, 16 Sep 2025 13:30:00 +0000",
        body="Please see the attached remittance advice. If the document appears blank, "
             "click Enable Editing and then Enable Content to view it.",
        attachments=["Remittance_Advice.docm"])),
    ("malware_delivery", "password-protected archive", Email(
        subject="Scanned document from HP-Scanner",
        sender='"HP Scanner" <scanner@acme-scan.xyz>', receiver="jane.doe@acme.com",
        date="Wed, 17 Sep 2025 09:45:00 +0000",
        body="A document has been scanned and sent to you. The password for the archive "
             "is 1234. Please open the attached file to view the scanned document.",
        attachments=["Scan_20250917.zip"])),
    ("malware_delivery", "double extension", Email(
        subject="Invoice overdue - immediate action",
        sender='"Billing" <billing@invoice-secure.work>', receiver="ap@acme.com",
        date="Wed, 17 Sep 2025 10:10:00 +0000",
        body="Your invoice is past due. Please review the attached statement immediately "
             "to avoid legal action.",
        attachments=["Invoice_Sept.pdf.exe"])),
    ("extortion", "sextortion with breach password", Email(
        subject="I know your password is Summer2019!",
        sender="<recovery@mailfence-secure.cf>", receiver="jane.doe@acme.com",
        date="Thu, 18 Sep 2025 02:00:00 +0000",
        body="I placed malware on an adult site and recorded you through your webcam. "
             "I have full control of your device and all your contacts. Send 0.4 bitcoin "
             "to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq within 48 hours or your "
             "contacts will receive the recording.")),
    ("extortion", "ransom threat", Email(
        subject="Your data has been copied",
        sender="<contact@securedrop-notify.gq>", receiver="ceo@acme.com",
        date="Thu, 18 Sep 2025 03:30:00 +0000",
        body="We have exfiltrated 40GB from your network. Pay 5 BTC within 72 hours or we "
             "publish. Failure to comply will result in regulatory penalties and legal "
             "action against your company.")),
    ("recon_probe", "availability probe", Email(
        subject="Quick question",
        sender='"Mark Hale" <mark.hale.exec@outlook.com>', receiver="alex.chen@acme.com",
        date="Fri, 19 Sep 2025 08:05:00 +0000",
        body="Alex, are you available? I need a quick favour.")),
    ("recon_probe", "blank probe", Email(
        subject="Hi",
        sender='"Dana W" <dana.w.acme@gmail.com>', receiver="finance@acme.com",
        date="Fri, 19 Sep 2025 08:20:00 +0000",
        body="Are you at your desk?")),
    ("credential_phishing", "thread hijack", Email(
        subject="RE: RE: Contract renewal - signed copy",
        sender='"Tom Brady" <t.brady@northgate-supplies.net>', receiver="legal@acme.com",
        date="Fri, 19 Sep 2025 11:00:00 +0000",
        body='On Thu 18 Sep, Legal wrote:\n> Thanks Tom, we will review and revert.\n\n'
             'Apologies, the earlier link expired. Here is the signed copy:\n'
             '<a href="http://secure-docs-view.click/contract/renewal">'
             'https://northgate-supplies.net/contracts</a>\nYou will need to sign in to view it.')),
    ("credential_phishing", "payroll portal phish", Email(
        subject="Action needed: confirm your payroll details before 30 Sep",
        sender='"Workday Notifications" <noreply@workday-hr.link>', receiver="staff@acme.com",
        date="Fri, 19 Sep 2025 12:00:00 +0000",
        body='Your annual payroll confirmation is due. Please sign in to confirm your '
             'details:\nhttp://workday-hr.link/login/confirm\nAccounts not confirmed by '
             '30 September will be suspended.')),
]

def _auth(domain: str) -> str:
    """A passing, aligned DKIM/SPF result for `domain`.

    Measured on a real mailbox, 97% of legitimate mail is DKIM-authenticated.
    Benign controls without any Authentication-Results are therefore
    unrealistically suspicious, and were tripping first-contact and
    link-deception floors that real mail would never trip.
    """
    return (f"mx.google.com; dkim=pass header.i=@{domain} header.s=k1; "
            f"spf=pass smtp.mailfrom={domain}; dmarc=pass")


BENIGN: list[tuple[str, Email]] = [
    ("routine internal update", Email(
        subject="Weekly engineering sync notes",
        sender='"Priya Raman" <priya.raman@acme.com>', auth_results=_auth("acme.com"), receiver="engineering@acme.com",
        date="Mon, 15 Sep 2025 16:00:00 +0000",
        body="Hi all,\n\nNotes from today's sync are in the shared drive. We agreed to move "
             "the database migration to next sprint and Sam will own the rollback plan. "
             "Next sync is Monday at 10.\n\nThanks,\nPriya")),
    ("legitimate invoice", Email(
        subject="Invoice INV-2025-0912 from Northgate Supplies",
        sender='"Northgate Supplies" <accounts@northgate-supplies.com>', auth_results=_auth("northgate-supplies.com"),
        receiver="ap@acme.com", date="Fri, 12 Sep 2025 09:00:00 +0000",
        body="Dear Acme Ltd,\n\nPlease find attached invoice INV-2025-0912 for September "
             "deliveries, due 30 days from issue. Our bank details are unchanged and appear "
             "on the invoice as usual.\n\nRegards,\nAccounts Receivable",
        attachments=["INV-2025-0912.pdf"])),
    ("genuine password expiry", Email(
        subject="Your Acme password expires in 7 days",
        sender='"Acme IT" <it-notifications@acme.com>', auth_results=_auth("acme.com"), receiver="jane.doe@acme.com",
        date="Mon, 15 Sep 2025 07:00:00 +0000",
        body="Your network password will expire in 7 days. You can change it from any "
             "company device by pressing Ctrl+Alt+Del and selecting Change Password. "
             "The IT team will never ask you for your password.")),
    ("real payment request", Email(
        subject="Approval needed: September supplier run",
        sender='"Alex Chen" <alex.chen@acme.com>', auth_results=_auth("acme.com"), receiver="finance@acme.com",
        date="Tue, 16 Sep 2025 10:30:00 +0000",
        body="Hi team,\n\nThe September supplier payment run is ready for approval in the "
             "finance system. Total is as forecast. Please approve via the portal by "
             "Thursday so the wire transfer goes out on time.\n\nAlex")),
    ("marketing opt-in", Email(
        subject="Your September product newsletter",
        sender='"Stripe" <newsletter@stripe.com>', auth_results=_auth("stripe.com"), receiver="jane.doe@acme.com",
        date="Wed, 17 Sep 2025 08:00:00 +0000",
        body="Here is what shipped this month. You are receiving this email because you "
             "subscribed to product updates. Unsubscribe at any time.")),
    ("calendar logistics", Email(
        subject="Re: Lunch Thursday?",
        sender='"Sam Okafor" <sam.okafor@acme.com>', auth_results=_auth("acme.com"), receiver="priya.raman@acme.com",
        date="Wed, 17 Sep 2025 12:15:00 +0000",
        body="On Wed 17 Sep, Priya wrote:\n> Are you free Thursday?\n\nYes, works for me. "
             "Shall we say 12:30 at the usual place?")),
    ("genuine docusign", Email(
        subject="Please DocuSign: Master Services Agreement",
        sender='"DocuSign EU" <dse@eu.docusign.net>', auth_results=_auth("docusign.net"), receiver="legal@acme.com",
        date="Thu, 18 Sep 2025 09:00:00 +0000",
        body='<p>Priya Raman sent you a document to sign.</p>'
             '<p><a href="https://eu.docusign.net/Signing/EmailStart?t=9f2a">Review Document</a></p>')),
    ("HR announcement", Email(
        subject="Open enrolment starts Monday",
        sender='"Acme People Team" <people@acme.com>', auth_results=_auth("acme.com"), receiver="staff@acme.com",
        date="Thu, 18 Sep 2025 15:00:00 +0000",
        body="Open enrolment for benefits runs from Monday to the end of the month. "
             "Details and the enrolment portal link are on the intranet under People. "
             "Drop-in sessions are on Tuesday and Thursday.")),
]

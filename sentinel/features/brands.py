"""Registry of commonly impersonated brands and their legitimate domains.

Used for two checks that catch what keyword matching cannot: a display name
claiming a brand the sending domain does not own, and a sending domain that is
one or two keystrokes away from a real one.
"""
from __future__ import annotations

BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.co.uk"),
    "microsoft": ("microsoft.com", "office.com", "office365.com", "live.com",
                  "outlook.com", "microsoftonline.com", "sharepoint.com",
                  "msn.com", "windows.com", "azure.com", "msdn.com",
                  "microsoftstore.com", "skype.com", "github.com"),
    "apple": ("apple.com", "icloud.com", "itunes.com", "me.com", "mac.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazonses.com", "amazonaws.com",
               "awsstatic.com", "audible.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com",
               "googlecode.com", "googleapis.com", "googleusercontent.com",
               "gstatic.com", "googlesyndicatedsearch.com", "googlesource.com",
               "googleblog.com", "goo.gl", "withgoogle.com", "android.com"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobesign.com"),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "ups": ("ups.com",),
    "chase": ("chase.com", "jpmorgan.com"),
    "wells fargo": ("wellsfargo.com",),
    "citibank": ("citi.com", "citibank.com"),
    "bank of america": ("bankofamerica.com", "bofa.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.com", "barclays.co.uk"),
    "natwest": ("natwest.com",),
    "american express": ("americanexpress.com", "aexp.com"),
    "stripe": ("stripe.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "hmrc": ("hmrc.gov.uk", "gov.uk"),
    "irs": ("irs.gov",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "zoom": ("zoom.us", "zoom.com"),
    "slack": ("slack.com",),
    "salesforce": ("salesforce.com",),
    "intuit": ("intuit.com", "quickbooks.com"),
    "ebay": ("ebay.com", "ebay.co.uk"),
    "walmart": ("walmart.com",),
    "usps": ("usps.com", "usps.gov"),
}

# Brands own their country domains. Treating google.co.uk or amazon.de as an
# impersonation of google.com / amazon.com produced ten false positives on
# held-out mail, all of them ordinary mailing-list traffic, so a
# "<brand>.<any suffix>" registrable domain counts as owned by that brand.
def owns(brand: str, registrable: str) -> bool:
    if not registrable:
        return False
    if registrable in BRAND_DOMAINS.get(brand, ()):
        return True
    base = registrable.split(".", 1)[0]
    return base == brand.replace(" ", "")


# Flat set of every legitimate registrable domain above.
LEGIT_DOMAINS: frozenset[str] = frozenset(
    d for domains in BRAND_DOMAINS.values() for d in domains
)

# Brand token -> canonical name, for matching a display name or subdomain.
BRAND_TOKENS: dict[str, str] = {}
for brand in BRAND_DOMAINS:
    BRAND_TOKENS[brand.replace(" ", "")] = brand
    BRAND_TOKENS[brand] = brand
BRAND_TOKENS.update({
    "office365": "microsoft", "o365": "microsoft", "onedrive": "microsoft",
    "sharepoint": "microsoft", "outlook": "microsoft", "msft": "microsoft",
    "icloud": "apple", "itunes": "apple", "aws": "amazon", "prime": "amazon",
    "bofa": "bank of america", "amex": "american express", "jpmorgan": "chase",
})

FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.jp",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "aol.com", "mail.com", "gmx.com", "gmx.net", "gmx.de", "yandex.ru",
    "yandex.com", "mail.ru", "protonmail.com", "proton.me", "tutanota.com",
    "zoho.com", "icloud.com", "me.com", "inbox.com", "rediffmail.com",
    "163.com", "126.com", "qq.com", "sina.com", "web.de", "t-online.de",
    "libero.it", "free.fr", "orange.fr", "wanadoo.fr", "terra.com",
    "maktoob.com", "rocketmail.com", "ymail.com", "fastmail.com",
})

# TLDs with a persistently poor abuse reputation, plus the ones that collide
# with file extensions (.zip / .mov) and so make a URL look like a download.
HIGH_RISK_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
    "country", "stream", "download", "racing", "win", "bid", "loan", "date",
    "review", "faith", "science", "party", "trade", "webcam", "accountant",
    "cricket", "gdn", "men", "kim", "mom", "zip", "mov", "rest", "cyou",
    "sbs", "quest", "monster", "buzz", "icu", "cam", "surf", "lol", "autos",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "rebrand.ly", "s.id", "t.ly", "shorte.st", "bl.ink", "lnkd.in",
    "db.tt", "qr.ae", "j.mp", "tr.im", "soo.gd", "clck.ru", "v.gd",
})

# Extensions that either execute directly or are containers used to smuggle
# something that does.
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "msp", "cpl", "jar", "ps1", "psm1", "reg",
    "lnk", "iso", "img", "vhd", "vhdx", "cab", "dll", "scf", "inf", "application",
    "docm", "xlsm", "pptm", "dotm", "xlam", "xll", "xlsb", "slk", "iqy",
    "one", "svg", "chm", "appref-ms", "diagcab", "settingcontent-ms",
})

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    "zip", "rar", "7z", "tar", "gz", "bz2", "arj", "ace", "z", "lzh",
})

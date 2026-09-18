"""Social-engineering lexicons with span capture.

Each lexicon is a named regex bank. Matching returns not just a count but the
exact character spans that matched, so an incident report can quote the words
that drove the score instead of asserting "urgency detected".
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    lexicon: str
    term: str
    start: int
    end: int
    field: str          # "subject" | "body"

    def quote(self, text: str, pad: int = 45) -> str:
        lo = max(0, self.start - pad)
        hi = min(len(text), self.end + pad)
        frag = text[lo:hi].replace("\n", " ").replace("\r", " ")
        frag = re.sub(r"\s+", " ", frag).strip()
        return f"{'…' if lo else ''}{frag}{'…' if hi < len(text) else ''}"


# Each entry: lexicon name -> list of regex source strings.
# Phrases are preferred over bare words: "verify your account" carries signal,
# "account" alone does not.
LEXICONS: dict[str, list[str]] = {
    "urgency": [
        r"\burgent(?:ly)?\b", r"\bimmediate(?:ly)?\b", r"\bact now\b",
        r"\bright away\b", r"\bas soon as possible\b", r"\basap\b",
        r"\bwithin (?:24|48|72) hours?\b", r"\bexpir(?:es?|ing|ed) (?:today|soon|in)\b",
        r"\bfinal (?:notice|warning|reminder)\b", r"\blast chance\b",
        r"\btime[- ]sensitive\b", r"\bdo not delay\b", r"\bbefore it'?s too late\b",
        r"\bdeadline\b", r"\bprompt attention\b",
    ],
    "authority": [
        r"\b(?:ceo|cfo|coo|cto|chairman|managing director|president)\b",
        r"\bboard of directors\b", r"\bhead of (?:finance|hr|payroll|it)\b",
        r"\bit (?:department|helpdesk|help desk|support|administrator|admin)\b",
        r"\bsystem administrator\b", r"\bhuman resources\b", r"\bpayroll department\b",
        r"\bon behalf of the\b", r"\bcompliance (?:team|department|officer)\b",
        r"\blegal department\b", r"\bsecurity team\b",
    ],
    "credential_request": [
        r"\bverify your (?:account|identity|email|details|information)\b",
        r"\bconfirm your (?:account|password|identity|details|credentials)\b",
        r"\bvalidate your (?:account|email|mailbox)\b",
        r"\bupdate your (?:password|account|billing|payment) (?:details|information)\b",
        r"\bre[- ]?enter your\b", r"\bsign in to (?:continue|verify|confirm|restore)\b",
        r"\blog ?in to (?:continue|verify|confirm|restore|your account)\b",
        r"\bclick (?:here|below|the link) to (?:verify|confirm|log ?in|sign in|update)\b",
        r"\byour (?:password|credentials) (?:will )?expire",
        r"\bmailbox (?:is )?(?:full|quota|storage) (?:exceeded|limit|full)\b",
        r"\bstorage (?:quota|limit) exceeded\b",
        r"\breactivate your account\b", r"\bunusual (?:sign[- ]?in|login|activity)\b",
        r"\bsecurity (?:alert|notice) (?:for|on) your account\b",
        r"\btwo[- ]factor\b", r"\bone[- ]time (?:code|password|pin)\b",
        # The polished variants. A well-written lure does not say "verify your
        # account" -- it says "confirm the information through the secure
        # verification portal", which read as ordinary business English to an
        # earlier version of this bank and scored zero.
        r"\b(?:secure |online |customer )?verification (?:portal|session|page|link|review|process)\b",
        r"\bsecure (?:portal|link|form|page|upload)\b",
        r"\bconfirm (?:the|your) [\w ]{0,24}(?:information|details|data|record)s?\b",
        r"\b(?:complete|finish|proceed with) (?:the |your )?verification\b",
        r"\badditional verification\b", r"\bidentity (?:verification|confirmation)\b",
        r"\bre[- ]?confirm\b", r"\bauthenticate (?:your|the)\b",
        r"\bsign in to (?:the|your) (?:portal|account|dashboard)\b",
        r"\baccess (?:the|your) (?:secure )?(?:portal|document|file)\b",
    ],
    "payment": [
        r"\bwire (?:transfer|the funds|payment)\b", r"\bbank (?:transfer|details|account details)\b",
        r"\bremittance\b", r"\bswift code\b", r"\biban\b", r"\bach (?:transfer|payment)\b",
        r"\brouting number\b", r"\bbeneficiary account\b",
        r"\bgift ?cards?\b", r"\bitunes card\b", r"\bsteam card\b", r"\bgoogle play card\b",
        r"\boutstanding (?:invoice|balance|payment)\b", r"\boverdue (?:invoice|payment)\b",
        r"\bpast due\b", r"\bpurchase order\b", r"\bpayment (?:instructions?|details)\b",
        r"\bupdated? (?:our )?(?:bank|banking|account) (?:details|information)\b",
        r"\bchange (?:of|in) (?:bank|banking) (?:details|account)\b",
        r"\bprocess (?:this|the) payment\b", r"\bdirect deposit\b",
        r"\bbeneficiar(?:y|ies) (?:information|details|verification|reconciliation|account)\b",
        r"\bsettlement (?:cycle|status|date|verification|pending)\b",
        r"\breconciliation\b", r"\bmanual review\b",
        r"\bpayment (?:verification|confirmation|authorisation|authorization)\b",
    ],
    "money_request": [
        r"\b(?:send|wire|transfer|lend|loan|forward|remit)\s+(?:me|us|him|her|it)?\s*"
        r"(?:some\s+|the\s+|a\s+little\s+)?(?:money|cash|funds?|amount)\b",
        r"\bkindly\s+(?:send|help|assist|transfer|pay)\b",
        r"\brequest(?:ing)?\s+(?:for|you for)?\s*(?:an?\s+)?(?:amount|sum|money|funds?|loan)\b",
        r"\b(?:need|require)\s+(?:some\s+)?(?:money|cash|funds?|financial (?:help|assistance|support))\b",
        r"\bfinancial (?:help|assistance|support|aid)\b",
        r"\bhelp me (?:out )?with (?:some )?(?:money|cash|\$|£|€|₹)\b",
        r"\bcan you (?:kindly )?(?:spare|lend)\b",
        r"\bpay(?:ment)? (?:me|us) (?:back|the)\b",
        r"\bdonat(?:e|ion)\b", r"\bcontribut(?:e|ion)\b",
        r"\bsponsor(?:ship)?\b", r"\bfund ?rais(?:e|ing|er)\b",
    ],
    "identity_claim": [
        # Every pattern here must survive the module-wide IGNORECASE. An earlier
        # version used a bare [A-Z] to mean "a capitalised name", which under
        # IGNORECASE matches any letter -- so "i am going home" counted as an
        # identity claim. Where capitalisation genuinely matters, (?-i:...)
        # turns the flag off for just that part.
        r"\bmy name is\b", r"\bi represent\b", r"\bspeaking on behalf of\b",
        r"\bon behalf of (?:the )?(?:ceo|president|director|chairman|board)\b",
        r"\byou (?:may|might) (?:know|remember) me\b",
        r"\bverified (?:account|profile)\b",
        r"\bofficial (?:account|representative|page|charity)\b",
        r"\bi am (?:the )?(?:ceo|cfo|founder|owner|president|director|manager|"
        r"chairman|attorney|barrister|solicitor|agent|representative)\b",
        r"\bi am (?:the )?(?:real|actual|genuine)\b",
        # "this is <Capitalised Name>" -- capitalisation enforced explicitly.
        r"\bthis is (?-i:[A-Z][a-z]{2,}(?:[ -][A-Z][a-z]{2,})?)\b",
    ],
    "secrecy": [
        r"\bstrictly confidential\b", r"\bkeep this (?:between us|confidential|discreet)\b",
        r"\bdo not (?:tell|discuss|inform|share with)\b", r"\bdiscreet(?:ly|ion)?\b",
        r"\bprivate (?:and|&) confidential\b", r"\bdon'?t mention this\b",
        r"\bhandle this personally\b", r"\bbetween you and (?:me|i)\b",
    ],
    "threat": [
        r"\baccount (?:has been )?(?:suspended|locked|disabled|closed|restricted)\b",
        r"\bwill be (?:suspended|terminated|closed|deleted|deactivated)\b",
        r"\blegal action\b", r"\blawsuit\b", r"\bprosecut(?:ion|ed)\b",
        r"\bpolice\b", r"\bcourt (?:order|summons)\b", r"\bpenalt(?:y|ies)\b",
        r"\bfailure to (?:comply|respond|act)\b", r"\bpermanently (?:delete|lose|remove)\b",
        r"\bservice (?:will be )?(?:interrupted|discontinued)\b",
    ],
    "reward": [
        r"\byou have won\b", r"\blottery\b", r"\bjackpot\b", r"\bsweepstakes?\b",
        r"\bprize\b", r"\binherit(?:ance|ed)\b", r"\bnext of kin\b",
        r"\bbeneficiar(?:y|ies)\b", r"\bunclaimed (?:funds?|estate|money)\b",
        r"\bmillion (?:dollars|usd|pounds|euros)\b", r"\bcompensation (?:fund|payment)\b",
        r"\bwinning notification\b", r"\bclaim your (?:prize|reward|funds?)\b",
        r"\bfree (?:gift|money|cash)\b",
    ],
    "sextortion": [
        r"\bwebcam\b", r"\brecorded you\b", r"\bfilmed you\b",
        r"\badult (?:site|website|video|content)\b", r"\bpornograph",
        r"\byour (?:contacts|friends|family) will (?:see|receive)\b",
        r"\bi (?:have|got) (?:access to|full control of) your (?:device|computer|webcam)\b",
        r"\bmalware (?:on|installed on) your\b", r"\brdp\b",
        r"\bi know your password\b", r"\byour password is\b",
    ],
    "crypto": [
        r"\bbitcoin\b", r"\bbtc\b", r"\bethereum\b", r"\busdt\b", r"\btether\b",
        r"\bcrypto(?:currency)? (?:wallet|address|payment)\b", r"\bwallet address\b",
        r"\bbc1[a-z0-9]{20,}\b", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        r"\b0x[a-fA-F0-9]{40}\b", r"\bbinance\b", r"\bcoinbase\b",
    ],
    "it_support": [
        r"\bmailbox (?:full|storage|quota)\b", r"\bexceeded your (?:storage|quota)\b",
        r"\bpassword (?:expires?|expiry|expiration)\b",
        r"\bre[- ]?validate\b", r"\bmigrat(?:e|ion) (?:to|your) (?:new )?(?:server|mailbox|office|microsoft)\b",
        r"\bupgrade your (?:mailbox|account|email)\b",
        r"\bmaintenance (?:window|scheduled)\b", r"\bserver upgrade\b",
        r"\bemail (?:account )?(?:will be )?(?:deactivated|suspended)\b",
    ],
    "attachment_lure": [
        r"\bsee (?:the )?attach(?:ed|ment)\b", r"\bplease (?:find|review|open) (?:the )?attach",
        r"\benable (?:editing|content|macros?)\b", r"\bprotected (?:view|document)\b",
        r"\bdocument is (?:encrypted|protected)\b",
        r"\bpassword (?:for|to) (?:the )?(?:file|archive|attachment|document) is\b",
        r"\bopen the (?:attached|file|document) to (?:view|read|verify)\b",
        r"\bscanned (?:document|invoice|copy)\b", r"\bfax (?:message|document)\b",
        r"\bvoice ?mail (?:message|attached)\b", r"\bpurchase order attached\b",
    ],
    "spam_adult": [
        r"\bporn(?:ograph\w*)?\b", r"\bxxx\b", r"\bnude\b", r"\bnaked\b",
        r"\bhorny\b", r"\bmilf\b", r"\bfetish\b", r"\bescorts?\b",
        r"\bhardcore\b", r"\berotic\b", r"\borgasm\b", r"\bwebcam girls?\b",
        r"\badult (?:dvd|movie|video|site|content)\b", r"\bsex (?:video|tape|chat|cam)\b",
        r"\bpenis\b", r"\bpecker\b", r"\blibido\b", r"\berection\b",
        r"\benlarge(?:ment)?\b", r"\bviagra\b", r"\bcialis\b", r"\blevitra\b",
    ],
    "spam_pharma": [
        r"\bpharmac(?:y|ies|eutical)\b", r"\bno prescription\b",
        r"\bprescription (?:drugs?|meds?|required)\b", r"\bmedications?\b",
        r"\bxanax\b", r"\bvalium\b", r"\bvicodin\b", r"\bambien\b",
        r"\boxycontin\b", r"\bphentermine\b", r"\btramadol\b",
        r"\bgeneric (?:viagra|cialis|drugs?)\b", r"\bmedicinal drugs?\b",
        r"\bweight loss\b", r"\blose (?:weight|pounds|lbs)\b", r"\bdiet pills?\b",
        r"\bfat burn\w*\b", r"\bappetite suppress\w*\b", r"\bhoodia\b",
    ],
    "spam_finance": [
        r"\bpenny stocks?\b", r"\botc ?bb\b", r"\bpink sheets\b",
        r"\bhot stock\b", r"\bstock (?:pick|alert|tip)s?\b", r"\bticker symbol\b",
        r"\bstrong buy\b", r"\bprice target\b", r"\bundervalued (?:stock|company)\b",
        r"\bmortgages?\b", r"\brefinanc\w*\b", r"\bloan (?:approv\w*|offer|rate|amount)\b",
        r"\bdebt (?:relief|consolidat\w*|free)\b", r"\bcredit (?:repair|score)\b",
        r"\bpre-?approved\b", r"\bcash advance\b", r"\bpayday loan\b",
        r"\blowest (?:interest )?rates?\b", r"\blife insurance\b",
        r"\binsurance quote\b", r"\bcasino\b", r"\bonline poker\b",
        r"\broulette\b", r"\bblackjack\b", r"\bfree spins?\b", r"\bsportsbook\b",
    ],
    "spam_commercial": [
        r"\breplicas?\b", r"\brolex\b", r"\bluxury watch(?:es)?\b",
        r"\bdesigner (?:handbags?|bags?|watch(?:es)?)\b", r"\bknock ?offs?\b",
        r"\bimitations? of prestigious\b",
        r"\boem (?:soft|software)\b", r"\bcheap software\b",
        r"\bsoftware (?:sale|discount)\b", r"\bdownload (?:all )?softwares?\b",
        r"\bdiplomas?\b", r"\buniversity degrees?\b", r"\bdegree (?:program|online)\b",
        r"\bno (?:exams?|study|classes) required\b", r"\blife experience degree\b",
        r"\bsearch engine (?:optimi|submi|rank)\w*\b", r"\bbulk email\b",
        r"\bemail (?:list|blast|marketing)\b", r"\bmass mail\w*\b",
        r"\bincrease (?:your )?(?:web ?site )?traffic\b",
        r"\bwork (?:from|at) home\b", r"\bhome based business\b",
        r"\bbe your own boss\b", r"\bfinancial freedom\b", r"\bextra income\b",
        r"\bmake money (?:fast|online|from home)\b",
        r"\bearn \$?[\d,]+ (?:per|a|each) (?:week|day|month)\b",
        r"\btoner cartridges?\b", r"\bink cartridges?\b",
        r"\bsatellite tv\b", r"\bcable descrambler\b", r"\btimeshare\b",
        r"\bvacation packages?\b", r"\bfree (?:trial|sample|gift|cd|dvd)\b",
    ],
    "spam_bulk_marker": [
        r"\bunsubscribe\b", r"\bopt[- ]?out\b", r"\bremove me from\b",
        r"\bto be removed\b", r"\bclick here to (?:unsubscribe|stop)\b",
        r"\bthis is (?:an|a) (?:advertisement|ad|commercial)\b",
        r"\bcommercial e-?mail\b", r"\bcan-?spam\b",
        r"\byou (?:are )?receiv(?:ed|ing) this (?:e-?mail|message) because\b",
        r"\bmailing list\b", r"\bnewsletter\b",
    ],
    "job_scam": [
        r"\bjob (?:offer|opportunity|opening|vacancy|position)\b",
        r"\b(?:hiring|recruit(?:ing|ment))\b[^.!?\n]{0,40}\b(?:immediately|urgently|now)\b",
        r"\byour (?:cv|resume|profile) (?:has been |was )?(?:shortlisted|selected|reviewed)\b",
        r"\bwork from home\b", r"\bremote (?:job|work|position)\b",
        r"\bpart[- ]time (?:job|work|opportunity)\b",
        r"\bno (?:experience|interview|qualification) (?:required|needed|necessary)\b",
        r"\bearn (?:up to )?[$£€₹]?\s?[\d,]+\s?(?:per|a|each|/)\s?(?:day|week|hour|month)\b",
        r"\bdaily (?:payout|payment|earning)s?\b",
        r"\b(?:registration|security|training|processing) fee\b",
        r"\bsend (?:us )?your (?:bank|account) details? (?:for|to) (?:salary|payment)\b",
        r"\btask[- ]based (?:job|work|earning)\b", r"\bcomplete (?:simple )?tasks?\b",
        r"\bdata entry (?:job|work|operator)\b",
        r"\bwhat ?s ?app (?:me|us|your)\b", r"\btelegram (?:me|us|group|channel)\b",
    ],
    "investment_scam": [
        r"\bguaranteed (?:return|profit|income|payout)s?\b",
        r"\b(?:double|triple|10x|100x) your (?:money|investment|capital)\b",
        r"\brisk[- ]free (?:investment|profit|return)\b",
        r"\bhigh[- ](?:yield|return) investment\b",
        r"\b(?:crypto|bitcoin|forex|binary option)s? (?:trading|signal|investment|platform)\b",
        r"\btrading (?:signal|bot|expert|mentor|academy)\b",
        r"\b(?:roi|returns) of \d+ ?%\b", r"\b\d{2,} ?% (?:profit|return|roi|daily|weekly|monthly)\b",
        r"\bpassive income\b", r"\bfinancial freedom\b",
        r"\binvestment (?:plan|package|scheme|opportunity)\b",
        r"\bwithdraw(?:al)? (?:fee|tax|charge) (?:required|before)\b",
        r"\bminimum (?:deposit|investment) of\b",
        r"\bairdrop\b", r"\bpresale\b", r"\bgiveaway\b",
    ],
    "tech_support_scam": [
        r"\byour (?:computer|pc|device|system) (?:is|has been) (?:infected|compromised|at risk|hacked)\b",
        r"\b(?:virus|malware|trojan|spyware) (?:detected|found|alert)\b",
        r"\bsecurity (?:scan|alert) (?:found|detected)\b",
        r"\byour (?:licen[cs]e|antivirus|protection) (?:has )?expired\b",
        r"\b(?:norton|mcafee|avast|geek squad|microsoft support|windows support)\b",
        r"\bdo not (?:shut ?down|turn off|restart) your (?:computer|pc)\b",
        r"\berror code:? ?[a-z0-9-]{4,}\b",
        r"\bremote (?:access|assistance|session|support)\b",
        r"\banydesk\b", r"\bteamviewer\b", r"\bultraviewer\b",
        r"\bcall (?:microsoft|apple|windows|our) (?:support|technician)\b",
    ],
    "delivery_scam": [
        # Written to tolerate inserted words. An earlier version required
        # "unable to complete delivery" and missed "unable to complete THE
        # delivery"; "address could not be verified" missed "address
        # INFORMATION could not be verified"; and "delivery on hold" missed
        # "Delivery status: On hold".
        r"\b(?:package|parcel|shipment|delivery|item|consignment)\b[^.!?\n]{0,30}"
        r"\b(?:on hold|held|pending|suspended|failed|could ?n[o']t be delivered)\b",
        r"\bunable to (?:complete|make|process)\b[^.!?\n]{0,20}\bdeliver",
        r"\bdelivery (?:attempt|status|failed|exception)\b",
        r"\bre-?schedule\b[^.!?\n]{0,24}\bdeliver",
        r"\bredeliver(?:y)?\b", r"\bnew delivery (?:time|date|window)\b",
        r"\baddress\b[^.!?\n]{0,30}\b(?:could ?n[o']t be verified|incomplete|"
        r"incorrect|invalid|not recognised|not recognized)\b",
        r"\breturned to (?:the )?sender\b", r"\bawaiting (?:collection|delivery)\b",
        r"\b(?:customs|shipping|delivery|handling|redelivery) (?:fee|charge|duty|clearance)\b",
        r"\bsmall (?:fee|charge) to (?:release|redeliver)\b",
        r"\btrack(?:ing)? (?:your )?(?:package|parcel|shipment|order)\b",
        r"\byour (?:order|item|package) (?:could not|cannot|was unable to) be (?:delivered|shipped)\b",
        r"\bcourier\b", r"\bdispatch(?:ed)? (?:notice|failed)\b",
    ],
    "govt_impersonation": [
        r"\btax (?:refund|rebate|return|credit|notice|assessment)\b",
        r"\b(?:hmrc|irs|cra|ato|sars|income tax department|gst)\b",
        r"\bsocial security (?:number|administration|benefit)\b",
        r"\b(?:immigration|visa|passport) (?:status|application|office|violation)\b",
        r"\bgovernment (?:grant|benefit|subsidy|scheme)\b",
        r"\bunclaimed (?:tax|benefit|refund)\b",
        r"\bcourt (?:notice|summons|hearing)\b", r"\barrest warrant\b",
        r"\bfailure to (?:pay|respond) will result in (?:legal|police|arrest)\b",
        r"\b(?:aadhaar|pan card|kyc) (?:update|verification|suspended|expired)\b",
    ],
    "charity_fraud": [
        # Phrases, not words. A first version used bare "donation",
        # "contribution", "war" and "conflict"; measured on held-out mail it
        # fired 35 times and was wrong 34 times -- on Slashdot war coverage, an
        # academic "call for contributions", and a farewell-gift collection.
        # An appeal is recognisable by its structure, not its vocabulary.
        r"\b(?:affected|impacted|displaced|devastated) by\b[^.!?\n]{0,40}"
        r"\b(?:flood(?:ing|s)?|earthquake|hurricane|cyclone|famine|drought|"
        r"wildfire|tsunami|disaster|crisis|conflict|war)\b",
        r"\b(?:contribution|donation)s? of\b[^.!?\n]{0,20}[\d$£€₹]",
        r"\b(?:your |a |each |every )?(?:contribution|donation|gift)s?\b"
        r"[^.!?\n]{0,24}\b(?:can|will|would|help)\b[^.!?\n]{0,20}"
        r"\b(?:help|provide|support|fund|feed|shelter|save)\b",
        r"\b(?:disaster|emergency|humanitarian) (?:relief|response|aid|appeal|assistance)\b",
        r"\brelief (?:fund|effort|package|campaign|operation)s?\b",
        r"\bemergency (?:assistance|shelter|supplies|appeal|programme|program)\b",
        r"\b(?:clean water|temporary shelter|essential medicines?|food supplies)\b",
        r"\bevery (?:penny|cent|dollar|pound|rupee) (?:goes|helps|counts)\b",
        r"\bplease (?:give|donate|help|support)\b[^.!?\n]{0,24}"
        r"\b(?:generously|now|today)\b",
        r"\b(?:charity|charitable) (?:appeal|drive|campaign)\b",
        r"\bdonat(?:e|ion)s? (?:to|for) (?:the )?(?:victims|survivors|relief|fund|appeal)\b",
        r"\bsick (?:child|children)\b", r"\bmedical (?:bills?|treatment) (?:fund|appeal)\b",
        r"\bgofundme\b", r"\bfund ?raiser for\b",
    ],
    "romance": [
        r"\bmy dear(?:est)?\b", r"\bbeloved\b", r"\blooking for (?:a )?(?:serious )?relationship\b",
        r"\bsoul ?mate\b", r"\blonely\b", r"\bsingle (?:woman|lady|man) (?:seeking|looking)\b",
        r"\bdating (?:site|profile)\b", r"\bi saw your profile\b",
    ],
    "impersonated_brand": [
        r"\bpaypal\b", r"\bmicrosoft\b", r"\boffice ?365\b", r"\bo365\b",
        r"\bdocusign\b", r"\bdropbox\b", r"\bsharepoint\b", r"\bonedrive\b",
        r"\bamazon\b", r"\bapple\b", r"\bicloud\b", r"\bnetflix\b",
        r"\bgoogle (?:docs|drive|account)\b", r"\blinkedin\b", r"\badobe\b",
        r"\bfedex\b", r"\bdhl\b", r"\bups\b", r"\bups delivery\b",
        r"\bhmrc\b", r"\birs\b", r"\bwells fargo\b", r"\bchase\b", r"\bcitibank\b",
        r"\bbank of america\b", r"\bhsbc\b", r"\bbarclays\b", r"\bnatwest\b",
        r"\bamerican express\b", r"\bstripe\b", r"\bcoinbase\b", r"\bbinance\b",
    ],
}

# Compile once. IGNORECASE everywhere; these are lures, not code.
COMPILED: dict[str, re.Pattern] = {
    name: re.compile("|".join(f"(?:{p})" for p in pats), re.IGNORECASE)
    for name, pats in LEXICONS.items()
}

LEXICON_NAMES = tuple(LEXICONS.keys())


def scan(text: str, field: str = "body", lexicons: tuple[str, ...] | None = None) -> list[Hit]:
    """Return every lexicon hit in `text` with its exact span."""
    if not text:
        return []
    out: list[Hit] = []
    for name in (lexicons or LEXICON_NAMES):
        for m in COMPILED[name].finditer(text):
            out.append(Hit(lexicon=name, term=m.group(0), start=m.start(), end=m.end(), field=field))
    return out


def counts(hits: list[Hit]) -> dict[str, int]:
    """Hit count per lexicon, zero-filled so the feature vector is stable."""
    c = {name: 0 for name in LEXICON_NAMES}
    for h in hits:
        c[h.lexicon] += 1
    return c


def distinct_terms(hits: list[Hit], lexicon: str) -> list[str]:
    seen, out = set(), []
    for h in hits:
        if h.lexicon != lexicon:
            continue
        k = h.term.lower()
        if k not in seen:
            seen.add(k)
            out.append(h.term)
    return out

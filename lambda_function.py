#!/usr/bin/env python3
"""
Hartnell Security 411 — AWS Lambda Newsletter Generator
=========================================================
Pulls training_set.csv from the source S3 bucket, identifies the most
frequently reported duplicate/near-duplicate phishing emails, and generates
a formatted newsletter draft in the style of Hartnell College IT security
alerts. The draft is written as a .txt file to the drafts S3 bucket.

Architecture:
    S3 (hartnell-security411-source/training_set.csv)
        → Lambda (this function)
        → S3 (hartnell-security411-drafts/newsletter_YYYY-MM.txt)

Trigger: Monthly schedule via Amazon EventBridge

Environment Variables:
    SOURCE_BUCKET:  Name of S3 bucket containing training_set.csv
    DRAFTS_BUCKET:  Name of S3 bucket for newsletter draft output
    SOURCE_KEY:     Key (path) of CSV file in source bucket (default: training_set.csv)
    SIMILARITY_THRESHOLD: Near-duplicate threshold (default: 0.90)
"""

import csv
import re
import os
import io
import hashlib
import math
import time
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from datetime import datetime
from typing import List, Dict, Tuple, Set

try:
    import boto3
    s3_client = boto3.client('s3', region_name='us-west-2')
except ImportError:
    boto3 = None
    s3_client = None


# =============================================================================
# CONFIGURATION
# =============================================================================

SOURCE_BUCKET = os.environ.get('SOURCE_BUCKET', 'hartnell-security411-source')
DRAFTS_BUCKET = os.environ.get('DRAFTS_BUCKET', 'hartnell-security411-drafts')
SOURCE_KEY = os.environ.get('SOURCE_KEY', 'training_set.csv')
SIMILARITY_THRESHOLD = float(os.environ.get('SIMILARITY_THRESHOLD', '0.90'))

# Minimum number of duplicates for an email to be included in newsletter
MIN_REPORT_COUNT = 2


# =============================================================================
# TEXT NORMALIZATION
# =============================================================================

class TextNormalizer:
    """Normalizes email text for similarity comparison."""

    QP_PATTERN = re.compile(r'=([0-9A-Fa-f]{2})')
    QP_SOFT_LINEBREAK = re.compile(r'=\s*\n')
    HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
    HTML_ENTITY_PATTERN = re.compile(r'&[a-zA-Z]+;|&#\d+;')
    QUOTE_MARKER_PATTERN = re.compile(r'^[>\s]*>', re.MULTILINE)
    HEADER_PATTERN = re.compile(
        r'^(From|To|Cc|Bcc|Subject|Date|Sent|Reply-To|'
        r'Content-[Tt]ype|MIME-Version|Message-ID|'
        r'X-[A-Za-z-]+|Return-Path):.*$', re.MULTILINE
    )
    URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')
    EMAIL_PATTERN = re.compile(r'[\w.+-]+@[\w.-]+\.\w+')
    MULTI_SPACE = re.compile(r'[ \t]+')
    MULTI_NEWLINE = re.compile(r'\n{3,}')
    MIME_BOUNDARY = re.compile(r'^--[A-Za-z0-9_=.+-]+\s*$', re.MULTILINE)
    CONTENT_TYPE_LINE = re.compile(
        r'^Content-type:.*$', re.MULTILINE | re.IGNORECASE
    )

    @classmethod
    def normalize(cls, text: str) -> str:
        if not text:
            return ""
        text = cls.QP_SOFT_LINEBREAK.sub('', text)

        def decode_qp(match):
            try:
                return chr(int(match.group(1), 16))
            except (ValueError, OverflowError):
                return match.group(0)

        text = cls.QP_PATTERN.sub(decode_qp, text)
        text = cls.HTML_TAG_PATTERN.sub(' ', text)
        text = cls.HTML_ENTITY_PATTERN.sub(' ', text)
        text = cls.MIME_BOUNDARY.sub('', text)
        text = cls.CONTENT_TYPE_LINE.sub('', text)
        text = cls.HEADER_PATTERN.sub('', text)
        text = cls.QUOTE_MARKER_PATTERN.sub('', text)
        text = cls.MULTI_SPACE.sub(' ', text)
        text = cls.MULTI_NEWLINE.sub('\n\n', text)
        lines = [line.strip() for line in text.split('\n')]
        lines = [line for line in lines if line]
        text = '\n'.join(lines)
        text = text.lower().strip()
        return text

    @classmethod
    def extract_subject(cls, raw_text: str) -> str:
        if not raw_text:
            return ""
        first_line = raw_text.split('\n')[0].strip()
        for prefix in ['Re: ', 'Fwd: ', 'FW: ', 'RE: ']:
            if first_line.startswith(prefix):
                first_line = first_line[len(prefix):]
        return first_line

    @classmethod
    def extract_urls(cls, raw_text: str) -> List[str]:
        return cls.URL_PATTERN.findall(raw_text)

    @classmethod
    def extract_sender_emails(cls, raw_text: str) -> List[str]:
        emails = cls.EMAIL_PATTERN.findall(raw_text)
        skip_patterns = ['unsubscribe', 'privacy', 'noreply', 'no-reply',
                         'postmaster', 'mailer-daemon']
        filtered = []
        for email in emails:
            email_lower = email.lower()
            if not any(p in email_lower for p in skip_patterns):
                filtered.append(email_lower)
        return filtered


# =============================================================================
# TF-IDF ENGINE
# =============================================================================

class TFIDFEngine:
    """Lightweight TF-IDF for near-duplicate detection."""

    def __init__(self):
        self.vocabulary = {}
        self.idf = {}
        self.doc_count = 0

    @staticmethod
    def tokenize(text: str) -> List[str]:
        return re.findall(r'\b[a-z0-9]{2,}\b', text.lower())

    def fit(self, documents: List[str]):
        self.doc_count = len(documents)
        doc_freq = Counter()
        for doc in documents:
            tokens = set(self.tokenize(doc))
            for token in tokens:
                doc_freq[token] += 1
        idx = 0
        for term, freq in doc_freq.items():
            if freq > 1 and freq < self.doc_count * 0.95:
                self.vocabulary[term] = idx
                self.idf[term] = math.log(self.doc_count / (1 + freq))
                idx += 1

    def transform(self, text: str) -> Dict[int, float]:
        tokens = self.tokenize(text)
        tf = Counter(tokens)
        total = len(tokens) if tokens else 1
        vector = {}
        for term, count in tf.items():
            if term in self.vocabulary:
                idx = self.vocabulary[term]
                vector[idx] = (count / total) * self.idf[term]
        return vector

    @staticmethod
    def cosine_similarity(vec_a: Dict[int, float],
                          vec_b: Dict[int, float]) -> float:
        dot = sum(val * vec_b[idx] for idx, val in vec_a.items() if idx in vec_b)
        mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
        mag_b = math.sqrt(sum(v * v for v in vec_b.values()))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)


# =============================================================================
# PHISHING ARCHETYPE CLASSIFIER
# =============================================================================

ARCHETYPES = {
    'NIGERIAN_PRINCE_SCAM': {
        'description': 'advance-fee fraud or inheritance scam',
        'indicators': ['claims of inheritance', 'requests for bank details',
                       'promises of large sums of money'],
        'patterns': [r'inherit', r'million\s+(dollar|usd|pound)',
                     r'next\s+of\s+kin', r'deceased', r'beneficiary',
                     r'transfer.*funds', r'nigeri', r'algeri', r'prince']
    },
    'PHARMACY_SPAM': {
        'description': 'fake pharmacy or medication sales',
        'indicators': ['unsolicited drug offers', 'links to unknown pharmacies',
                       'claims of cheap prescription drugs'],
        'patterns': [r'pharmacy', r'viagra', r'cialis', r'pills?',
                     r'medication', r'drugstore', r'enlargement',
                     r'generic\s+drugs?', r'canadian\s+(pharmacy|healthcare)']
    },
    'CREDENTIAL_PHISHING': {
        'description': 'account or credential theft attempt',
        'indicators': ['requests to verify your account', 'fake login pages',
                       'threats of account suspension'],
        'patterns': [r'verify\s+your\s+(account|identity)',
                     r'password.*expir', r'update\s+your\s+(account|info)',
                     r'suspended', r'unauthorized\s+(access|activity)',
                     r'confirm\s+your\s+(identity|account)']
    },
    'FINANCIAL_FRAUD': {
        'description': 'payment or financial fraud attempt',
        'indicators': ['fake invoices or payment confirmations',
                       'requests to download attachments',
                       'urgent calls to contact your bank'],
        'patterns': [r'payment\s+(confirm|process|made)', r'invoice',
                     r'wire\s+transfer', r'bank\s+account',
                     r'financial\s+institution', r'mortgage']
    },
    'CREDIT_REPAIR': {
        'description': 'credit repair or debt services scam',
        'indicators': ['promises of free credit repair', 'links to unknown services',
                       'claims about removing negative items'],
        'patterns': [r'credit\s+(repair|bureau|score|consultation)',
                     r'bad\s+credit', r'negative\s+items',
                     r'free\s+consultation']
    },
    'REPLICA_GOODS': {
        'description': 'counterfeit merchandise advertising',
        'indicators': ['offers of luxury goods at impossibly low prices',
                       'links to unknown shopping sites'],
        'patterns': [r'replica', r'rolex', r'luxury\s+watch',
                     r'fraction.*price', r'high\s+quality.*replica']
    },
    'EMPLOYMENT_SCAM': {
        'description': 'fraudulent job offer or employment scam',
        'indicators': ['unsolicited job offers', 'requests for personal information',
                       'promises of quick or easy pay',
                       'impersonation of college employees'],
        'patterns': [r'job\s+offer', r'employment\s+opportunit',
                     r'work\s+from\s+home', r'paid\s+position',
                     r'hiring\s+immediately', r'easy\s+money']
    },
    'NEWSLETTER_IMPERSONATION': {
        'description': 'impersonation of a legitimate newsletter or alert',
        'indicators': ['mimics CNN, BBC, or institutional alerts',
                       'links that redirect to malicious sites'],
        'patterns': [r'daily\s+top\s+10', r'breaking\s+news',
                     r'click\s+here.*full\s+story', r'custom\s+alert']
    },
    'ROMANCE_SCAM': {
        'description': 'romance or dating lure',
        'indicators': ['unsolicited dating invitations',
                       'links to unknown dating sites'],
        'patterns': [r'dating', r'singles?\s+in\s+your',
                     r'meet\s+(hot|sexy|local)', r'relationship\s+type.*sex',
                     r'dream\s+girl']
    },
    'SOFTWARE_PIRACY': {
        'description': 'pirated software offer',
        'indicators': ['software at impossibly low prices',
                       'links to download cracked software'],
        'patterns': [r'download.*\$\d+', r'adobe', r'dreamweaver',
                     r'photoshop', r'software.*cheap']
    }
}


def classify_archetype(text: str) -> Tuple[str, str, List[str]]:
    """Returns (archetype_name, description, indicators) for the best match."""
    text_lower = text.lower()
    best_match = None
    best_score = 0

    for name, config in ARCHETYPES.items():
        matches = sum(1 for p in config['patterns'] if re.search(p, text_lower))
        score = matches / len(config['patterns'])
        if score > best_score:
            best_score = score
            best_match = name

    if best_match and best_score >= 0.15:
        config = ARCHETYPES[best_match]
        return (best_match, config['description'], config['indicators'])

    return ('UNKNOWN', 'unclassified phishing attempt',
            ['suspicious links', 'unsolicited contact', 'unusual requests'])


# =============================================================================
# DUPLICATE DETECTION ENGINE
# =============================================================================

def find_duplicate_groups(raw_emails, labels, threshold=0.90):
    """Find duplicate/near-duplicate email groups. Returns list of groups."""
    normalizer = TextNormalizer()
    tfidf = TFIDFEngine()

    # Normalize and fingerprint
    normalized = []
    fingerprints = []
    for raw in raw_emails:
        norm = normalizer.normalize(raw)
        normalized.append(norm)
        fingerprints.append(hashlib.md5(norm.encode('utf-8')).hexdigest())

    # Get unique representatives
    fp_to_rep = {}
    for idx, fp in enumerate(fingerprints):
        if fp not in fp_to_rep:
            fp_to_rep[fp] = idx

    unique_indices = list(fp_to_rep.values())
    unique_texts = [normalized[i] for i in unique_indices]

    # Build TF-IDF
    tfidf.fit(unique_texts)
    vectors = [tfidf.transform(text) for text in unique_texts]

    # Union-Find clustering
    n = len(unique_indices)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    # Pairwise comparison (with blocking for large datasets)
    if n > 2000:
        blocks = defaultdict(list)
        for i, idx in enumerate(unique_indices):
            subj_words = normalized[idx][:100].split()[:3]
            block_key = ' '.join(subj_words[:2]) if subj_words else ''
            blocks[block_key].append(i)

        for block_indices in blocks.values():
            if len(block_indices) > 500:
                continue
            for i in range(len(block_indices)):
                for j in range(i + 1, len(block_indices)):
                    sim = TFIDFEngine.cosine_similarity(
                        vectors[block_indices[i]], vectors[block_indices[j]])
                    if sim >= threshold:
                        union(block_indices[i], block_indices[j])
    else:
        for i in range(n):
            for j in range(i + 1, n):
                sim = TFIDFEngine.cosine_similarity(vectors[i], vectors[j])
                if sim >= threshold:
                    union(i, j)

    # Expand clusters with exact duplicates
    fp_groups = defaultdict(list)
    for idx, fp in enumerate(fingerprints):
        fp_groups[fp].append(idx)

    clusters = defaultdict(list)
    for i in range(n):
        clusters[find(i)].append(unique_indices[i])

    expanded = []
    for cluster_indices in clusters.values():
        full_group = []
        for idx in cluster_indices:
            full_group.extend(fp_groups[fingerprints[idx]])
        full_group = sorted(set(full_group))
        if len(full_group) >= MIN_REPORT_COUNT:
            expanded.append(full_group)

    # Sort by frequency descending
    expanded.sort(key=len, reverse=True)
    return expanded


# =============================================================================
# NEWSLETTER GENERATOR
# =============================================================================

def generate_newsletter(raw_emails, labels, duplicate_groups,
                        max_alerts=5) -> str:
    """Generate Hartnell Security 411 newsletter in the official format."""
    now = datetime.utcnow()
    month_year = now.strftime('%B %Y')

    normalizer = TextNormalizer()

    # Only include PHISHING duplicates
    phishing_groups = []
    for group in duplicate_groups:
        # Check if any in the group are labeled PHISHING
        phishing_in_group = [idx for idx in group if labels[idx] == 'PHISHING']
        if phishing_in_group:
            phishing_groups.append(group)

    if not phishing_groups:
        return _generate_no_threats_newsletter(month_year)

    # Build newsletter
    lines = []
    lines.append("=" * 70)
    lines.append("HARTNELL SECURITY 411")
    lines.append(f"Monthly Phishing Alert — {month_year}")
    lines.append("=" * 70)
    lines.append("")

    # Generate an alert for each top duplicate group
    for alert_num, group in enumerate(phishing_groups[:max_alerts], 1):
        representative = group[0]
        raw = raw_emails[representative]
        subject = normalizer.extract_subject(raw)
        urls = normalizer.extract_urls(raw)
        senders = normalizer.extract_sender_emails(raw)
        frequency = len(group)

        # Classify archetype
        archetype_name, description, indicators = classify_archetype(raw)

        lines.append("-" * 70)
        lines.append(f"ALERT #{alert_num} — Reported {frequency} times")
        lines.append("-" * 70)
        lines.append("")
        lines.append("Dear Panthers,")
        lines.append("")
        lines.append(
            f"Our Information Technology Department has been made aware of "
            f"a {description} circulating among Hartnell College email "
            f"accounts. This message has been reported {frequency} times "
            f"this period."
        )

        if subject:
            lines.append("")
            lines.append(f'The email uses a subject line similar to: "{subject}"')

        if senders:
            sender_display = senders[0] if len(senders) == 1 else \
                f"{senders[0]} (and {len(senders)-1} similar addresses)"
            lines.append(
                f"It may appear to come from: {sender_display}")

        lines.append("")
        lines.append("Please be aware:")

        for indicator in indicators[:4]:
            lines.append(f"    * {indicator.capitalize()}")

        if urls:
            suspicious_domains = set()
            for url in urls[:3]:
                try:
                    domain = url.split('/')[2]
                    suspicious_domains.add(domain)
                except IndexError:
                    pass
            if suspicious_domains:
                lines.append(
                    f"    * Contains links to: "
                    f"{', '.join(list(suspicious_domains)[:3])}")

        lines.append(
            "    * Do not reply, send your resume, or provide any "
            "personal information")
        lines.append(
            "    * Do not click on any links or respond to requests for "
            "personal or financial information")

        lines.append("")
        lines.append("How to protect yourself:")
        lines.append(
            "    * Verify the sender's email address before responding")
        lines.append(
            "    * Be cautious of unsolicited messages that promise "
            "quick or easy rewards")
        lines.append(
            "    * Never provide personal, banking, or financial "
            "information in response to an unexpected email")
        lines.append(
            "    * If you receive this message, forward it to "
            "cybersafe@hartnell.edu and then delete the email")
        lines.append("")

    # Summary statistics
    lines.append("")
    lines.append("=" * 70)
    lines.append("MONTHLY SUMMARY")
    lines.append("=" * 70)
    lines.append("")

    total_emails = len(raw_emails)
    total_phishing = labels.count('PHISHING')
    total_in_dup_groups = sum(len(g) for g in duplicate_groups)
    dup_percentage = (total_in_dup_groups / total_emails * 100) \
        if total_emails > 0 else 0

    lines.append(f"Total emails analyzed:              {total_emails:,}")
    lines.append(f"Phishing emails identified:         {total_phishing:,}")
    lines.append(f"Duplicate/near-duplicate groups:    {len(duplicate_groups):,}")
    lines.append(
        f"Emails in duplicate groups:         "
        f"{total_in_dup_groups:,} ({dup_percentage:.1f}%)")
    lines.append(
        f"Top reported phishing campaigns:    "
        f"{len(phishing_groups):,}")
    lines.append("")

    # Sign-off
    lines.append("-" * 70)
    lines.append("")
    lines.append(
        "Thank you for helping keep our Hartnell community safe. If you "
        "have any questions or believe you may have responded to this scam, "
        "please contact the Information Technology Department immediately "
        "at cybersafe@hartnell.edu.")
    lines.append("")
    lines.append("Stay Cyber Safe,")
    lines.append("Hartnell College Information Technology")
    lines.append("")
    lines.append("=" * 70)
    lines.append(
        f"Generated by Hartnell Security 411 Automated Analysis System")
    lines.append(
        f"Analysis date: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"Similarity threshold: {SIMILARITY_THRESHOLD * 100:.0f}%")
    lines.append("=" * 70)

    return '\n'.join(lines)


def _generate_no_threats_newsletter(month_year: str) -> str:
    """Generate newsletter when no significant threats detected."""
    lines = []
    lines.append("=" * 70)
    lines.append("HARTNELL SECURITY 411")
    lines.append(f"Monthly Phishing Alert — {month_year}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("Dear Panthers,")
    lines.append("")
    lines.append(
        "Our Information Technology Department has not identified any "
        "significant duplicate phishing campaigns this period. However, "
        "please remain vigilant.")
    lines.append("")
    lines.append("General reminders:")
    lines.append(
        "    * Always verify the sender's email address before responding")
    lines.append(
        "    * Never provide personal or financial information via email")
    lines.append(
        "    * Report suspicious emails to cybersafe@hartnell.edu")
    lines.append("")
    lines.append("Stay Cyber Safe,")
    lines.append("Hartnell College Information Technology")
    return '\n'.join(lines)


# =============================================================================
# LAMBDA HANDLER
# =============================================================================

def lambda_handler(event, context):
    """AWS Lambda entry point.

    Triggered monthly by EventBridge. Reads training_set.csv from S3,
    identifies duplicate phishing emails, generates newsletter draft,
    writes to drafts S3 bucket.
    """
    print(f"[INFO] Hartnell Security 411 Lambda starting...")
    print(f"[INFO] Source: s3://{SOURCE_BUCKET}/{SOURCE_KEY}")
    print(f"[INFO] Output: s3://{DRAFTS_BUCKET}/")
    start_time = time.time()

    # Step 1: Read CSV from S3
    print("[INFO] Reading training_set.csv from S3...")
    try:
        response = s3_client.get_object(Bucket=SOURCE_BUCKET, Key=SOURCE_KEY)
        csv_content = response['Body'].read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[ERROR] Failed to read from S3: {e}")
        return {
            'statusCode': 500,
            'body': f'Failed to read source file: {str(e)}'
        }

    # Step 2: Parse CSV
    print("[INFO] Parsing email database...")
    raw_emails = []
    labels = []

    reader = csv.reader(io.StringIO(csv_content), quotechar='"',
                        quoting=csv.QUOTE_ALL)
    for row_num, row in enumerate(reader, 1):
        if len(row) >= 2:
            label = row[0].strip().upper()
            content = row[1].strip()
            if label in ('BENIGN', 'PHISHING'):
                labels.append(label)
                raw_emails.append(content)

    total = len(raw_emails)
    print(f"[INFO] Loaded {total:,} emails "
          f"(BENIGN={labels.count('BENIGN'):,}, "
          f"PHISHING={labels.count('PHISHING'):,})")

    if total == 0:
        return {
            'statusCode': 400,
            'body': 'No valid emails found in source file'
        }

    # Step 3: Find duplicates
    print(f"[INFO] Finding duplicate/near-duplicate emails "
          f"(threshold={SIMILARITY_THRESHOLD})...")
    duplicate_groups = find_duplicate_groups(
        raw_emails, labels, threshold=SIMILARITY_THRESHOLD)
    print(f"[INFO] Found {len(duplicate_groups):,} duplicate groups")

    # Step 4: Generate newsletter
    print("[INFO] Generating newsletter draft...")
    newsletter = generate_newsletter(raw_emails, labels, duplicate_groups)

    # Step 5: Write to S3
    now = datetime.utcnow()
    output_key = f"newsletter_{now.strftime('%Y-%m')}.txt"
    print(f"[INFO] Writing draft to s3://{DRAFTS_BUCKET}/{output_key}")

    try:
        s3_client.put_object(
            Bucket=DRAFTS_BUCKET,
            Key=output_key,
            Body=newsletter.encode('utf-8'),
            ContentType='text/plain'
        )
    except Exception as e:
        print(f"[ERROR] Failed to write to S3: {e}")
        return {
            'statusCode': 500,
            'body': f'Failed to write draft: {str(e)}'
        }

    elapsed = time.time() - start_time
    print(f"[INFO] Complete in {elapsed:.2f}s")
    print(f"[INFO] Newsletter draft: s3://{DRAFTS_BUCKET}/{output_key}")

    return {
        'statusCode': 200,
        'body': {
            'message': 'Newsletter draft generated successfully',
            'output_bucket': DRAFTS_BUCKET,
            'output_key': output_key,
            'emails_analyzed': total,
            'duplicate_groups_found': len(duplicate_groups),
            'execution_time_seconds': round(elapsed, 2)
        }
    }


# =============================================================================
# LOCAL TESTING
# =============================================================================

if __name__ == '__main__':
    """Allow local testing without AWS infrastructure."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python lambda_function.py <path_to_training_set.csv>")
        print("  Runs the analysis locally and prints the newsletter to stdout.")
        sys.exit(1)

    csv_path = sys.argv[1]
    print(f"[LOCAL] Reading from: {csv_path}")

    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        csv_content = f.read()

    raw_emails = []
    labels = []
    reader = csv.reader(io.StringIO(csv_content), quotechar='"',
                        quoting=csv.QUOTE_ALL)
    for row in reader:
        if len(row) >= 2:
            label = row[0].strip().upper()
            content = row[1].strip()
            if label in ('BENIGN', 'PHISHING'):
                labels.append(label)
                raw_emails.append(content)

    print(f"[LOCAL] Loaded {len(raw_emails):,} emails")

    duplicate_groups = find_duplicate_groups(
        raw_emails, labels, threshold=SIMILARITY_THRESHOLD)
    print(f"[LOCAL] Found {len(duplicate_groups):,} duplicate groups")

    newsletter = generate_newsletter(raw_emails, labels, duplicate_groups)

    # Write to local file
    output_file = f"newsletter_{datetime.utcnow().strftime('%Y-%m')}.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(newsletter)

    print(f"\n[LOCAL] Newsletter written to: {output_file}")
    print(f"\n{'=' * 70}")
    print(newsletter)

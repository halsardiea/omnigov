# ---
# LOCATION : apps/interceptor/correlation.py
# PURPOSE  : The intelligence core of OmniGov — determines which framework controls
#            are relevant to each vulnerability finding.
#            Works in two stages:
#            1. Heuristic scoring: keyword matching, port hints, CVSS weighting
#            2. AI refinement (optional): sends the top heuristic candidates to Claude
#               for natural-language reasoning and richer summaries
#            Also computes the organisation-level compliance score and control impact
#            summary used in the executive PDF report.
#
# CONNECTS TO:
#   - apps/interceptor/tasks.py      → correlate_finding() called for every finding;
#                                       summarize_scan_alignment() called once per scan
#   - apps/interceptor/models.py     → FindingAnalysis stores the output of
#                                       correlate_finding() per finding
#   - apps/compliance/models.py      → FrameworkControl rows are the corpus that
#                                       rank_controls_for_finding() scores against
#   - omnigov/settings/base.py       → ANTHROPIC_API_KEY, AI_CORRELATION_MODEL,
#                                       AI_CORRELATION_MAX_CANDIDATES,
#                                       AI_CORRELATION_TOP_MATCHES read here
# ---
"""Framework control correlation and optional AI enrichment for scan findings."""
import json
import logging
import re
from collections import Counter

from django.conf import settings

logger = logging.getLogger(__name__)

STOPWORDS = {
    'about', 'after', 'against', 'also', 'among', 'been', 'being', 'between', 'because',
    'could', 'does', 'from', 'have', 'into', 'more', 'remote', 'server', 'service', 'that',
    'than', 'their', 'them', 'there', 'these', 'this', 'those', 'using', 'valid', 'with',
    'without', 'would', 'your', 'detected', 'found', 'host', 'hosts', 'system', 'systems',
}

SEVERITY_WEIGHTS = {
    'Critical': 1.0,
    'High': 0.8,
    'Medium': 0.5,
    'Low': 0.25,
    'Log': 0.0,
}

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.IGNORECASE)
MAC_PATTERN = re.compile(r'\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b', re.IGNORECASE)
PASSWORD_PATTERN = re.compile(r'(?i)(password\s*[:=]\s*)([^\s,;]+)')
USERNAME_PATTERN = re.compile(r'(?i)(username\s*[:=]\s*)([^\s,;]+)')

# Port number → relevant security topic keywords.
# When a finding comes in on port 443, we inject 'tls', 'ssl', 'encryption' etc.
# into the scoring so the correlator naturally favours cryptography controls.
PORT_HINTS = {
    '22': {'ssh', 'authentication', 'access', 'credential', 'identity'},
    '80': {'http', 'web', 'header', 'configuration', 'application'},
    '443': {'tls', 'ssl', 'https', 'certificate', 'encryption', 'communication'},
    '445': {'smb', 'windows', 'network', 'integrity', 'configuration'},
    '8080': {'web', 'application', 'default', 'credential', 'authentication'},
}

# Regex patterns that catch security topics in the finding description and name,
# each paired with the set of domain keywords it implies.
# For example, a finding mentioning 'ssh' or 'credential' injects 'authentication',
# 'identity', 'access' tokens which the scorer uses to rank access-control controls higher.
PATTERN_HINTS = [
    (re.compile(r'\b(ssl|tls|certificate|https|hsts)\b', re.IGNORECASE), {'tls', 'ssl', 'certificate', 'encryption', 'cryptography', 'communication'}),
    (re.compile(r'\b(ssh|credential|password|login|account|identity|auth)\b', re.IGNORECASE), {'authentication', 'identity', 'access', 'credential', 'password'}),
    (re.compile(r'\b(smb|signing|man-in-the-middle|mitm|network)\b', re.IGNORECASE), {'network', 'communication', 'integrity', 'segmentation'}),
    (re.compile(r'\b(version|patch|outdated|update|upgrade|apache|httpd)\b', re.IGNORECASE), {'patching', 'maintenance', 'configuration', 'software'}),
    (re.compile(r'\b(default|weak)\b', re.IGNORECASE), {'password', 'authentication', 'baseline', 'configuration'}),
]


def correlate_finding(finding, framework, controls=None):
    """Build a persisted analysis payload for a finding."""
    ranked_controls = rank_controls_for_finding(finding, framework, controls=controls)
    top_matches = ranked_controls[:settings.AI_CORRELATION_TOP_MATCHES]
    heuristic_result = _build_heuristic_result(finding, framework, top_matches)
    ai_result = _refine_with_claude(finding, framework, ranked_controls, heuristic_result)
    if ai_result:
        return ai_result
    return heuristic_result


def rank_controls_for_finding(finding, framework, controls=None):
    """Score framework controls against the finding text and return the best candidates."""
    finding_text, finding_tokens = _build_finding_document(finding)
    ranked_controls = []
    candidate_controls = controls if controls is not None else framework.controls.all()

    for control in candidate_controls:
        score, reasons = _score_control(control, finding_text, finding_tokens)
        if score <= 0:
            continue
        ranked_controls.append({
            'control_id': control.control_id,
            'title': control.title,
            'category': control.category,
            'description': control.description,
            'guidance': control.guidance,
            'keywords': list(control.keywords or []),
            'score': round(score, 2),
            'match_reasons': reasons,
        })

    ranked_controls.sort(key=lambda item: item['score'], reverse=True)
    threshold_matches = [item for item in ranked_controls if item['score'] >= 2.2]
    if threshold_matches:
        return threshold_matches[:settings.AI_CORRELATION_MAX_CANDIDATES]
    if ranked_controls and ranked_controls[0]['score'] >= 1.0:
        return ranked_controls[:min(settings.AI_CORRELATION_MAX_CANDIDATES, 3)]
    return []


def summarize_scan_alignment(findings, framework):
    """Compute a framework-level compliance score and impact summary."""
    impacted_controls = {}
    category_counter = Counter()
    mapped_findings = 0

    for finding in findings:
        analysis = getattr(finding, 'analysis_record', None)
        matched_controls = analysis.matched_controls if analysis else []
        if matched_controls:
            mapped_findings += 1

        seen_control_ids = set()
        for control in matched_controls:
            control_framework_id = control.get('framework_id')
            if control_framework_id is not None and control_framework_id != framework.id:
                continue

            control_id = control.get('control_id')
            if not control_id or control_id in seen_control_ids:
                continue
            seen_control_ids.add(control_id)

            weight = SEVERITY_WEIGHTS.get(finding.severity, 0.0)
            existing = impacted_controls.get(control_id)
            if existing is None or weight > existing['weight']:
                impacted_controls[control_id] = {
                    'weight': weight,
                    'title': control.get('title', ''),
                    'category': control.get('category', ''),
                }
            category_counter[control.get('category') or 'Uncategorized'] += 1

    total_controls = framework.controls.count()
    if total_controls:
        penalty = sum(item['weight'] for item in impacted_controls.values())
        compliance_score = round(max(0.0, (1 - penalty / total_controls) * 100), 1)
    else:
        compliance_score = 100.0

    if not impacted_controls and findings:
        average_penalty = sum(SEVERITY_WEIGHTS.get(finding.severity, 0.0) for finding in findings) / max(len(findings), 1)
        compliance_score = round(max(0.0, (1 - average_penalty) * 100), 1)

    return {
        'compliance_score': compliance_score,
        'impacted_controls_count': len(impacted_controls),
        'mapped_findings_count': mapped_findings,
        'top_categories': category_counter.most_common(5),
    }


def _build_heuristic_result(finding, framework, matched_controls):
    control_labels = [f"{item['control_id']} ({item['title']})" for item in matched_controls]
    categories = sorted({item['category'] for item in matched_controls if item.get('category')})
    control_text = ', '.join(control_labels[:3]) if control_labels else 'no direct control match was strong enough'
    category_text = ', '.join(categories) if categories else 'general cyber hygiene'
    summary = (
        f"This {finding.severity.lower()}-severity finding most directly affects {framework.name} requirements "
        f"around {category_text}. The strongest control matches are {control_text}."
    )

    remediation_parts = []
    if finding.solution:
        remediation_parts.append(finding.solution.strip())
    guidance_snippets = [item['guidance'].strip() for item in matched_controls if item.get('guidance')]
    if guidance_snippets:
        remediation_parts.append('Framework guidance: ' + ' '.join(dict.fromkeys(guidance_snippets[:2])))
    if not remediation_parts:
        remediation_parts.append('Review the affected service, validate exposure, and implement the mapped framework guidance.')

    confidence = 0.0
    if matched_controls:
        confidence = round(min(0.99, matched_controls[0]['score'] / 8.0), 2)

    return {
        'matched_controls': matched_controls,
        'executive_summary': summary,
        'technical_remediation': ' '.join(remediation_parts),
        'analysis_method': 'heuristic',
        'confidence_score': confidence,
        'raw_provider_response': {},
    }


def _refine_with_claude(finding, framework, ranked_controls, heuristic_result):
    """Refine heuristic control matches using the Anthropic Claude API."""
    if not settings.ANTHROPIC_API_KEY or not ranked_controls:
        return None

    try:
        import anthropic
    except ImportError:
        logger.warning(
            'ANTHROPIC_API_KEY is set but the anthropic package is not installed. '
            'Falling back to heuristic correlation.'
        )
        return None

    candidate_controls = ranked_controls[:settings.AI_CORRELATION_MAX_CANDIDATES]
    candidate_map = {item['control_id']: item for item in candidate_controls}

    prompt_payload = {
        'framework': {
            'name': framework.name,
            'version': framework.version,
        },
        'finding': {
            'name': finding.name,
            'severity': finding.severity,
            'cvss_score': finding.cvss_score,
            'cve_ids': finding.cve_ids,
            'description': _sanitize_for_external_model(finding.description),
            'solution': _sanitize_for_external_model(finding.solution),
        },
        'candidate_controls': [
            {
                'control_id': item['control_id'],
                'title': item['title'],
                'category': item['category'],
                'description': item['description'],
                'guidance': item['guidance'],
                'heuristic_score': item['score'],
            }
            for item in candidate_controls
        ],
    }

    system_prompt = (
        'You are a compliance correlation engine. '
        'Given a vulnerability finding and a list of candidate framework controls, '
        'select the controls that are most directly relevant. '
        'Return ONLY a JSON object — no markdown fences, no surrounding text — '
        'with exactly these keys: '
        '"selected_control_ids" (array of strings, max 3, from candidate list only), '
        '"executive_summary" (string, 3-5 sentences explaining business risk, likely exploitation path, '
        'and exactly why the finding conflicts with the intent of the selected controls; no IPs/hostnames/usernames/passwords), '
        '"technical_remediation" (string, detailed remediation plan with root cause, why it is non-compliant, '
        'prioritized implementation steps, validation steps, and compensating controls if a full fix is delayed; '
        'no IPs/hostnames/usernames/passwords), '
        '"confidence_score" (float between 0.0 and 1.0).'
    )

    user_message = (
        'Correlate this finding to the most relevant compliance controls.\n\n'
        + json.dumps(prompt_payload, indent=2)
    )

    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        # Prefill the assistant response with '{' to lock Claude into producing JSON.
        response = client.messages.create(
            model=settings.AI_CORRELATION_MODEL,
            max_tokens=1600,
            temperature=0.1,
            system=system_prompt,
            messages=[
                {'role': 'user', 'content': user_message},
                {'role': 'assistant', 'content': '{'},
            ],
        )
        raw_text = '{' + (response.content[0].text or '').strip()
        # Strip any trailing markdown fence the model may have added
        raw_text = re.sub(r'\s*```\s*$', '', raw_text.strip())
        payload = json.loads(raw_text)
    except Exception:
        logger.exception('Claude correlation refinement failed for finding %s', finding.pk)
        return None

    selected_ids = payload.get('selected_control_ids', [])
    selected_controls = [
        candidate_map[control_id]
        for control_id in selected_ids
        if control_id in candidate_map
    ]
    if not selected_controls:
        return None

    confidence = payload.get('confidence_score', heuristic_result['confidence_score'])
    if confidence is None:
        confidence = heuristic_result['confidence_score']
    if confidence and confidence > 1:
        confidence = round(min(confidence / 100.0, 1.0), 2)

    return {
        'matched_controls': selected_controls[:settings.AI_CORRELATION_TOP_MATCHES],
        'executive_summary': payload.get('executive_summary') or heuristic_result['executive_summary'],
        'technical_remediation': payload.get('technical_remediation') or heuristic_result['technical_remediation'],
        'analysis_method': 'ai_hybrid',
        'confidence_score': confidence or heuristic_result['confidence_score'],
        'raw_provider_response': payload,
    }


def _build_finding_document(finding):
    text_parts = [
        finding.name or '',
        finding.description or '',
        finding.solution or '',
        ' '.join(finding.cve_ids or []),
        ' '.join(finding.references or []),
        _extract_port_hints(finding.port),
    ]
    combined_text = ' '.join(part for part in text_parts if part)
    hint_tokens = set()
    for pattern, tokens in PATTERN_HINTS:
        if pattern.search(combined_text):
            hint_tokens.update(tokens)

    tokens = _tokenize(combined_text)
    tokens.update(hint_tokens)
    return combined_text.lower(), tokens


def _score_control(control, finding_text, finding_tokens):
    score = 0.0
    reasons = []

    exact_keyword_hits = []
    keyword_overlap_terms = set()
    for keyword in control.keywords or []:
        keyword_text = keyword.lower().strip()
        keyword_tokens = _tokenize(keyword_text)
        if not keyword_tokens:
            continue
        if ' ' in keyword_text and keyword_text in finding_text:
            score += 4.0
            exact_keyword_hits.append(keyword)
            continue
        overlap = finding_tokens & keyword_tokens
        if overlap:
            score += 1.8 * len(overlap) / len(keyword_tokens)
            keyword_overlap_terms.update(overlap)

    if exact_keyword_hits:
        reasons.append('keyword:' + ', '.join(exact_keyword_hits[:2]))
    if keyword_overlap_terms:
        reasons.append('overlap:' + ', '.join(sorted(keyword_overlap_terms)[:3]))

    title_overlap = finding_tokens & _tokenize(control.title)
    category_overlap = finding_tokens & _tokenize(control.category)
    description_overlap = finding_tokens & _tokenize(control.description)
    guidance_overlap = finding_tokens & _tokenize(control.guidance)

    score += 1.5 * len(title_overlap)
    score += 1.0 * len(category_overlap)
    score += 0.35 * min(4, len(description_overlap))
    score += 0.5 * min(4, len(guidance_overlap))

    if title_overlap:
        reasons.append('title:' + ', '.join(sorted(title_overlap)[:3]))
    if category_overlap:
        reasons.append('category:' + ', '.join(sorted(category_overlap)[:2]))

    return score, reasons[:4]


def _extract_port_hints(port_value):
    if not port_value:
        return ''
    port_text = str(port_value)
    port_number = port_text.split('/')[0]
    return ' '.join(sorted(PORT_HINTS.get(port_number, set())))


def _sanitize_for_external_model(text):
    if not text:
        return ''
    redacted = IP_PATTERN.sub('<ip>', text)
    redacted = EMAIL_PATTERN.sub('<email>', redacted)
    redacted = MAC_PATTERN.sub('<mac>', redacted)
    redacted = PASSWORD_PATTERN.sub(r'\1<redacted>', redacted)
    redacted = USERNAME_PATTERN.sub(r'\1<redacted>', redacted)
    return redacted


def _tokenize(text):
    if not text:
        return set()
    tokens = set(re.findall(r'[a-z0-9]{3,}', text.lower()))
    return {token for token in tokens if token not in STOPWORDS}
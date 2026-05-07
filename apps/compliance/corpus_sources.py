import json
import re
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]


def build_generated_controls(generator, corpus_file):
    if not isinstance(generator, dict):
        raise ValueError(f'{corpus_file.name} generator must be an object.')

    kind = _require_generator_text(generator, 'kind', corpus_file)
    source_file = _require_generator_text(generator, 'source_file', corpus_file)
    source_path = _resolve_source_path(source_file)

    if not source_path.is_file():
        raise ValueError(
            f'{corpus_file.name} references missing generator source {source_path}.'
        )

    if kind == 'nist-csf-export':
        return build_nist_csf_controls(source_path)

    if kind == 'jordan-capabilities-pdf':
        return build_jordan_capability_controls(source_path)

    raise ValueError(f'{corpus_file.name} references unsupported generator kind {kind}.')


def build_nist_csf_controls(source_path):
    payload = json.loads(source_path.read_text(encoding='utf-8'))
    response = payload.get('response')
    if not isinstance(response, dict):
        raise ValueError(f'{source_path.name} is missing a response object.')

    elements_container = response.get('elements')
    if not isinstance(elements_container, dict):
        raise ValueError(f'{source_path.name} is missing a response.elements object.')

    raw_elements = elements_container.get('elements')
    if not isinstance(raw_elements, list):
        raise ValueError(f'{source_path.name} response.elements.elements must be a list.')

    best_elements = {}
    for element in raw_elements:
        if not isinstance(element, dict):
            continue
        element_id = _clean_text(element.get('element_identifier', ''))
        if not element_id:
            continue
        current = best_elements.get(element_id)
        if current is None or _element_score(element) > _element_score(current):
            best_elements[element_id] = element

    withdrawn_ids = {
        element_id[3:]
        for element_id, element in best_elements.items()
        if element.get('element_type') == 'withdraw_reason' and element_id.startswith('WR-')
    }

    examples_by_subcategory = defaultdict(list)
    for element in raw_elements:
        if not isinstance(element, dict) or element.get('element_type') != 'implementation_example':
            continue
        example_id = _clean_text(element.get('element_identifier', ''))
        example_text = _clean_text(element.get('text', ''))
        parent_id = _parent_subcategory_id_from_example(example_id)
        if parent_id and example_text:
            examples_by_subcategory[parent_id].append(example_text)

    seen_subcategories = set()
    controls = []
    for element in raw_elements:
        if not isinstance(element, dict) or element.get('element_type') != 'subcategory':
            continue

        subcategory_id = _clean_text(element.get('element_identifier', ''))
        if not subcategory_id or subcategory_id in seen_subcategories:
            continue
        seen_subcategories.add(subcategory_id)

        subcategory = best_elements.get(subcategory_id, element)
        subcategory_text = _clean_text(subcategory.get('text', ''))
        if not subcategory_text or subcategory_id in withdrawn_ids:
            continue

        category_id = _category_id_from_subcategory(subcategory_id)
        if not category_id or category_id in withdrawn_ids:
            continue

        category = best_elements.get(category_id)
        category_text = _clean_text((category or {}).get('text', ''))
        if not category_text:
            continue

        function_id = category_id.split('.', 1)[0]
        function = best_elements.get(function_id, {})
        function_title = _clean_text(function.get('title', ''))
        category_title = _clean_text(category.get('title', '')) or category_id

        guidance = ''
        examples = examples_by_subcategory.get(subcategory_id, [])
        if examples:
            guidance = 'Implementation examples: ' + '; '.join(examples)

        controls.append(
            {
                'control_id': subcategory_id,
                'title': subcategory_text,
                'description': category_text,
                'category': ' / '.join(part for part in [function_title, category_title] if part),
                'keywords': _unique_strings(
                    [function_title, category_title, function_id, category_id]
                ),
                'guidance': guidance,
            }
        )

    if not controls:
        raise ValueError(f'{source_path.name} did not yield any active NIST subcategories.')

    return controls


def build_jordan_capability_controls(source_path):
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError(
            'Jordan capability generation requires the pypdf package to be installed.'
        ) from exc

    reader = PdfReader(str(source_path))
    pages = [_collapse_whitespace(page.extract_text() or '') for page in reader.pages]
    if len(pages) < 23:
        raise ValueError(f'{source_path.name} does not contain the expected 23 pages.')

    sections = [
        {
            'control_id': 'JNCF-AP',
            'title': 'Security in Architecture and Portfolio',
            'page': 5,
            'stop_marker': 'To have this consolidating capability',
            'subcapabilities': [
                'Strategy Management Capability',
                'Enterprise Architecture Management Capability',
                'Portfolio Management Capability',
                'Product / Services Portfolio Capability',
            ],
            'keywords': ['strategy', 'architecture', 'portfolio'],
        },
        {
            'control_id': 'JNCF-DEV',
            'title': 'Security in Development',
            'page': 8,
            'stop_marker': 'To have this consolidating capability',
            'subcapabilities': [
                'Requirements Management Capability',
                'Product & Team Backlog Capability',
                'Service / Product Design Capability',
                'Secure Code Management Capability',
                'Test Management Capability',
                'CI/CD Pipeline Capability',
                'Defect Management Capability',
                'Build Management Capability',
                'Release Management Capability',
            ],
            'keywords': ['development', 'secure coding', 'release'],
        },
        {
            'control_id': 'JNCF-DEL',
            'title': 'Security in Delivery',
            'page': 12,
            'stop_marker': 'A Comprehensive Overview',
            'subcapabilities': [
                'Operations Management',
                'Resource Management Capability',
                'Automated Remediation',
                'Request Management',
                'Change Management',
                'Identity & Access Management',
                'Deployment / Provisioning',
                'Secrets Management',
            ],
            'keywords': ['delivery', 'deployment', 'operations'],
        },
        {
            'control_id': 'JNCF-OPS',
            'title': 'Security in Operations',
            'page': 14,
            'stop_marker': 'These activities are listed below',
            'subcapabilities': [
                'Service Level Management Capability',
                'Incident Management Capability',
                'Problem Management Capability',
                'Event Management Capability',
                'Monitoring Capability',
                'Configuration Management Capability',
                'Fraud & Forensics Investigations Capability',
                'Continuity Management Capability',
                'Threat Intelligence Capability',
                'Data Management Capability',
            ],
            'keywords': ['operations', 'monitoring', 'incident response'],
        },
        {
            'control_id': 'JNCF-FND',
            'title': 'Fundamental Capabilities',
            'page': 18,
            'stop_marker': 'To provide a better overview',
            'subcapabilities': [
                'Policy Management Capability',
                'Risk and Compliance Management Capability',
                'Audit Management Capability',
                'Vendor and Contract Management Capability',
                'Workforce Management Capability',
                'Legal Management Capability',
                'Facility Management Capability',
                'Intelligence and Reporting Capability',
            ],
            'keywords': ['policy', 'risk', 'compliance'],
        },
        {
            'control_id': 'JNCF-NCR',
            'title': 'Security in National Cyber Responsibility',
            'page': 21,
            'stop_marker': 'This collaboration and these programs will aid in the following areas',
            'subcapabilities': [
                'Capacity Building Capability',
                'National Product Development Capability',
            ],
            'keywords': ['awareness', 'capacity building', 'national products'],
        },
    ]

    controls = []
    for section in sections:
        description = _extract_section_summary(
            pages[section['page'] - 1],
            section['title'],
            section.get('stop_marker'),
        )
        if not description:
            raise ValueError(
                f'{source_path.name} did not yield text for {section["title"]}.'
            )

        controls.append(
            {
                'control_id': section['control_id'],
                'title': section['title'],
                'description': description,
                'category': 'Main Capability',
                'keywords': _unique_strings([section['title'], *section['keywords']]),
                'guidance': 'Key sub-capabilities: ' + '; '.join(section['subcapabilities']),
            }
        )

    return controls


def _require_generator_text(generator, key, corpus_file):
    value = _clean_text(generator.get(key, ''))
    if value:
        return value
    raise ValueError(f'{corpus_file.name} generator is missing required field {key}.')


def _resolve_source_path(source_file):
    source_path = Path(source_file)
    if source_path.is_absolute():
        return source_path
    return BASE_DIR / source_path


def _element_score(element):
    return (len(_clean_text(element.get('text', ''))) * 2) + len(
        _clean_text(element.get('title', ''))
    )


def _parent_subcategory_id_from_example(example_id):
    parent_id, separator, suffix = example_id.rpartition('.')
    if separator and '-' in parent_id and suffix.isdigit():
        return parent_id
    return None


def _category_id_from_subcategory(subcategory_id):
    category_id, separator, suffix = subcategory_id.rpartition('-')
    if separator and suffix.isdigit():
        return category_id
    return None


def _extract_section_summary(page_text, title, stop_marker=None):
    text = re.sub(r'^Page\s+\d+\s+of\s+\d+\s+', '', page_text).strip()
    title_index = text.find(title)
    if title_index != -1:
        text = text[title_index + len(title):].strip()
    if stop_marker and stop_marker in text:
        text = text.split(stop_marker, 1)[0].strip()
    if 'A Comprehensive Overview' in text:
        text = text.split('A Comprehensive Overview', 1)[0].strip()
    return text.strip(' :-')


def _collapse_whitespace(text):
    return ' '.join(text.split())


def _clean_text(value):
    if not isinstance(value, str):
        return ''
    return _collapse_whitespace(value)


def _unique_strings(values):
    seen = set()
    items = []
    for value in values:
        cleaned = _clean_text(value)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            items.append(cleaned)
    return items
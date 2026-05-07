"""Helpers for rendering framework-specific finding analysis in reports."""


def matched_controls_for_framework(matched_controls, framework):
    controls = []
    for control in matched_controls or []:
        control_framework_id = control.get('framework_id')
        if control_framework_id is None or control_framework_id == framework.id:
            controls.append(control)
    return controls


def build_framework_finding_entry(finding, framework):
    analysis = finding.analysis_record
    framework_payload = {}

    if analysis and isinstance(analysis.raw_provider_response, dict):
        framework_results = analysis.raw_provider_response.get('framework_results') or {}
        if isinstance(framework_results, dict):
            framework_payload = framework_results.get(str(framework.id)) or {}

    matched_controls = framework_payload.get('matched_controls') or matched_controls_for_framework(
        analysis.matched_controls if analysis else [],
        framework,
    )

    return {
        'finding': finding,
        'matched_controls': matched_controls,
        'executive_summary': framework_payload.get('executive_summary') or getattr(analysis, 'executive_summary', ''),
        'technical_remediation': framework_payload.get('technical_remediation') or getattr(analysis, 'technical_remediation', ''),
        'analysis_method': framework_payload.get('analysis_method') or getattr(analysis, 'analysis_method', ''),
        'confidence_score': framework_payload.get('confidence_score', getattr(analysis, 'confidence_score', None)),
        'raw_provider_response': framework_payload.get('raw_provider_response') or getattr(analysis, 'raw_provider_response', {}),
    }
import json
from dataclasses import dataclass
from pathlib import Path

from django.db import transaction

from .corpus_sources import build_generated_controls
from .models import Framework, FrameworkControl


CORPUS_DIR = Path(__file__).resolve().parents[2] / 'data' / 'corpus'


class CorpusLoadError(ValueError):
    """Raised when a compliance corpus file cannot be loaded."""


@dataclass
class CorpusLoadResult:
    framework_name: str
    framework_version: str
    source_file: str
    framework_created: bool
    controls_loaded: int
    controls_replaced: int

    @property
    def label(self):
        return f"{self.framework_name} ({self.framework_version})"


def load_all_framework_corpora(corpus_dir=CORPUS_DIR):
    corpus_files = sorted(path for path in Path(corpus_dir).glob('*.json') if path.is_file())
    if not corpus_files:
        raise CorpusLoadError(f'No corpus files found in {corpus_dir}.')

    results = []
    for corpus_file in corpus_files:
        results.append(load_framework_corpus_file(corpus_file))
    return results


@transaction.atomic
def load_framework_corpus_file(corpus_file):
    with open(corpus_file, 'r', encoding='utf-8') as handle:
        payload = json.load(handle)

    framework_data = payload.get('framework')
    controls_data = payload.get('controls', [])
    generator_data = payload.get('generator')

    if not isinstance(framework_data, dict):
        raise CorpusLoadError(f'{corpus_file.name} is missing a framework object.')

    if not isinstance(controls_data, list):
        raise CorpusLoadError(f'{corpus_file.name} controls must be a list.')

    if generator_data is not None:
        try:
            controls_data = build_generated_controls(generator_data, corpus_file)
        except ValueError as exc:
            raise CorpusLoadError(str(exc)) from exc

    name = _require_text(framework_data, 'name', corpus_file)
    version = _require_text(framework_data, 'version', corpus_file)

    framework, created = Framework.objects.update_or_create(
        name=name,
        version=version,
        defaults={
            'description': framework_data.get('description', '').strip(),
            'is_active': framework_data.get('is_active', True),
        },
    )

    existing_count = framework.controls.count()
    framework.controls.all().delete()

    seen_control_ids = set()
    control_records = []
    for index, control in enumerate(controls_data, start=1):
        if not isinstance(control, dict):
            raise CorpusLoadError(
                f'{corpus_file.name} control #{index} must be an object.'
            )

        control_id = _require_text(control, 'control_id', corpus_file, index)
        if control_id in seen_control_ids:
            raise CorpusLoadError(
                f'{corpus_file.name} contains duplicate control_id {control_id}.')
        seen_control_ids.add(control_id)

        keywords = control.get('keywords', [])
        if not isinstance(keywords, list):
            raise CorpusLoadError(
                f'{corpus_file.name} control {control_id} keywords must be a list.'
            )

        control_records.append(
            FrameworkControl(
                framework=framework,
                control_id=control_id,
                title=_require_text(control, 'title', corpus_file, index),
                description=control.get('description', '').strip(),
                category=control.get('category', '').strip(),
                keywords=keywords,
                guidance=control.get('guidance', '').strip(),
            )
        )

    if control_records:
        FrameworkControl.objects.bulk_create(control_records)

    return CorpusLoadResult(
        framework_name=framework.name,
        framework_version=framework.version,
        source_file=corpus_file.name,
        framework_created=created,
        controls_loaded=len(control_records),
        controls_replaced=existing_count,
    )


def _require_text(data, key, corpus_file, index=None):
    value = data.get(key, '')
    if isinstance(value, str) and value.strip():
        return value.strip()

    location = corpus_file.name
    if index is not None:
        location = f'{location} control #{index}'
    raise CorpusLoadError(f'{location} is missing required field {key}.')
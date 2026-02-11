import re
from difflib import SequenceMatcher

#from cyclonedx.model.crypto import DetectionContext
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from typing import Optional, Set, Any



from cbom import lib_utils

_ALGORITHM_NAMES = lib_utils.get_algorithms()
if isinstance(_ALGORITHM_NAMES, dict):
    _ALGORITHM_NAMES = list(_ALGORITHM_NAMES.keys())
_ALGORITHM_PATTERN = '|'.join(
    sorted((re.escape(alg) for alg in _ALGORITHM_NAMES), key=len, reverse=True)
)

_ALGORITHM_REGEX = re.compile(_ALGORITHM_PATTERN, flags=re.IGNORECASE)
_KEY_LENGTH_REGEX = re.compile(f"\\D({'|'.join([str(key_length) for key_length in lib_utils.get_key_lengths()])})\\D")


def get_algorithm(code_snippet):
    match = _ALGORITHM_REGEX.search(code_snippet)
    if match:
        algorithm = match.group().upper()
        return lib_utils.get_algorithms().get(algorithm) or algorithm  # return full algorithm name if algorithm is aliased e.g. diffiehellman instead of dh
    return 'unknown'


def get_occurrence(physical_location):
    file_path = physical_location['artifactLocation']['uri']
    region = physical_location.get('region', {})
    start_line = region.get('startLine')
    end_line = region.get('endLine', start_line)
    line_numbers = None
    if start_line is not None:
        end_line = end_line if end_line is not None else start_line
        line_numbers = set(range(start_line, end_line + 1))

    if context_region := physical_location.get('contextRegion'):
        line = (context_region['startLine'] + context_region['endLine']) // 2
        code_snippet = context_region.get('snippet').get('text')
        occurrence = Occurrence(location=file_path, line=line, additional_context=code_snippet)
    else:
        occurrence = Occurrence(location=file_path, line=start_line)

    if line_numbers:
        occurrence.line_numbers = line_numbers
    return occurrence



def get_key_size(code_snippet):
    match = _KEY_LENGTH_REGEX.search(code_snippet)
    if match:
        return _KEY_LENGTH_REGEX.sub('\\1', match.group())



def _to_lines(value: Any) -> Set[int]:
    """
    Occurrence içinde satır numaraları bazen `line_numbers` (set),
    bazen tekil `line` (int) olarak gelebilir. Hepsini sete çeviriyoruz.
    """
    if value is None:
        return set()
    if isinstance(value, set):
        return value
    if isinstance(value, (list, tuple)):
        return set(value)
    if isinstance(value, int):
        return {value}
    return set()


def is_existing_occurrence_match(
    component,
    new_occurrence: Occurrence
) -> Optional[Occurrence]:
    """
    • Aynı **dosya yolu**nu (file_path / location) gösteren  
    • Satır kümeleri **kesişen** bir Occurrence varsa onu döndürür.  
      Yoksa `None` döner.
    """
    # Bileşende kayıtlı tüm Occurrence'lar
    for occ in component.evidence.occurrences:

        # 1️⃣  Dosya karşılaştırması
        occ_path = getattr(occ, "file_path", getattr(occ, "location", None))
        new_path = getattr(new_occurrence, "file_path", getattr(new_occurrence, "location", None))
        if occ_path != new_path:
            continue

        # 2️⃣  Satır kümelerinin kesişimi
        occ_lines = _to_lines(getattr(occ, "line_numbers", getattr(occ, "line", None)))
        new_lines = _to_lines(getattr(new_occurrence, "line_numbers", getattr(new_occurrence, "line", None)))

        if occ_lines & new_lines:          # kesişim boş değilse eşleşme var
            return occ

    return None

# def is_existing_occurrence_match(component, new_context):
#     for context in component.crypto_properties.detection_context:
#         if context.file_path == new_context.file_path and context.line_numbers.intersection(new_context.line_numbers):
#             return context


def merge_code_snippets(dc1, dc2):
    first = (dc1 if min(dc1.line_numbers) < min(dc2.line_numbers) else dc2).additional_context
    second = (dc1 if max(dc1.line_numbers) > max(dc2.line_numbers) else dc2).additional_context

    match = SequenceMatcher(None, first, second).find_longest_match()
    return f'{first[:match.a]}{second[:match.size]}{second[match.size:]}'


def extract_precise_snippet(snippet, region):
    line_start = region['startLine']
    line_end = region.get('endLine')
    line_start_col = region.get('startColumn', 1)
    line_end_col = region['endColumn']

    match line_start:
        case 1:
            array_of_lines = snippet.split('\n')
        case 2:
            array_of_lines = snippet.split('\n')[1:]
        case _:
            array_of_lines = snippet.split('\n')[2:]

    if not line_end:
        actual_line = array_of_lines[0]
        return actual_line[line_start_col - 1:line_end_col]
    else:
        end_line_index = (line_end - line_start)
        actual_lines = array_of_lines[:end_line_index + 1]
        actual_lines[0] = actual_lines[0][line_start_col - 1:]
        actual_lines[-1] = actual_lines[-1][:line_end_col]
        return '\n'.join(actual_lines)

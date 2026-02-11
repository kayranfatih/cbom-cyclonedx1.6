import copy
import itertools

_SARIF_TEMPLATE = {
    "version": "2.1.0",
    "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.4",
    "runs": [{
        "tool": {
            "driver": {
                "name": "CryptoCheck",
                "rules": []
            }
        },
        "results": []
    }]
}


def build_cryptocheck_sarif(cbom, rules, rule_violations, *, aggressive_aggregation=False):
    sarif = copy.deepcopy(_SARIF_TEMPLATE)
    rule_index_lookup = {rule['name']: index for index, rule in enumerate(rules)}

    for violation in rule_violations:
        violation_context = violation['detection']
        rule_index = rule_index_lookup.get(violation['name'], 0)
        if aggressive_aggregation:
            affected_components = (
                _get_bom_component(cbom, bom_ref).evidence.occurrences
                for bom_ref in violation['bom-refs']
            )
            detection_contexts = list(itertools.chain.from_iterable(affected_components))

            sarif['runs'][0]['results'].append({
                'ruleId': violation['name'],
                'ruleIndex': rule_index,
                'message': {
                    'text': violation_context['description']
                },
                'level': violation_context['type'],
                'locations': [_build_location_object(dc) for dc in detection_contexts]
            })
        else:
            for bom_ref in violation['bom-refs']:
                affected_component = _get_bom_component(cbom, bom_ref)
                for detection_context in affected_component.evidence.occurrences:
                    sarif['runs'][0]['results'].append({
                        'ruleId': violation['name'],
                        'ruleIndex': rule_index,
                        'message': {
                            'text': violation_context['description']
                        },
                        'level': violation_context['type'],
                        'locations': [_build_location_object(detection_context)]
                    })

    _add_rules_to_sarif(sarif, rules)
    return sarif


def _add_rules_to_sarif(sarif, rules):
    for rule in rules:
        sarif['runs'][0]['tool']['driver']['rules'].append({
            'id': rule['name'],
            'shortDescription': {
                'text': rule['name'].replace('-', ' ')
            },
            'properties': {
                'category': 'function',
                'tags': ['cryptography'],
                'problem.severity': rule['detection']['type'],  # todo: handle default
                'security-severity': str(rule['detection']['severity'])  # todo: handle default
            }
        })


def _build_location_object(detection_context):
    line_numbers = getattr(detection_context, 'line_numbers', None)
    if line_numbers:
        if isinstance(line_numbers, set):
            line_numbers = sorted(line_numbers)
    else:
        line = getattr(detection_context, 'line', None)
        line_numbers = [line, line] if line is not None else [0, 0]

    file_path = getattr(detection_context, 'file_path', None) or getattr(detection_context, 'location', '')
    region = {
        'startLine': line_numbers[0],
        'endLine': line_numbers[-1]
    }

    snippet = getattr(detection_context, 'additional_context', None)
    if snippet:
        region['snippet'] = {
            'text': snippet
        }

    return {
        'physicalLocation': {
            'artifactLocation': {
                'uri': file_path,
                'index': 0,
                'uriBaseId': '%SRCROOT%'
            },
            'region': region
        }
    }


def _get_bom_component(cbom, bom_ref):
    for component in cbom.components:
        if component.bom_ref == bom_ref:
            return component

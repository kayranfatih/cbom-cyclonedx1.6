import re
import uuid

from cyclonedx.model.component import ComponentType, Component, ComponentEvidence
from cyclonedx.model.crypto import CryptoPrimitive, CryptoProperties, CryptoAssetType, AlgorithmProperties, CryptoMode, CryptoPadding


from cbom import lib_utils
from cbom.parser import certificate, utils, related_crypto_material

_BLOCK_MODE_REGEX = re.compile(f"{'|'.join(lib_utils.get_block_modes())}", flags=re.IGNORECASE)
_FUNCTION_REGEX = re.compile(f"\\.[A-Z_\\d]*({'|'.join(lib_utils.get_functions())})[A-Z_\\d]*")
_PADDING_REGEX = re.compile(f"{'|'.join(lib_utils.get_padding_schemes())}", flags=re.IGNORECASE)
_ASYMMETRIC_KEY_TOKENS_REGEX = re.compile(f"{'|'.join(lib_utils.get_asymmetric_key_tokens())}", flags=re.IGNORECASE)


def parse_algorithm(cbom, finding):
    crypto_component = _generate_crypto_component(finding)
    

    if (crypto_component.crypto_properties.algorithm_properties.parameter_set_identifier) is not None and (crypto_component.crypto_properties.algorithm_properties.mode not in [CryptoMode.OTHER,CryptoMode.UNKNOWN] and crypto_component.crypto_properties.algorithm_properties.mode is not None): #in [CryptoPadding.OTHER, CryptoPadding.UNKNOWN]:
        name = f'{crypto_component.name}-{crypto_component.crypto_properties.algorithm_properties.parameter_set_identifier}-{crypto_component.crypto_properties.algorithm_properties.mode.value.upper()}'
    elif (crypto_component.crypto_properties.algorithm_properties.parameter_set_identifier is not None and crypto_component.crypto_properties.algorithm_properties.primitive is not CryptoPrimitive.PKE):
        name = f'{crypto_component.name}-{crypto_component.crypto_properties.algorithm_properties.parameter_set_identifier}'
    elif (crypto_component.crypto_properties.algorithm_properties.mode not in [CryptoMode.OTHER,CryptoMode.UNKNOWN]) and crypto_component.crypto_properties.algorithm_properties.mode is not None:
        name = f'{crypto_component.name}-{crypto_component.crypto_properties.algorithm_properties.mode.value.upper()}'
    else:
        name = f'{crypto_component.name}'

    occ = utils.get_occurrence(finding)
    evidence = ComponentEvidence(occurrences=[occ])

    algorithm_component = Component(
        bom_ref=f'cryptography:algorithm:{uuid.uuid4()}',
        name=name,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        crypto_properties=crypto_component.crypto_properties,
        evidence=evidence
    )

    if not (existing_component := _is_existing_component_overlap(cbom, algorithm_component)):
        cbom.components.add(algorithm_component)
        cbom.register_dependency(cbom.metadata.component, depends_on=[algorithm_component])
    else:
        algorithm_component = _update_existing_component(existing_component, algorithm_component, finding)

    if crypto_component.crypto_properties.algorithm_properties.primitive == CryptoPrimitive.PKE:
        code_snippet = finding['contextRegion']['snippet']['text']
        #if 'key' in code_snippet.lower():
        if _ASYMMETRIC_KEY_TOKENS_REGEX.search(code_snippet) or 'private_key' in code_snippet.lower():
            private_key_component = related_crypto_material.parse_private_key(cbom, finding)
            cbom.register_dependency(algorithm_component, depends_on=[private_key_component])

        if 'x509' in code_snippet.lower() or 'x.509' in code_snippet.lower():
            certificate_component = certificate.parse_x509_certificate_details(cbom, finding)
            cbom.register_dependency(algorithm_component, depends_on=[certificate_component])


def _generate_crypto_component(finding):
    code_snippet = finding['contextRegion']['snippet']['text']
    algorithm = utils.get_algorithm(utils.extract_precise_snippet(code_snippet, finding['region']))

    if algorithm == 'unknown':
        algorithm = utils.get_algorithm(code_snippet)

    if algorithm == 'FERNET':
        algorithm, key_size, mode = 'AES', '128', CryptoMode.CBC
        primitive = CryptoPrimitive.BLOCK_CIPHER
    else:
        primitive = _infer_primitive(algorithm)
        if 'key' in code_snippet.lower() and primitive != CryptoPrimitive.HASH:
            key_size = utils.get_key_size(code_snippet)
        else:
            key_size = None

        try:
            if primitive == CryptoPrimitive.BLOCK_CIPHER:
                mode = _extract_mode(code_snippet)
                mode = CryptoMode(mode.lower()) if mode else CryptoMode.UNKNOWN
            else:
                mode = None
        except ValueError:
            mode = CryptoMode.OTHER

    try:
        padding = _extract_padding(code_snippet)
        padding = CryptoPadding(padding.lower()) if padding else CryptoPadding.UNKNOWN
    except ValueError:
        padding = CryptoPadding.OTHER

    return Component(
        name=algorithm,
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=AlgorithmProperties(
                primitive=primitive,
                parameter_set_identifier=key_size,
                mode=mode,
                padding=padding,
                crypto_functions=tuple(_extract_crypto_functions(code_snippet))
            )
        )
    )


# def _build_variant(algorithm, *, key_size=None, block_mode=None):
#     variant = algorithm.upper()
#     if key_size:
#         variant += f'-{key_size}'
#     if block_mode and block_mode not in [CryptoMode.OTHER, CryptoMode.UNKNOWN]:
#         variant += f'-{block_mode.value.upper()}'
#     return variant


def _extract_crypto_functions(code_snippet):
    matches = _FUNCTION_REGEX.findall(''.join(code_snippet.split()))
    matches = [_FUNCTION_REGEX.sub('\\1', m) for m in matches]
    return set(matches)


def _extract_mode(code_snippet):
    match = _BLOCK_MODE_REGEX.search(code_snippet)
    if match:
        return match.group()


def _extract_padding(code_snippet):
    match = _PADDING_REGEX.search(code_snippet)
    if match:
        return match.group()


def _infer_primitive(algorithm, additional_context=None):
    primitive = lib_utils.get_primitive_mapping(algorithm.lower())
    return CryptoPrimitive(primitive)


def _is_existing_component_overlap(cbom, component):
    algorithm_components = (c for c in cbom.components if c.crypto_properties.asset_type == CryptoAssetType.ALGORITHM)

    for existing_component in algorithm_components:
        if existing_component.name == component.name:
            return existing_component


def _update_existing_component(existing_component, component, finding):
    new_occ = utils.get_occurrence(finding)

    # 1️⃣  Eşleşen Occurrence var mı?
    existing_occ = utils.is_existing_occurrence_match(existing_component, new_occ)
    if existing_occ:
        existing_occ.additional_context = utils.merge_code_snippets(
            existing_occ, new_occ
        )
    else:
        existing_component.evidence.occurrences.add(new_occ)

    # 2️⃣  Yeni crypto-function’ları ekle
    existing_component.crypto_properties.algorithm_properties.crypto_functions |= (
        component.crypto_properties.algorithm_properties.crypto_functions
    )

    return existing_component


    # new_context = component.crypto_properties.detection_context[0]

    # if existing_context := utils.is_existing_detection_context_match(existing_component, new_context):
    #     existing_context.additional_context = utils.merge_code_snippets(existing_context, new_context)
    #     existing_context.line_numbers = existing_context.line_numbers.union(new_context.line_numbers)
    #     return existing_component
    # else:
    #     existing_component.crypto_properties.algorithm_properties.crypto_functions.update(component.crypto_properties.algorithm_properties.crypto_functions)
    #     existing_component.crypto_properties.detection_context.add(new_context)
    #     return existing_component

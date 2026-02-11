import re
import uuid

from cyclonedx.model.component import ComponentType, Component, ComponentEvidence
from cyclonedx.model.crypto import CertificateProperties, CryptoProperties, CryptoAssetType

from cbom import lib_utils
from cbom.parser import utils

_X509_ATTRIBUTE_NAMES = {
    'COMMON_NAME': 'CN',  # 2.5.4.3
    'LOCALITY_NAME': 'L',  # 2.5.4.7
    'STATE_OR_PROVINCE_NAME': 'ST',  # 2.5.4.8
    'ORGANIZATION_NAME': 'O',  # 2.5.4.10
    'ORGANIZATIONAL_UNIT_NAME': 'OU',  # 2.5.4.11
    'COUNTRY_NAME': 'C',  # 2.5.4.6
    'DOMAIN_COMPONENT': 'DC',  # 0.9.2342.19200300.100.1.2
    'USER_ID': 'UID',  # 0.9.2342.19200300.100.1.1
}

_X509_ATTRIBUTES_REGEX = re.compile(
    f"({'|'.join(_X509_ATTRIBUTE_NAMES.keys())})(.*['\"].*['\"])",
    flags=re.IGNORECASE
)

_ALGORITHM_NAMES = lib_utils.get_algorithms()
if isinstance(_ALGORITHM_NAMES, dict):
    _ALGORITHM_NAMES = list(_ALGORITHM_NAMES.keys())
_ALGORITHM_PATTERN = '|'.join(
    sorted((re.escape(alg) for alg in _ALGORITHM_NAMES), key=len, reverse=True)
)

_SIGNING_ALGORITHM_REGEX = re.compile(
    f"sign[A-Z\\d_$]*\\(.*({_ALGORITHM_PATTERN}).*\\)",
    flags=re.IGNORECASE
)


def parse_x509_certificate_details(cbom, finding):
    crypto_properties = _generate_crypto_component(finding)
    unique_identifier = uuid.uuid4()

    occ = utils.get_occurrence(finding)       
    evidence = ComponentEvidence(occurrences=[occ])

    component = Component(
        bom_ref=f'cryptography:certificate:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        crypto_properties=crypto_properties,
        evidence=evidence
    )
    if not (existing_component := _is_existing_component_overlap(cbom, component, finding)):
        cbom.components.add(component)
    else:
        component = _update_existing_component(existing_component, component, finding)
    return component


def _generate_crypto_component(finding):
    code_snippet = finding['contextRegion']['snippet']['text']
    subject = issuer = _generate_distinguished_name(code_snippet)

    certificate_properties = CertificateProperties(
        subject_name=subject,
        issuer_name=issuer,
        certificate_format='X.509'
    )
    # These attributes are not part of the upstream constructor in cyclonedx>=10.2.0,
    # but we still rely on them internally for de-duplication and reporting.
    certificate_properties.certificate_algorithm = utils.get_algorithm(code_snippet)
    certificate_properties.certificate_signature_algorithm = _extract_signature_algorithm(code_snippet)

    return CryptoProperties(
        asset_type=CryptoAssetType.CERTIFICATE,
        certificate_properties=certificate_properties
    )


def _generate_distinguished_name(code_snippet):

    def append(text):
        nonlocal distinguished_name
        distinguished_name += f', {text}' if distinguished_name else text

    distinguished_name = ''
    for attribute_name, attribute_value in re.findall(_X509_ATTRIBUTES_REGEX, code_snippet):
        start_index = attribute_value.index(attribute_value[-1])
        attribute_value = attribute_value[start_index + 1:len(attribute_value) - 1]
        append(f'{_X509_ATTRIBUTE_NAMES[attribute_name.upper()]}={attribute_value}')
    return distinguished_name


def _extract_signature_algorithm(code_snippet):
    match = _SIGNING_ALGORITHM_REGEX.search(code_snippet)
    if match:
        return _SIGNING_ALGORITHM_REGEX.sub('\\1', match.group())


def _is_existing_component_overlap(cbom, component, finding):
    new_occ = utils.get_occurrence(finding)

    certificate_components = (
        c for c in cbom.components
        if c.crypto_properties.asset_type == CryptoAssetType.CERTIFICATE
    )

    for existing_component in certificate_components:
        same_algo = (
            existing_component.crypto_properties
            .certificate_properties.certificate_algorithm
            ==
            component.crypto_properties
            .certificate_properties.certificate_algorithm
        )
        if not same_algo:
            continue

        # 🔑  component → new_occ (DOĞRU imza)
        if utils.is_existing_occurrence_match(existing_component, new_occ):
            return existing_component
    return None

    
    
    # certificate_components = (c for c in cbom.components if c.crypto_properties.asset_type == CryptoAssetType.CERTIFICATE)

    # for existing_component in certificate_components:
    #     if (  # same certificate algorithm & overlapping detection context
    #         existing_component.crypto_properties.certificate_properties.certificate_algorithm == component.crypto_properties.certificate_properties.certificate_algorithm and
    #         utils.is_existing_occurrence_match(existing_component, component.crypto_properties.detection_context[0])
    #     ):
    #         return existing_component


def _update_existing_component(existing_component, component, finding):
    new_occ = utils.get_occurrence(finding)

    # 1️⃣  Çakışan Occurrence var mı?
    existing_occ = utils.is_existing_occurrence_match(existing_component, new_occ)

    if existing_occ:
        existing_occ.additional_context = utils.merge_code_snippets(
            existing_occ, new_occ
        )
        if hasattr(existing_occ, "line_numbers") and hasattr(new_occ, "line_numbers"):
            existing_occ.line_numbers |= new_occ.line_numbers
    else:
        existing_component.evidence.occurrences.add(new_occ)

    # 2️⃣  crypto_functions kümelerini birleştir (varsa)
    new_algo_props = getattr(component.crypto_properties, "algorithm_properties", None)
    if new_algo_props:
        existing_algo_props = getattr(existing_component.crypto_properties, "algorithm_properties", None)
        if existing_algo_props:
            existing_algo_props.crypto_functions |= new_algo_props.crypto_functions
        else:
            existing_component.crypto_properties.algorithm_properties = new_algo_props

    # 3️⃣  Sertifika alanlarını doldur
    old_cert = existing_component.crypto_properties.certificate_properties
    new_cert = component.crypto_properties.certificate_properties
    for field, value in vars(new_cert).items():
        if not getattr(old_cert, field, None):
            setattr(old_cert, field, value)

    return existing_component

    # context = component.crypto_properties.detection_context[0]

    # if existing_context := utils.is_existing_detection_context_match(existing_component, context):
    #     existing_context.additional_context = utils.merge_code_snippets(existing_context, context)
    #     existing_context.line_numbers = existing_context.line_numbers.union(context.line_numbers)

    #     for field in vars(component.crypto_properties.certificate_properties):
    #         if not getattr(existing_component.crypto_properties.certificate_properties, field):
    #             field_value = getattr(component.crypto_properties.certificate_properties, field)
    #             setattr(existing_component.crypto_properties.certificate_properties, field, field_value)
    #     return existing_component

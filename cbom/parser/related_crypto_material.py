import uuid

from cyclonedx.model.component import Component, ComponentType, ComponentEvidence
from cyclonedx.model.crypto import CryptoProperties, CryptoAssetType, RelatedCryptoMaterialProperties, \
    RelatedCryptoMaterialType

from cbom.parser import utils


def parse_initialization_vector(cbom, finding):
    crypto_properties = _generate_crypto_component(finding, RelatedCryptoMaterialType.INITIALIZATION_VECTOR)
    unique_identifier = uuid.uuid4()

    occ = utils.get_occurrence(finding)       
    evidence = ComponentEvidence(occurrences=[occ])

    component = Component(
        bom_ref=f'cryptography:iv:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTO_ASSET,
        crypto_properties=crypto_properties,
        evidence=evidence
    )
    cbom.components.add(component)
    return component


def parse_private_key(cbom, finding):
    key_size = utils.get_key_size(finding['contextRegion']['snippet']['text'])
    if key_size:
        key_size = int(key_size)

    crypto_properties = _generate_crypto_component(finding, RelatedCryptoMaterialType.PRIVATE_KEY, size=key_size)
    unique_identifier = uuid.uuid4()

    occ = utils.get_occurrence(finding)       
    evidence = ComponentEvidence(occurrences=[occ])

    component = Component(
        bom_ref=f'cryptography:private_key:{unique_identifier}',
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


def _generate_crypto_component(component, material_type, *, size=None):
    return CryptoProperties(
        asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
        related_crypto_material_properties=RelatedCryptoMaterialProperties(
            type=material_type,
            size=size
        )
    )


# def _is_existing_component_overlap(cbom, component):
#     related_crypto_material_components = (c for c in cbom.components if c.crypto_properties.asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL)

#     for existing_component in related_crypto_material_components:
#         if utils.is_existing_occurrence_match(existing_component, component.crypto_properties.detection_context[0]):
#             return existing_component
def _is_existing_component_overlap(cbom, component, finding):
    new_occ = utils.get_occurrence(finding)

    rcm_components = (
        c for c in cbom.components
        if c.crypto_properties.asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL
    )

    for existing in rcm_components:
        if utils.is_existing_occurrence_match(existing, new_occ):
            return existing
    return None



# def _update_existing_component(existing_component, component):
#     context = component.crypto_properties.detection_context[0]

#     if existing_context := utils.is_existing_occurrence_match(existing_component, context):
#         existing_context.additional_context = utils.merge_code_snippets(existing_context, context)
#         existing_context.line_numbers = existing_context.line_numbers.union(context.line_numbers)

#         for field in vars(component.crypto_properties.related_crypto_material_properties):
#             if not getattr(existing_component.crypto_properties.related_crypto_material_properties, field):
#                 field_value = getattr(component.crypto_properties.related_crypto_material_properties, field)
#                 setattr(existing_component.crypto_properties.related_crypto_material_properties, field, field_value)
#         return existing_component

def _update_existing_component(existing_component, component, finding):
    new_occ = utils.get_occurrence(finding)

    # 1️⃣  Var olan Occurrence’ı bul
    existing_occ = utils.is_existing_occurrence_match(existing_component, new_occ)

    if existing_occ:
        existing_occ.additional_context = utils.merge_code_snippets(
            existing_occ, new_occ
        )
        if hasattr(existing_occ, "line_numbers") and hasattr(new_occ, "line_numbers"):
            existing_occ.line_numbers |= new_occ.line_numbers
    else:
        existing_component.evidence.occurrences.add(new_occ)

    # 2️⃣  Metadata alanlarını zenginleştir
    old_props = existing_component.crypto_properties.related_crypto_material_properties
    new_props = component.crypto_properties.related_crypto_material_properties
    for field in vars(new_props):
        if not getattr(old_props, field):
            setattr(old_props, field, getattr(new_props, field))

    return existing_component
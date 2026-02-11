from cbom.cryptocheck import cryptocheck
from cbom.parser import algorithm


def test_validate_cbom_flags_aes_ecb(cbom, aes):
    algorithm.parse_algorithm(cbom, aes)

    sarif = cryptocheck.validate_cbom(cbom, enrich_cbom=False)
    results = sarif['runs'][0]['results']

    assert any(result['ruleId'] == 'AES-ECB-mode' for result in results)
    first = results[0]
    region = first['locations'][0]['physicalLocation']['region']
    assert 'snippet' in region and region['snippet']['text']

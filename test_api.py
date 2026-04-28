import sys
sys.path.append("scripts")
from parsers.vendor_advisory_parsers import ApiParser
from source_registry import SourceConfig
import logging
logging.basicConfig(level=logging.DEBUG)

s = SourceConfig({
    'id': 'msrc_advisory',
    'name': 'Microsoft MSRC',
    'region': 'GLOBAL',
    'category': 'product_vendor',
    'content_type': 'vendor_advisory',
    'source_quality': 'primary',
    'parser': 'api',
    'url': 'https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$orderby=releaseDate%20desc&$top=5',
    'enabled': True,
    'rate_limit_seconds': 5,
    'tags': ["microsoft"],
    'notes': "",
    'expected_fields': [],
    'safety_policy': "strict_no_poc"
})

p = ApiParser()
res = p.parse(s, 5)
print(len(res))

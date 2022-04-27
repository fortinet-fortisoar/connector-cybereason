""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError
import json
import copy
import validators

logger = get_logger('cybereason')

# Global var
DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
DEFAULT_SORT = 'ASC'
DEFAULT_TOTAL_RESULTS_LIMIT = 200
DEFAULT_PER_GROUP_LIMIT = 100
DEFAULT_PER_FEATURE_LIMIT = 100
DEFAULT_QUERY_TIMEOUT = 120000
LAST_X_MINUTES = 10

# Schemas
schemas = {
    'query_sensors': {
        'limit': DEFAULT_LIMIT,
        'offset': DEFAULT_OFFSET,
        'sortDirection': DEFAULT_SORT,
        'filters': []
    },
    'simple_query_generic_attributes': {
        'totalResultLimit': 200,
        'perGroupLimit': 100,
        'perFeatureLimit': 100,
        'templateContext': 'SPECIFIC',
        'queryTimeout': 120000
    },
    'query_user': {
        'queryPath': [
            {
                'requestedType': 'User',
                'filters': [],
                'isResult': True
            }
        ],
        'customFields': [
            'domain',
            'ownerMachine',
            'ownerOrganization.name',
            'ownerOrganization',
            'isLocalSystem',
            'elementDisplayName'
        ]
    },
    'query_file': {
        'queryPath': [
            {
                'requestedType': 'File',
                'filters': [],
                'isResult': True
            }
        ],
        'customFields': [
            'md5String',
            'ownerUser',
            'ownerMachine',
            'sha1String',
            'signatureVerified', 'avRemediationStatus',
            'maliciousClassificationType',
            'createdTime',
            'modifiedTime',
            'size',
            'correctedPath',
            'productName',
            'productVersion',
            'companyName',
            'internalName',
            'elementDisplayName',
            'isSigned'
        ]
    },
    'query_process': {
        "queryPath": [
            {
                "requestedType": "Process",
                "filters": [],
                "isResult": True
            }
        ],
        "customFields": [
            "elementDisplayName",
            "creationTime",
            "endTime",
            "commandLine",
            "productType",
            "children",
            "parentProcess",
            "ownerMachine",
            "calculatedUser",
            "imageFile",
            "knownMalwareSuspicion",
            "hasListeningConnection",
            "scanningProcessSuspicion",
            "tid",
            "iconBase64",
            "ransomwareAutoRemediationSuspended",
            "executionPrevented",
            "isWhiteListClassification",
            "matchedWhiteListRuleIds"
        ]
    },
    'white_blacklist': [
        {
            "keys": [],
            "maliciousType": "blacklist",
            "prevent": False,
            "remove": False
        }
    ]
}


# Utils
def sensor_payload_builder(params):
    '''
    Build POST payload for sensors calls
    '''
    payload = copy.deepcopy(schemas['query_sensors'])
    for param in params:
        if params[param] and param != 'operation':
            if 'filter.' in param:
                value = params[param] if isinstance(params[param], str) else str(params[param])
                payload['filters'].append({'fieldName': param.split('.')[1], 'operator': 'Equals', 'values': [value]})
            elif 'raw_filters' == param:
                payload['filters'].append(params[param])
            else:
                payload[param] = params[param]
    return payload


def simple_query_filter_builder(params):
    '''
    Build query filter
    '''
    filters = []
    for param in params:
        if params[param] and param != 'operation':
            if 'filter.filehash' in param:
                filters.append({'facetName': resolve_hash_type(params[param]),
                                'filterType': 'ContainsIgnoreCase', 'values': [params[param]]})
            elif 'filter.' in param:
                filters.append({'facetName': param.split('.')[1], 'values': [params[param]]})
            elif 'raw_filters' == param:
                filters.append(params[param])
    return filters


def simple_query_builder(operation,
                         params,
                         per_group_limit=DEFAULT_PER_GROUP_LIMIT,
                         per_feature_limit=DEFAULT_PER_FEATURE_LIMIT,
                         total_results_limit=DEFAULT_TOTAL_RESULTS_LIMIT,
                         template_context='SPECIFIC'):
    '''
    Builds query's JSON body
    '''
    query = copy.deepcopy(schemas[operation])
    query.update(copy.deepcopy(schemas['simple_query_generic_attributes']))

    query['queryPath'][0]['filters'] = simple_query_filter_builder(params)
    query['perGroupLimit'] = per_group_limit
    query['perFeatureLimit'] = per_feature_limit
    query['totalResultLimit'] = total_results_limit
    query['templateContext'] = template_context

    payload = json.dumps(query)
    try:
        query = json.loads(payload)
    except Exception as e:
        logger.exception('Invalid input query data: {}'.format(e))
        raise ConnectorError('Invalid input query data: {}'.format(e))
    finally:
        return query


def resolve_hash_type(hash):
    '''
    lookup hash type
    '''
    if len(hash) == 32:
        return 'md5String'
    elif len(hash) == 40:
        return 'sha1String'
    else:
        logger.exception('Invalid Hash Code: {}'.format(hash))
        raise ConnectorError('Invalid Hash Code: {}'.format(hash))


def white_blacklist_body_builder(params):
    '''
    Builds whitelist/blacklist operations JSON body
    '''
    operation = params.get('operation').split('_')
    keys = params.get('keys').strip()
    remove = params.get('remove') if not None else False
    prevent = params.get('prevent')
    payload = copy.deepcopy(schemas['white_blacklist'])
    keys = keys.split(',') if ',' in keys else [keys]

    # Validators
    for item in keys:
        if 'file' in operation:
            resolve_hash_type(item)
        else:
            if not validators.domain(item) and not validators.ipv4(item) and not validators.ipv6(item):
                logger.exception('Invalid Entry: {}'.format(item))
                raise ConnectorError('Invalid Entry: {}'.format(item))

    payload[0]['keys'] = keys
    payload[0]['maliciousType'] = operation[0]
    payload[0]['remove'] = remove
    payload[0]['prevent'] = True if 'file' in operation and prevent is True and remove is False else False
    return payload

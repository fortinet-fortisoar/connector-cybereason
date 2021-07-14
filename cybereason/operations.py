""" Operations """
from .utils import *
from connectors.core.connector import get_logger, ConnectorError

import requests
import logging
import arrow
import jmespath

logger = get_logger('Cybereason')

class CybereasonMC(object):
    def __init__(self, config):
        self.url = config.get('server').strip()   
        if not self.url.startswith('https://'):
            self.url = 'https://' + self.url
        if self.url[-1] == '/':
            self.url = self.url[:-1]
        self.username = config['username']
        self.password = config['password']        
        self.verify_ssl = config['verify_ssl']
        self.headers = {
            'Content-Type': 'application/json',
            'Connection': 'close'
        }
        self.session = requests.session()
        self.login()


    def close(self):
        '''
        Closes the session before exit
        '''
        return self.make_rest_call(endpoint='/logout',method='GET')


    def login(self):
        '''
        Credentials login
        #TODO: implement certificate based authentication
        '''
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'close'
        }
        data = {
            'username': self.username,
            'password': self.password
        }
        return self.make_rest_call(endpoint='/login.html', data=data, headers=headers)


    def make_rest_call(self, endpoint, json=None,data=None,headers=None,params=None,method='POST'):
        '''
        Requests wrapper
        '''
        try:
            response = self.session.request(method,
                                            url=self.url + endpoint,
                                            headers=headers or self.headers,
                                            json=json,
                                            data=data,
                                            params=params,
                                            #proxies={'https':'http://127.0.0.1:8080'}, # debug requests via mitmproxy
                                            verify=self.verify_ssl)

            if response.status_code in [200]:
                try:
                    response_data = response.json()
                    return {'status': response_data['status'] if 'status' in response_data else 'Success', 'data': response_data}
                except Exception as e:
                    response_data = response.content
                    return {'status':'Failure','data':response_data}

            else:
                raise ConnectorError({'status':'Failure','status_code':str(response.status_code),'response':response.content})

        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


    def get_sensors(self,params):
        '''
        Get all or a filtered group of sensors
        '''
        json_body = sensor_payload_builder(params)
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/sensors/query', json=json_body)


    def get_malops(self,params):
        '''
        Get all Malops within a time range
        time format:
        2021-06-22T10:00:38.476Z
        2021-06-22T17:26:38.476Z
        '''
        start_time = arrow.get(params.get("start_time")).int_timestamp * 1000 if params.get("start_time") else arrow.now().shift(minutes=-LAST_X_MINUTES).int_timestamp * 1000
        end_time = arrow.get(params.get("end_time")).int_timestamp * 1000 if params.get("end_time") else arrow.now().int_timestamp * 1000
        json_body = {"startTime":start_time, "endTime":end_time}
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/detection/inbox', json=json_body)


    def query_user(self,params):
        '''
        Query user via username
        '''
        operation = params.get('operation')
        json_body = simple_query_builder(operation,params)
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/visualsearch/query/simple', json=json_body)


    def query_file(self,params):
        '''
        Query a file by its hashcode (md5/sha1)
        '''
        operation = params.get('operation')
        json_body = simple_query_builder(operation, params)
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/visualsearch/query/simple', json=json_body)


    def query_process(self,params):
        '''
        Find processes by its name
        '''
        #TODO: fix json query
        operation = params.get('operation')
        json_body = simple_query_builder(operation, params)
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/visualsearch/query/simple', json=json_body)


    def _sensor_isolation_by_pylum_id(self,params,endpoint):
        '''
        Isolates/Un-isolate a sensor via its Pylum ID
        '''
        pylum_ids = params.get('pylumIds')
        pylum_ids = pylum_ids.split(',') if ',' in pylum_ids else [pylum_ids]
        json_body = {
            'pylumIds': pylum_ids
        }
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint=endpoint, json=json_body)


    def isolate_sensor_by_pylum_id(self,params):
        '''
        Isolates a sensor via its Pylum ID
        '''
        return self._sensor_isolation_by_pylum_id(params,'/rest/monitor/global/commands/isolate')


    def unisolate_sensor_by_pylum_id(self,params):
        '''
        Un-isolate a sensor via its Pylum ID
        '''
        return self._sensor_isolation_by_pylum_id(params,'/rest/monitor/global/commands/un-isolate')


    def _sensor_isolation_by_ip(self,params,endpoint):
        '''
        Isolates/Un-isolate a sensor using its internal IP address
        '''
        ip_addresses = params.get('ip_addresses')
        ip_addresses = ip_addresses.split(',') if ',' in ip_addresses else [ip_addresses]
        json_body = copy.deepcopy(schemas['query_sensors'])
        json_body['filters'].append({"fieldName": "internalIpAddress","operator": "Equals","values": ip_addresses})
        pylum_ids = self.make_rest_call(endpoint='/rest/sensors/query', json=json_body)
        if 'sensors' in pylum_ids['data'] and len(pylum_ids['data']['sensors']) > 0:
            pylum_ids = jmespath.search('sensors[].pylumId',pylum_ids['data'])
            return self._sensor_isolation_by_pylum_id({'pylumIds': ','.join(pylum_ids)},endpoint)
        else:
            return {'status': 'Failure', 'Reason': 'IP Address(s) not found'}

    def isolate_sensor_by_ip(self,params):
        '''
        Isolates a sensor using its internal IP address
        '''
        return self._sensor_isolation_by_ip(params,'/rest/monitor/global/commands/isolate')


    def unisolate_sensor_by_ip(self,params):
        '''
        Un-isolate a sensor using its internal IP address
        '''
        return self._sensor_isolation_by_ip(params,'/rest/monitor/global/commands/un-isolate')

    def kill_process(self,params):
        '''
        Kill a process identified by process_id on machine_id
        '''
        machine_guid = str(params.get('machine_guid'))
        process_guid = str(params.get('process_guid'))
        json_body = {
            "initiatorUserName": self.username,
            "actionsByMachine": {
                machine_guid: [
                    {
                        "targetId": process_guid,
                        "actionType": "KILL_PROCESS"
                    }
                ]
            }
        }
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/remediate', json=json_body)


    def white_blacklist(self,params):
        '''
        Whitelist and Blacklist Hashes, IPs and Domains organization wide
        '''
        json_body = white_blacklist_body_builder(params)
        logger.debug('JSON Body: {}'.format(json_body))
        return self.make_rest_call(endpoint='/rest/classification/update', json=json_body)


    def blacklist_file(self,params):
        '''
        wrapper for white_blacklist
        '''
        return self.white_blacklist(params)


    def whitelist_file(self,params):
        '''
        wrapper for white_blacklist
        '''
        return self.white_blacklist(params)


    def blacklist_ip_or_domain(self,params):
        '''
        wrapper for white_blacklist
        '''
        return self.white_blacklist(params)


    def whitelist_ip_or_domain(self,params):
        '''
        wrapper for white_blacklist
        '''
        return self.white_blacklist(params)


def _run_operation(config,params):
    '''
    Map operations to Cybereason methods
    '''
    operation = params['operation']
    cr_object = CybereasonMC(config)
    command = getattr(CybereasonMC,operation)
    response = command(cr_object,params)
    cr_object.close()
    return response


def _check_health(config):
    '''
    Test service availability with a login/logoff
    '''
    try:
        cr_object = CybereasonMC(config)
        server_config = cr_object.make_rest_call(endpoint='/rest/settings/configurations', method='GET')
        cr_object.close()
        if server_config['status'] == 'Failure':
            logger.exception('Authentication Error, Check URL and Credentials')
            raise ConnectorError('Authentication Error, Check URL and Credentials')

    except Exception as Err:
        logger.exception('Health Check Error:{}'.format(Err))
        raise ConnectorError('Health Check Error:{}'.format(Err))    


""" Connector """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
logger = get_logger('cybereason')


class Cybereason(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            params.update({"operation":operation})              
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.error('Cybereason:{}'.format(err))
            raise ConnectorError('Cybereason:{}'.format(err))


    def check_health(self, config):
        return _check_health(config)
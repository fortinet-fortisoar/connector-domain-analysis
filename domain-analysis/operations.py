import arrow
import os
import whodap
import validators
import tldextract
from tranco import Tranco
from connectors.core.connector import get_logger, ConnectorError
from .freq.freq import *


logger = get_logger('domain_analysis')
CACHE_DIR = '/tmp'
FREQTABLE = os.path.dirname(os.path.realpath(__file__)) + '/freq/freqtable.freq'


def analyze_domain(config, params):
    try:
        domain = params.get('domain')
        fc = FreqCounter()
        fc.load(FREQTABLE)
        total_word_probability, average_probability = fc.probability(domain)
        return {'Total Word Probability': total_word_probability, 'Average Probability': average_probability}

    except Exception as exp:
        logger.exception('Error Executing Code: {}'.format(exp))
        raise ConnectorError('Error Executing Code: {}'.format(exp))

def get_domain_popularity(config, params):
    try:
        domain = params.get('domain')
        list_date = params.get('list_date', None)
        list_date = arrow.get(list_date).format("YYYY-MM-DD") if list_date else None
        tranco = Tranco(cache=True, cache_dir=CACHE_DIR)
        date_list = tranco.list()
        if list_date:
            cache_file = tranco._cache_path(date_list.list_id)
            logger.debug('Deleting old cache file: {}'.format(cache_file))
            os.remove(cache_file)
            tranco = Tranco(cache=True, cache_dir=CACHE_DIR)
            logger.debug('Loading domains list for: {}'.format(list_date))
            date_list = tranco.list(date=list_date)

        return date_list.rank(domain)

    except Exception as exp:
        logger.exception('Error Executing Code: {}'.format(exp))
        raise ConnectorError('Error Executing Code: {}'.format(exp))


def whois(config, params):
    input_value = params.get('input_value')

    try:
        if ( isinstance(input_value, int) or input_value.isdigit() ) and validators.between(int(input_value), min=1, max=64495):
            logger.debug('Whois ASN: {}'.format(input_value))
            response = whodap.lookup_asn(int(input_value))
        elif validators.ipv4(input_value):
            logger.debug('Whois IPv4: {}'.format(input_value))
            response = whodap.lookup_ipv4(input_value)
        elif validators.ipv6(input_value):
            logger.debug('Whois IPv6: {}'.format(input_value))
            response = whodap.lookup_ipv6(input_value)
        elif validators.domain(input_value):
            logger.debug('Whois Domain: {}'.format(input_value))
            domain_attr = tldextract.extract(input_value)
            response = whodap.lookup_domain(domain=domain_attr[1], tld=domain_attr[2])

        else:
            logger.exception('{} did not match a domain name, IP address or ASN'.format(input_value))
            raise ConnectorError('{} did not match a domain name, IP address or ASN'.format(input_value))
        return response.to_dict()

    except Exception as exp:
        logger.exception('Whois Error: {}'.format(exp))
        raise ConnectorError('Whois Error: {}'.format(exp))

def get_domain_report(config, params):
    try:
        report = {
            'Popularity': get_domain_popularity(config, params),
            'DGA': analyze_domain(config, params),
            'Whois': whois(config, {'input_value': params.get('domain')})
        }
        return report
    except Exception as exp:
        logger.exception('Error Executing Code: {}'.format(exp))
        raise ConnectorError('Error Executing Code: {}'.format(exp))


def _check_health(config):
    try:
        params = {'domain': 'fortinet.com'}
        get_domain_popularity(config, params)
    except:
        logger.exception('Python module(s) not found')
        raise ConnectorError('Python module(s) not found')


operations = {
    'analyze_domain': analyze_domain,
    'get_domain_popularity': get_domain_popularity,
    'whois': whois,
    'get_domain_report': get_domain_report
}

import argparse
import csv
import json
import socket
import subprocess
from pymongo import MongoClient
from elasticsearch import Elasticsearch, serializer, compat, exceptions
from datetime import datetime, timedelta
import pytz

class JSONSerializerPython2(serializer.JSONSerializer):
    def dumps(self, data):
        if isinstance(data, compat.string_types):
            return unicode(data).decode("utf-8", errors='ignore')
        try:
            return unicode(
                json.dumps(
                    data,
                    default=self.default,
                    ensure_ascii=True)).decode(
                "utf-8",
                errors='ignore')
        except (ValueError, TypeError) as e:
            raise exceptions.SerializationError(data, e)

class MongoDB:
    def __init__(self):
        process = subprocess.Popen(
            ["sudo /usr/local/bin/wsc -c 'cluster list mongo' | /bin/grep 'mongodb://' | /usr/bin/awk '{print $2}'"],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        mongo_uri = process.stdout.readline().strip()
        self.client = MongoClient(mongo_uri)
        self.db = self.client['waf']

    def fetch_all(self, collection_name, filter = {}, excluded_fields = []):
        res = []
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                    excluded[field] = False
            if excluded:
                    db_iterator = storage.find(filter, excluded)
            else:
                    db_iterator = storage.find(filter)
            for doc in db_iterator:
                    res.append(doc)
        return res

    def fetch_one(self, collection_name, filter = {}, excluded_fields = []):
        res = {}
        collections = self.db.collection_names()
        if collection_name in collections:
            storage = self.db[collection_name]
            excluded = {}
            for field in excluded_fields:
                excluded[field] = False
            if excluded:
                res = storage.find_one(filter, excluded)
            else:
                res = storage.find_one(filter)
        return res

    def get_webapp_by_name(self, name):
        return self.fetch_one('web_apps', {'name': name})

    def get_policy_by_id(self, policy_id):
        return self.fetch_one('policies', {'_id': policy_id})

class ES:
    def __init__(self):
        process = subprocess.Popen(
            ["sudo /usr/local/bin/wsc -c 'password list'"],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        passwd = process.stdout.readline().strip()
        host = socket.gethostname()
        self.db = Elasticsearch(
            ['http://{}:9200'.format(host)],
            serializer=JSONSerializerPython2(),
            http_auth=("root", passwd))

    def fetch_all(self, query, fields=[]):
            res = []
            if fields:
                 resp = self.db.search(index="attacks", size=1000000, body=query, _source=fields)
            else:
                resp = self.db.search(index="attacks", size=1000000, body=query)
            for doc in resp['hits']['hits']:
                    o = doc['_source']
                    res.append(o)
            return res


def parse_cli_args(test_data=""):
    parser = argparse.ArgumentParser(description='Export data from PT AF')
    parser.add_argument('-w', '--webapp',
                        action='store',
                        dest='WEBAPP_NAME',
                        default='Any',
                        required=False,
                        help='webapp name')
    parser.add_argument('--range', '-r',
                        dest='RANGE',
                        type=int,
                        required=False,
                        default=7,
                        action='store',
                        help='Data range in days from start date')
    parser.add_argument('--end_date', '-e',
                        dest='END_DATE',
                        required=False,
                        default=datetime.today().date(),
                        type=lambda s: ((datetime.today().date()+timedelta(days=1)) if s == 'today' else datetime.strptime(s, '%Y-%m-%d').date()),
                        action='store',
                        help='End of exported timeframe, in YYYY-MM-DD form (e.g. 2020-05-01) or just "today"')

    if test_data:
        args = parser.parse_args(test_data)
    else:
        args = parser.parse_args()

    args.START_DATE = args.END_DATE - timedelta(days=args.RANGE)

    return args


class Run:
    def __init__(self, args, mongo=MongoDB(), es=ES()):
        tz = pytz.timezone("Europe/Moscow")  # Change in needed
        self.start_date = tz.localize(datetime.combine(args.START_DATE, datetime.min.time()))
        self.range = args.RANGE
        self.end_date = tz.localize(datetime.combine(args.END_DATE, datetime.min.time()))
        self.webapp_name = args.WEBAPP_NAME
        self.webapp = {}
        self.policy = {}
        self.actions = []
        self.mongo = mongo
        self.elasticsearch = es
        self.action_modes = {100:   'block_request',
                             90:    'block_ip',
                             80:    'block_session',
                             70:    'sanitize',
                             60:    'monitoring',
                             50:    'count',  #  e.g. sent to correlator, but not logged
                             #1:     'hidden', #  Means no action
                             0:     'unknown',
                             -1:    'n/a'}
        self.action_types = {'block_ip':            90,
                             'custom_response':     100,
                             'email':               60,
                             'log':                 60,
                             'modify_content':      70,
                             'send_to_arbor':       90,
                             'send_to_blacklist':   90,
                             'send_to_checkpoint':  90,
                             'send_to_corr':        50,
                             'send_to_infotecs':    90,
                             'send_to_qrator':      90,
                             'snmpv3':              60,
                             'suspect_session':     80,
                             'syslog':              60,
                             'tcp_rst':             100}
        self.protectors = [
            {'db_name': 'HTTPProtector',          'ui_name': 'HTTP Protector',            'nickname': 'http'},
            {'db_name': 'HMMProtector',           'ui_name': 'HMM Protector',             'nickname': 'hmm'},
            {'db_name': 'CSRFProtector',          'ui_name': 'CSRF Protector',            'nickname': 'csrf'},
            {'db_name': 'DDoSProtector',          'ui_name': 'DDoS Protector',            'nickname': 'ddos'},
            {'db_name': 'SQLiProtector',          'ui_name': 'SQL Injection Protector',   'nickname': 'sqlinjection'},
            {'db_name': 'XSSProtector',           'ui_name': 'XSS Protector',             'nickname': 'xss'},
            {'db_name': 'OpenRedirectProtector',  'ui_name': 'Open Redirect Protector',   'nickname': 'openredirect'},
            {'db_name': 'XMLProtector',           'ui_name': 'XML Protector',             'nickname': 'xml'},
            {'db_name': 'ICAPProtector',          'ui_name': 'ICAP Protector',            'nickname': 'icap'},
            {'db_name': 'RuleEngine',             'ui_name': 'Rule Engine',               'nickname': 'rule-engine'},
            {'db_name': 'CSPProtector',           'ui_name': 'CSP Protector',             'nickname': 'csp'},
            {'db_name': 'ResponseFilter',         'ui_name': 'Response Filter',           'nickname': 'response-filter'},
            {'db_name': 'WafJsProtector',         'ui_name': 'WafJS',                     'nickname': 'wafjs'},
            {'db_name': 'AuthOracle',             'ui_name': 'ACL Protector',             'nickname': 'auth-oracle'},
            {'db_name': 'AuthLDAP',               'ui_name': 'LDAP Protector',            'nickname': 'auth-ldap'},
            {'db_name': 'BlacklistProtector',     'ui_name': 'Blacklist Protector',       'nickname': 'ip'},
            {'db_name': 'SessionCookieProtector', 'ui_name': 'Session Tracking',          'nickname': 'session'},
            {'db_name': 'JSONProtector',          'ui_name': 'JSON Protector',            'nickname': 'json'},
            {'db_name': 'RVPProtector',           'ui_name': 'RVP Protector',             'nickname': 'rvp'},
            {'db_name': 'ScriptEngine',           'ui_name': 'Script Engine',             'nickname': 'script-engine'}
        ]
        self.event_fields = [
            "TICKET_ID",
            "TIMESTAMP",
            "EVENT_SEVERITY",
            "EVENT_ID",
            "CLIENT_IP",
            "CLIENT_COUNTRY_CODE",
            "CLIENT_COUNTRY_NAME",
            "CLIENT_BROWSER"
        ]

    def bootstrap(self):
        self.webapp = self.mongo.get_webapp_by_name(self.webapp_name)
        self.policy = self.mongo.get_policy_by_id(self.webapp["policy_id"])
        self.actions = self.mongo.fetch_all('actions')

    def get_meta(self):
        return [{"policy": self.policy["name"],
                 "webapp": self.webapp_name,
                 "webapp_id": self.webapp['_id'],
                 "start_date": self.start_date,
                 "end_date": self.end_date,
                 "range": self.range}]

    def get_protectors(self):
        res = list()
        for protector in self.protectors:
            if protector['db_name'] in self.policy.keys():
                res.append({'name': protector['ui_name'],
                            'nickname': protector['nickname'],
                            'enabled': self.policy[protector['db_name']]['enabled']})
        return res

    def get_mode_for_action(self, action_id):
        action_found = {}
        for action in self.actions:
            if action['_id'] == action_id:
                action_found = action
                break
        if action_found:
            if action_found['type'] in self.action_types.keys():
                return self.action_types[action_found['type']]
            else:
                return 0  # action found, but its mode unknown
        else:
            return -1  # n/a

    def get_effective_mode_for_rule(self, rule):
        rule_actions = list()
        policy_id = self.policy['_id']

        for policy in rule['custom_policies']:  # Check if custom actions are defined for the policy
            if policy['policy'] == policy_id:
                rule_actions = policy['actions']
        if not rule_actions:  # Use default actions if no custom actions are defined
            rule_actions = rule['actions']

        mode = -1
        for action_id in rule_actions:
            action_mode = self.get_mode_for_action(action_id)
            if action_mode > mode:
                mode = action_mode

        return self.action_modes[mode]

    def get_rules(self):
        res = list()
        rules = self.mongo.fetch_all('rules', {'policies': self.policy['_id']})
        for rule in rules:
            res.append({'name': rule['name'],
                        'protector': rule['protector'],
                        'enabled': rule['enabled'],
                        'mode': self.get_effective_mode_for_rule(rule)})

        return res

    def get_events(self):
        events = self.elasticsearch.fetch_all(
            {"query": {
                "filtered": {
                    "query": {
                        "bool": {
                            "should": [{"query_string": {"query": "_type:attack"}}]
                        }
                    },
                    "filter": {
                        "bool": {
                            "must": [
                                {"range": {"TIMESTAMP": {"from": self.start_date, "to": self.end_date}}},
                                {"missing": {"field": "_exclude"}},
                                {"terms": {"APPLICATION_ID.raw": [str(self.webapp['_id'])]}}
                            ]
                        }
                    }
                }
            }},
            self.event_fields)

        return events

    def store_as_csv(self, data, filename):
        data_file = open(filename, "w")
        if data:
            data_csv = csv.writer(data_file)
            data_csv.writerow(data[0].keys())
            for o in data:
                row = [s.encode('utf-8') if type(s) == str else s for s in o.values()]
                data_csv.writerow(row)
        data_file.close()


if __name__ == "__main__":
    r = Run(parse_cli_args())
    r.bootstrap()

    # Get meta
    meta = r.get_meta()

    # Get data
    protectors = r.get_protectors()
    rules = r.get_rules()
    events = r.get_events()

    # Dump to files
    r.store_as_csv(meta, 'meta.csv')
    r.store_as_csv(protectors, 'protectors.csv')
    r.store_as_csv(rules, 'rules.csv')
    r.store_as_csv(events, 'events.csv')

    print("DONE!")




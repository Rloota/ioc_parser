#!/usr/bin/env python

import os
import sys
import csv
import json
from pymisp import ExpandedPyMISP

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

import io
import iocp


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
OUTPUT_FORMATS = ('csv', 'tsv', 'json', 'yara', 'netflow', 'misp' )


def getHandler(output_format, misp_event):

	#quick hacky global variable to access misp_event inside OutputHandler_misp class.
    global g_misp_event
    g_misp_event = misp_event
    if output_format == 'misp' and misp_event == None:
        e = "Valid MISP event ID required for MISP output."
        raise ValueError(e)

    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified... using CSV")
        output_format = 'csv'

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class()


class OutputHandler(object):
    def print_match(self, fpath, page, name, match):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        print("[ERROR] %s" % (exception))


class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

    # Added flag and sheet which are unused but needed to make CSV output work
    def print_match(self, fpath, page, name, match, flag, sheet=''):
        self.csv_writer.writerow((fpath, page, name, match, sheet))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))

class OutputHandler_tsv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter = '\t', quoting=csv.QUOTE_NONNUMERIC)

    def print_match(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))


class OutputHandler_json(OutputHandler):    
    def print_match(self, fpath, page, name, match, flag, sheet=''):
        """ @param flag:
            0 = default (pdf/txt/html)
            1 = gmail
            2 = csv
            3 = xls and xlsx
        @param sheet    The sheet being parsed if Excel spreadsheet (single or multi-sheet)
        """
        if flag == 0 or flag == 2:
            data = {
                'path' : fpath,
                'file' : os.path.basename(fpath),
                'page' : page,
                'type' : name,
                'match': match
            }
        elif flag == 1:
            data = {
                'input' : 'gmail',
                'subject' : fpath,
                'type' : name,
                'match': match
            }
        elif flag == 3:
            data = {
                'path' : fpath,
                'file' : os.path.basename(fpath),
                'sheet' : sheet,
                'line' : page,
                'type' : name,
                'match': match,
            }
        print(json.dumps(data))

    def print_error(self, fpath, exception):
        data = {
            'path'      : fpath,
            'file'      : os.path.basename(fpath),
            'type'      : 'error',
            'exception' : exception
        }

        print(json.dumps(data))


class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    # Added flag and sheet which are unused but needed to make YARA output work
    def print_match(self, fpath, page, name, match, flag, sheet=''):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1

        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace('\\', '\\\\')
        print("\t\t%s = \"%s\"" % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = ' or '.join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")


class OutputHandler_netflow(OutputHandler):
    def __init__(self):
        print("host 255.255.255.255")

    # Added flag and sheet which are unused but needed to make Netflow output work
    def print_match(self, fpath, page, name, match, flag, sheet=''):
        data = {
            'type' : name,
            'match': match
        }

        if data["type"] == "IP":
            print(" or host %s " % data["match"])

class OutputHandler_misp(OutputHandler):

	def print_match(self, fpath, page, name, match, flag, sheet=''):
		#Read misp API key, address and cert value from misp_keys.ini
		config = ConfigParser()
		config.read(os.path.join(iocp.get_basedir(), 'data/misp_keys.ini'))

		misp = ExpandedPyMISP(config.get('misp', 'misp_url'), config.get('misp', 'misp_key'), False)
		data = {
			'path' : fpath,
			'file' : os.path.basename(fpath),
			'page' : page,
			'type' : name,
			'match': match
		}

		data_type = data['type']
		data_match = data['match']
		event_id = g_misp_event


		if data_type == 'URL':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'url','value': data_match})

		elif data_type == 'IP':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'ip-src','value': data_match})

		elif data_type == 'Email':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'email-src','value': data_match})

		elif data_type == 'MD5':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'md5','value': data_match})

		elif data_type == 'SHA1':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'sha1','value': data_match})

		elif data_type == 'SHA256':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'sha256','value': data_match})

		elif data_type == 'CVE':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'vulnerability','value': data_match})

		elif data_type == 'Registry':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'regkey','value': data_match})

		elif data_type == 'Filename':
			print("Importing to MISP ioc %s" %(data_match))
			misp.add_attribute(event_id,{'type': 'filename','value': data_match})

		else:
			print("Data type: %s not supported by the script" %(data_type))
# IMPORTANT: This Script is not suitable for production environments !
# IMPORTANT: This Script is just a MOCUKP and it is not performant at all !
# IMPORTANT: I am not accepting criticism on such piece of code since it has been written in Hurry just to make it works

# If you want to know more about what this script does please visit: http://marcoramilli.com
# You might decide to use this script to generate from a CuckooSandbo machine a
# MIST (modified) report in order to use it to you AI engine

import os
import subprocess
import hashlib
import urllib
import random
import string
import glob
import threading
import json
import gzip
import sys
import time
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
import traceback

log = logging.getLogger()

class MistJson(Report):
    """Converts reports on MIST JSON to produce features for Prediction IO"""

    def sanitize_file(self, filename):
        normals = filename.lower().replace('\\', ' ').replace('.', ' ').split(' ')
        hashed_components = [
            hashlib.md5(normal).hexdigest()[:8] for normal in normals[-3:]]
        return hashed_components


    def sanitize_reg(self, keyname):
        normals = keyname.lower().replace('\\', ' ').split(' ')
        hashed_components = [
            hashlib.md5(normal).hexdigest()[:8] for normal in normals[-2:]]
        return hashed_components


    def sanitize_cmd(self, cmd):
        normals = cmd.lower().replace('"', '').replace(
            '\\', ' ').replace('.', ' ').split(' ')
        hashed_components = [
            hashlib.md5(normal).hexdigest()[:8] for normal in normals]
        return hashed_components


    def sanitize_generic(self, value):
        return [hashlib.md5(value.lower()).hexdigest()[:8]]


    def sanitize_domain(self, domain):
        components = domain.lower().split('.')
        hashed_components = [
            hashlib.md5(comp).hexdigest()[:8] for comp in components]
        return hashed_components


    def sanitize_ip(self, ipaddr):
        components = ipaddr.split('.')
        class_c = components[:3]
        return [hashlib.md5('.'.join(class_c)).hexdigest()[:8],
                hashlib.md5(ipaddr).hexdigest()[:8]]


    def sanitize_url(self, url):
        # normalize URL according to CIF specification
        uri = url
        if ":" in url:
            uri = url[url.index(':') + 1:]
	if not isinstance(uri, list):
            uri = uri.strip("/")
	else:
	    uri_2 = ",".join(uri)
	    uri = uri_2

        quoted = urllib.quote(uri.encode('utf8')).lower()
        return [hashlib.md5(quoted).hexdigest()[:8]]


    def insert_into_json(self, json_result, key, values):
        new_set = set(values)
        if key not in json_result:
            json_result[key] = new_set
        else:
            json_result[key] |= new_set


    def try_iterate(self, results, *paths):
        try:
            for entry in paths:
                results = results[entry]
            for el in results:
                yield el
        except:
            return


    def mist_convert(self, results):
        """ Performs conversion of analysis results to MIST format """
        json_result = {}
        analysis_id = results["info"]["id"]
        log.info("[+] Working on converting id= " + str(analysis_id))

        for entry in self.try_iterate(results, "behavior", "summary", "files"):
           self.insert_into_json(json_result, "file_access", self.sanitize_file(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "write_files"):
            self.insert_into_json(json_result, "file_write", self.sanitize_file(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "delete_files"):
            self.insert_into_json(json_result, "file_delete", self.sanitize_file(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "read_files"):
            self.insert_into_json(json_result, "file_read", self.sanitize_file(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "keys"):
            self.insert_into_json(json_result, "reg_access", self.sanitize_reg(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "read_keys"):
            self.insert_into_json(json_result, "reg_read", self.sanitize_reg(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "write_keys"):
            self.insert_into_json(json_result, "reg_write", self.sanitize_reg(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "delete_keys"):
            self.insert_into_json(json_result, "reg_delete", self.sanitize_reg(entry))
        for entry in self.try_iterate(results, "behavior", "summary",
                                 "executed_commands"):
            self.insert_into_json(json_result, "cmd_exec", self.sanitize_cmd(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "resolved_apis"):
            self.insert_into_json(json_result, "api_resolv", self.sanitize_generic(entry))
        for entry in self.try_iterate(results, "behavior", "summary", "mutexes"):
            self.insert_into_json(json_result, "mutex_access", self.sanitize_generic(entry))
        for entry in self.try_iterate(results, "behavior", "summary",
                                 "created_services"):
            self.insert_into_json(json_result, "service_create",
                             self.sanitize_generic(entry))
        for entry in self.try_iterate(results, "behavior", "summary",
                                 "started_services"):
            self.insert_into_json(json_result, "service_start", self.sanitize_generic(entry))

        for entry in self.try_iterate(results, "signatures"):
            if "virustotal" in entry["name"]:
                continue
            signame = "sig_" + entry["name"].lower().replace(' ', '_')
            for res in self.try_iterate(entry, "data"):
                try:
                    for key, value in res.items():
                        if isinstance(value, basestring):
                            lowerval = value.lower()
                            sanitized = None
                            if lowerval.startswith("hkey"):
                                sanitized = self.sanitize_reg(value)
                            elif lowerval.startswith("c:"):
                                sanitized = self.sanitize_file(value)
                            else:
                                sanitized = self.sanitize_generic(value)
                            self.insert_into_json(json_result, signame, sanitized)
                except:
                    pass

        for host in self.try_iterate(results, "network", "hosts"):
            if "country_name" in host:
                self.insert_into_json(
                    json_result, "net_con", self.sanitize_generic(host["country_name"]))
            if "ip" in host:
                self.insert_into_json(json_result, "net_con", self.sanitize_ip(host["ip"]))

        for domain in self.try_iterate(results, "network", "domains"):
            self.insert_into_json(
                json_result, "net_dns", self.sanitize_domain(domain["domain"]))

        for req in self.try_iterate(results, "network", "http"):
            self.insert_into_json(json_result, "net_http", self.sanitize_url(req["uri"]))

        for req in self.try_iterate(results, "network", "mitm", "requests"):
            self.insert_into_json(json_result, "net_mitm", self.sanitize_url(req["url"]))

        for dropped in self.try_iterate(results, "dropped"):
            if "size" in dropped and "type" in dropped:
                self.insert_into_json(json_result, "file_drop",
                                 list(map(
                                     lambda el:
                                     "%08x_%s" % (int(dropped["size"]) &
                                                  0xfffffc00, el),
                                     self.sanitize_generic(dropped["type"]))))

        for key, value in json_result.items():
          json_result[key] = ' '.join(value)
        return json_result


    def run(self, results):
	""""
            Writes features:
    	    @param results: results dictionary.
	        @raise CuckooReportError: if it fails to parse results.
  	"""

        mistjson = self.options.get("enabled", True)
        analyses_home = self.options.get("analyses_home", "/analyses/")

  	if mistjson:
	    mts_id = results["info"]["id"]
            path       = os.path.join(analyses_home, str(mts_id), "reports", "mist.json.gzip")
	    try:
                mist_json = self.mist_convert(results)
                if len(mist_json) > 0:
            	    log.info( "[+] Saving mist report for %s " % mts_id)
    		    with gzip.open(path, 'wb') as outfile:
    		        json.dump(mist_json, outfile, sort_keys=True,indent=2, ensure_ascii=False)
	    except Exception as e:
	        log.error("Error in feature extraction for %s, error is: %s" % (mts_id, e))


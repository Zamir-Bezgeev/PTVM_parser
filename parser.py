'''
Install: Put folder pt_vm to dojo/tools/
Requirements for the report you are uploading to the system:
    Type:csv, delimiter=';'
    Required fields:@Host,host.@Vulners.CVEs,host.@vulners.Description,host.@vulners.HowToFix,host.@Id,host.@vulners.SeverityRating,host.@vulners.CVSS3BaseScore,host.IpAddress
'''

import csv
import hashlib
import io

from cvss import parser as cvss_parser
from dateutil import parser
from dojo.models import Finding, Endpoint


class PTVMParser(object):

    def get_scan_types(self):
        return ["PT VM"]

    def get_label_for_scan_types(self, scan_type):
        return "PT VM"

    def get_description_for_scan_types(self, scan_type):
        return "PT VM CSV format"

    def get_findings(self, filename, test):
        if filename is None:
            return list()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content), delimiter=';', quotechar='"', fieldnames = None , restkey = None)
        csvarray = []

        dupes = dict()

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            finding.title = row['@Host'] + ' - ' + row['host.@Vulners.CVEs']
            finding.description = row['host.@vulners.Description']
            finding.mitigation = row['host.@vulners.HowToFix']
            finding.references = row['host.@Id']
            finding.severity = row['host.@vulners.SeverityRating'].title()
            finding.unsaved_vulnerability_ids = [row['host.@Vulners.CVEs']]
            finding.cvssv3_score = row['host.@vulners.CVSS3BaseScore'].replace(",", ".")
            finding.unsaved_endpoints = [
                    Endpoint(
                        host=row['host.IpAddress'],
                    )
                ]
            
            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.md5((finding.title + '|' + finding.description).encode("utf-8")).hexdigest()

                if key not in dupes:
                    dupes[key] = finding

        return list(dupes.values())

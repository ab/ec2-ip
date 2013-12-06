#!/usr/bin/env python

# supply input on stdin from https://forums.aws.amazon.com/ann.jspa?annID=1701

import re
import sys
import yaml

from datetime import datetime

region_codes = {
    'US East (Northern Virginia)': 'us-east-1',
    'US West (Oregon)': 'us-west-2',
    'US West (Northern California)': 'us-west-1',
    'EU (Ireland)': 'eu-west-1',
    'Asia Pacific (Singapore)': 'ap-southeast-1',
    'Asia Pacific (Sydney)': 'ap-southeast-2',
    'Asia Pacific (Tokyo)': 'ap-northeast-1',
    'South America (Sao Paulo)': 'sa-east-1',
    'GovCloud': 'us-gov-west-1',
}

class ParseError(Exception):
    pass

def parse_section(line):
    region_description = line.rstrip(':')
    if not region_description in region_codes:
        raise ParseError("Not a recognized region: %r" % region_description)
    return region_codes[region_description]

def parse_cidr(line):
    address = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    pat = r'^(%s/\d+) \((%s) - (%s)\)(?: NEW)?$' % (address, address, address)

    match = re.search(pat, line)
    if not match:
        raise ParseError("Unexpected CIDR format: %r" % line)

    cidr, start, end = match.groups()
    return {'cidr': cidr, 'first': start, 'last': end}

def process(stream):
    section = None
    ip_info = {}
    for name, code in region_codes.iteritems():
        ip_info[code] = {'ranges': [], 'name': name}

    for line in stream:
        line = line.strip()

        if not line:
            continue

        if line == 'Sincerely,':
            break
        if line.startswith('Dear Amazon EC2 customer'):
            continue
        if line.startswith('We are pleased to announce'):
            continue

        try:
            section = parse_section(line)
            continue
        except ParseError:
            pass

        try:
            cidr_data = parse_cidr(line)
        except ParseError:
            pass
        else:
            ip_info[section]['ranges'].append(cidr_data)
            continue

        raise ParseError("Could not parse line: %r" % line)

    return ip_info

def report(ip_info):
    return {'generated': datetime.utcnow(), 'regions': ip_info}

if __name__ == '__main__':
    info = process(sys.stdin)
    print '---'
    yaml.dump(report(info), sys.stdout)

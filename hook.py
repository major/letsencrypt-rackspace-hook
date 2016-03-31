#!/usr/bin/python
#
# Copyright 2016 Major Hayden
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
"""Rackspace DNS API hook for letsencrypt.sh."""
import logging
import os
import pyrax
import sys
import time


import dns.resolver
import dns.exception


# Configure some basic logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Ensure that the environment variable PYRAX_CREDS is set and it contains the
# path to your pyrax credentials file.
pyrax.set_setting("identity_type", "rackspace")
try:
    pyrax.set_credential_file(os.environ['PYRAX_CREDS'])
    rax_dns = pyrax.cloud_dns
except KeyError:
    logger.error(" + Missing pyrax credentials file (export PYRAX_CREDS)")
    sys.exit(1)

# Determine the IP addresses for Rackspace's public nameservers. We will query
# these servers later to determine when our challenge record is published.
dns_servers = ["ns1.rackspace.com", "ns2.rackspace.com"]
resolver = dns.resolver.Resolver()
rackspace_dns_servers = [item.address for server in dns_servers
                         for item in resolver.query(server)]


def _has_dns_propagated(name, token):
    """
    Verify that the challenge DNS record exists on Rackspace's nameservers.

    Keyword arguments:
    name -- domain name that needs a challenge record
    token -- the challenge text that LetsEncrypt expects to find in DNS
    """
    # We want to query Rackspace's DNS servers directly
    resolver.nameservers = rackspace_dns_servers

    # Retrieve all available TXT records that match our query
    try:
        dns_response = resolver.query(name, 'txt')
    except dns.resolver.NoAnswer:
        return False

    # Loop through the TXT records to find one that matches our challenge
    text_records = [record.strings[0] for record in dns_response]
    for text_record in text_records:
        if text_record == token:
            logger.info(" + Challenge record found!")
            return True
        else:
            return False

    return False


def get_domain(domain_name):
    """
    Query the Rackspace DNS API to get a domain object for the domain name.

    Keyword arguments:
    domain_name -- the domain name that needs a challenge record
    """
    domain = rax_dns.find(name=domain_name)
    return domain


def create_txt_record(args):
    """
    Create a TXT DNS record via Rackspace's DNS API.

    Keyword arguments:
    args -- passed from letsencrypt.sh
    """
    domain_name, token = args[0], args[2]
    domain = get_domain(domain_name)

    # Assemble the parts of our record and create it
    name = "{0}.{1}".format('_acme-challenge', domain_name)
    record = {
        'type': 'TXT',
        'name': name,
        'data': token,
    }
    domain.add_records(record)
    logger.info(" + TXT record created: {0} => {1}".format(name, token))

    # Loop over a DNS query until the challenge record is published
    logger.info(" + Waiting for challenge DNS record to appear on the DNS "
                "server (this usually takes 30-60 seconds)")
    while True:
        if _has_dns_propagated(name, token) is False:
            time.sleep(5)
        else:
            break


def delete_txt_record(args):
    """
    Clean up the TXT record when it is no longer needed.

    Keyword arguments
    args -- passed from letsencrypt.sh
    """
    domain_name = args[0]
    domain = get_domain(domain_name)

    # Get the DNS record object(s) for our challenge record(s)
    name = "{0}.{1}".format('_acme-challenge', domain)
    dns_records = list(rax_dns.get_record_iterator(domain))
    text_records = [x for x in dns_records if x.type == 'TXT']

    # Delete any matching records we find
    for text_record in text_records:
        if text_record.name == name:
            text_record.delete()

    return True


def deploy_cert(args):
    """
    Display a message about the location of the cert/key/chain files.

    Keyword arguments:
    args -- passed from letsencrypt.sh
    """
    # Args = domain_name, privkey, cert, fullchain, chain_pem, timestamp
    logger.info(' + Certificate issued for {0}! Awesome!'.format(args[0]))
    logger.info(' + Private key: {0}'.format(args[1]))
    logger.info(' + Certificate: {0}'.format(args[2]))
    logger.info(' + Certificate w/chain: {0}'.format(args[3]))
    logger.info(' + CA chain: {0}'.format(args[4]))
    return


def main(argv):
    """
    The main logic of the hook.

    letsencrypt.sh will pass different arguments for different types of
    operations. The hook calls different functions based on the arguments
    passed.
    """
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge': delete_txt_record,
        'deploy_cert': deploy_cert,
    }
    logger.info(" + Rackspace hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])

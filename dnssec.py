import argparse
import sys
import time
import datetime
import dns.flags
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.dnssec

class DNSSEC_Resolver:
    root_server_ips = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
                       '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                       '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                       '202.12.27.33']

    def query(self, domain_name, remaining_labels=[], query_server='root_servers', parent_zone_DS=None):
        # print(domain_name, query_server)
        if query_server == 'root_servers':
            domain_name = domain_name.strip('. ')
            remaining_labels = domain_name.split('.')
            remaining_labels.append('.')
            for root_server_ip in DNSSEC_Resolver.root_server_ips:
                query_server_ip = root_server_ip
                query_result = self.query(domain_name, remaining_labels, query_server_ip)
                if query_result:
                    return query_result
        else:
            if not remaining_labels:
                return DNS_Query_Result('Didn\'t find the records', '', domain_name, '')

            query_server_ip = query_server
            current_domain_label = remaining_labels[-1]
            if current_domain_label == '.':
                current_domain = '.'
            else:
                current_domain = domain_name[domain_name.find(current_domain_label) : ]
            del remaining_labels[-1]

            request = dns.message.make_query(domain_name, dns.rdatatype.RdataType.A, want_dnssec=True)
            try:
                response = dns.query.udp(request, query_server_ip, timeout=10)
            except dns.exception.Timeout:
                return None

            dns_key_request = dns.message.make_query(current_domain, dns.rdatatype.RdataType.DNSKEY, want_dnssec=True)
            try:
                dns_key_response = dns.query.udp(dns_key_request, query_server_ip, timeout=10)
            except dns.exception.Timeout:
                return None

            dns_key_rrset = None
            dns_key_rrsig = None
            for rrset in dns_key_response.answer:
                if rrset.rdtype == dns.rdatatype.RdataType.DNSKEY:
                    dns_key_rrset = rrset
                else:
                    dns_key_rrsig = rrset

            # Didn't observe DNS_Key for last subdomain (verisigninc) of verisigninc.com 
            if dns_key_rrset:
                for dns_key in dns_key_rrset:
                    if dns_key.flags == 257:
                        ksk_key = dns_key

                try:
                    dns.dnssec.validate(dns_key_rrset, dns_key_rrsig, {dns_key_rrset.name : dns_key_rrset})
                except dns.dnssec.ValidationFailure:
                    return DNS_Query_Result('DNSSec verification failed', '', domain_name, '')
            else:
                # DS record found for the parent zone but DNS Key not found for this (child)
                # zone. Either this is an invalid Domain (most likely) or there is a configuration 
                # issue in this (child) zone. 
                return DNS_Query_Result('Didn\'t find the records', '', domain_name, '')

            if parent_zone_DS:
                parent_zone_DS_text = parent_zone_DS.to_text()
                parent_zone_DS_details = parent_zone_DS_text.split()
                digest_type_algo =  'SHA1' if parent_zone_DS_details[-2] == '1' else 'SHA256'

                parent_zone_owner = parent_zone_DS_details[0]
                curr_zone_DS_from_ksk = dns.dnssec.make_ds(parent_zone_owner, ksk_key, digest_type_algo)

                # Need to compare just the hash parts
                if parent_zone_DS_text.split()[-1] != curr_zone_DS_from_ksk.to_text().split()[-1]:
                    query_result = DNS_Query_Result('DNSSec verification failed', '', domain_name, '')
                    return query_result

            question_server = str(response.question[0]).split()[0]

            if len(response.answer) > 0:
                rrset = response.answer
                query_result = None
                for rr in rrset:
                    if rr.rdtype == dns.rdatatype.RdataType.A:
                        A_rr = rr
                        query_output = rr.to_text().split()[-1]
                        query_result = DNS_Query_Result('SUCCESS', 'ANSWER SECTION:', question_server, query_output) 
                    elif rr.rdtype == dns.rdatatype.RdataType.RRSIG:
                        A_rrsig = rr

                try:
                    dns.dnssec.validate(A_rr, A_rrsig, {dns_key_rrset.name : dns_key_rrset})
                except dns.dnssec.ValidationFailure:
                    return DNS_Query_Result('DNSSec verification failed', '', domain_name, '')

                return query_result

            elif len(response.authority) > 0:
                rrsets = response.authority

                DS_rrset = None
                DS_rrset_sig = None
                NS_rrset = None
                for rrset in rrsets:
                    if rrset.rdtype == dns.rdatatype.RdataType.DS:
                        DS_rrset = rrset
                    elif rrset.rdtype == dns.rdatatype.RdataType.RRSIG:
                        DS_rrset_sig = rrset
                    elif rrset.rdtype == dns.rdatatype.RdataType.NS:
                        NS_rrset = rrset
                if not DS_rrset:
                    return DNS_Query_Result('DNSSEC not supported', '', domain_name, '')

                try:
                    dns.dnssec.validate(DS_rrset, DS_rrset_sig, {dns_key_rrset.name : dns_key_rrset})
                except dns.dnssec.ValidationFailure:
                    return DNS_Query_Result('DNSSec verification failed', '', domain_name, '')

                if not NS_rrset:
                    return DNS_Query_Result('Didn\'t find the records', '', domain_name, '')

                for rr in NS_rrset:
                    query_server_name = str(rr)

                    query_server_ip = None
                    response_additional = response.additional
                    total_response_additional = len(response_additional)

                    for i in range(total_response_additional):
                        current_response_additional = response_additional[i].to_text()

                        if query_server_name in current_response_additional and\
                        current_response_additional.split()[-2] == 'A': # additional record captures IP address
                            query_server_ip =  current_response_additional.split()[-1]
                            
                            if question_server == query_server_name:
                                query_output = query_server_ip
                                return DNS_Query_Result('SUCCESS', 'AUTHORITY SECTION:', question_server, query_output)

                            break
                    if query_server_ip is None:
                        # IP ADDRESS not captured in ADDITIONAL INFO
                        query_server_ip = self.query(query_server_name, [], 'root_servers', None).query_output

                    query_result = self.query(domain_name, remaining_labels, query_server_ip, DS_rrset)
                    if query_result:
                        return query_result
                return None
            else:
                return None

class DNS_Query_Result:
    def __init__(self, status, header, query_server, query_output):
        self.status = status
        self.header = header
        self.query_server = query_server
        self.query_output = query_output    # IP Address for queries of type A, Name Server for type NS and MX

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--domainName', default='233.23445t34y56.org', help='name of the domain you want to resolve')
    arguments = vars(parser.parse_args())
    domain_name = arguments['domainName']

    resolver = DNSSEC_Resolver()

    start = time.time()
    dns_query_output = resolver.query(domain_name)
    end = time.time()
    query_time = end - start

    print("QUESTION SECTION:")
    print(dns_query_output.query_server + '\t' + 'IN' + '\t' + 'A' + '\n')

    if dns_query_output.status != 'SUCCESS':
        print(dns_query_output.status)
    else:
        print(dns_query_output.header)
        print(dns_query_output.query_server + '\t' + 'IN' + '\t' + dns_query_output.query_output + '\n')

        print('Query time: ' + str(query_time*1000) + ' msec')
        print('WHEN: ' + str(datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f")))
        print('MSG SIZE rcvd: ' + str(len(dns_query_output.status) +
         len(dns_query_output.query_server) + len(dns_query_output.header) +
          len(dns_query_output.query_output)))
    
    



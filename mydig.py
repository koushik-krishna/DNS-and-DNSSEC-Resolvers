import argparse
import sys
import time
import datetime
import dns.flags
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype

class DNS_Resolver:
    root_server_ips = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
                       '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                       '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                       '202.12.27.33']

    def query(self, domain_name, query_type='A', remaining_labels=[], query_server='root_servers'):
        if query_server == 'root_servers':
            domain_name = domain_name.strip('. ')
            remaining_labels = domain_name.split('.')
            remaining_labels.append('.')
            for root_server_ip in DNS_Resolver.root_server_ips:
                query_server_ip = root_server_ip
                query_result = self.query(domain_name, query_type, remaining_labels, query_server_ip)
                if query_result:
                    return query_result
        else:
            if not remaining_labels:
                return None

            del remaining_labels[-1]

            query_server_ip = query_server
            request = dns.message.make_query(domain_name, dns.rdatatype.RdataType[query_type])
            
            try:
                response = dns.query.udp(request, query_server_ip, timeout=10)
            except dns.exception.Timeout:
                return None

            question_server = str(response.question[0]).split()[0]

            # Checking answer section of response
            if len(response.answer) > 0:
                rrset = response.answer
                for rr in rrset:
                    if int(dns.rdatatype.RdataType[query_type]) == rr.rdtype:
                        query_output = rr.to_text().split()[-1]
                        return DNS_Query_Result('ANSWER SECTION:', question_server, query_output)

            elif len(response.authority) > 0:
                rrsets = response.authority

                NS_rrset = None
                for rrset in rrsets:
                    if rrset.rdtype == dns.rdatatype.RdataType.NS:
                        NS_rrset = rrset

                if not NS_rrset:
                    return None

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
                                return DNS_Query_Result('AUTHORITY SECTION:', question_server, query_output)

                            break
                    if query_server_ip is None:
                        # IP ADDRESS not captured in ADDITIONAL INFO
                        query_server_ip = self.query(query_server_name).query_output

                    query_result = self.query(domain_name, query_type, remaining_labels, query_server_ip)
                    if query_result:
                        return query_result
                return None
            else:
                return None

class DNS_Query_Result:
    def __init__(self, header, query_server, query_output):
        # Captures Status of the resolution
        self.header = header
        # Target DomainName
        self.query_server = query_server
        # IP Address for queries of type A, Name Server for type NS and MX
        self.query_output = query_output    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--domainName', default='Soho.com', 
    help='name of the domain you want to resolve')
    parser.add_argument('--type', default='A', help='DNS query type')
    arguments = vars(parser.parse_args())
    domain_name = arguments['domainName']
    query_type = arguments['type'] 

    resolver = DNS_Resolver()

    start = time.time()
    dns_query_output = resolver.query(domain_name, query_type)
    end = time.time()
    query_time = end - start

    print("QUESTION SECTION:")

    if not dns_query_output:
        print(domain_name + '\t' + 'IN' + '\t' + query_type + '\n')
        print('Record Not found')
        sys.exit()

    print(dns_query_output.query_server + '\t' + 'IN' + '\t' + query_type + '\n')
    print(dns_query_output.header)
    print(dns_query_output.query_server + '\t' + 'IN' + '\t' + dns_query_output.query_output
     + '\n')

    print('Query time: ' + str(query_time*1000) + ' msec')
    print('WHEN: ' + str(datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f")))
    print('MSG SIZE rcvd: ' + str(len(dns_query_output.query_server) + len(dns_query_output.header) + len(dns_query_output.query_output)))
    



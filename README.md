<h2 align="center">

  <img src="https://dimabusiness.com/wp-content/uploads/2020/10/Untitled-design-1.png"><br>

</h2>


# To deploy DNS Firewall

<strong>To Know More:</strong> https://dimabusiness.com/<br>
<strong>Read 1: </strong> <a href="https://dimabusiness.com/wp-content/uploads/2020/10/DNS-Firewall-Builder-User-Guide.pdf">DNS-Firewall-Builder-User-Guide</a>  <br> 
<strong>Read 2: </strong> <a href="https://dimabusiness.com/wp-content/uploads/2020/10/DNS-Firewall-User-Interface-User-Guide.pdf">DNS-Firewall-User-Interface-User-Guide</a><br>
<strong>Network Penetration Testing & Advanced Configuration Reports: </strong> <a href="https://dimabusiness.com/wp-content/uploads/2020/09/Dima_Business_Solutions_Pvt_Ltd_NPT_and_Advanced_Conf_Review_Report.pdf">View Reports</a><br>
<strong>GRC DNS Benchmark Report: </strong> <a href="https://dimabusiness.com/wp-content/uploads/2020/10/GRC-DNS-Benchmark-Report-2_Oct_2020.pdf">View Reports</a><br>
<strong>Register and Build DNS Firewall Here:</strong> https://newitv1.dimabusiness.com/accounts/signup

# Differences between DNS Firewall and Next Generation Firewall

Let’s look at the difference between Next Generation Firewalls and DNS Firewalls.

DNS Firewall is a Domain Name System (DNS) service that utilizes response policy
zones (RPZs) with a threat intelligence feed service to protect against malware and
advanced persistent threats (APTs) by disrupting the ability of infected devices to
communicate with command-and-control (C&C) sites and botnets.

Next Generation Firewall is a deep-packet inspection hardware or software firewall that
moves beyond port/protocol inspection and blocking to add application-level inspection,
intrusion prevention, and bring in intelligence from outside the firewall.

# NGFW is Mostly a Reactive Defense Tool

NGFW defenses react after an attack has already been launched—so if your network is
attacked, the NGFW will respond. Hence, NGFW acts as a reactive defense tool rather
than as a proactive one. Today, this line of thinking could be very risky because the
velocity and volume of new attack tools and techniques enable some malicious activity
to be dormant and go undetected for minutes, weeks or even months.

# DNS Firewall is Proactive in Stopping Malicious Traffic

While a DNS Firewall can stop malicious Internet connections before they occur at the
DNS control plane, NGFW must scan each of these connections. NGFWs do not offer
protection to off-network devices/users such as remote and roaming users without
always keeping a VPN on, which adds latency. When it comes to protecting your
end-users working inside or outside of your perimeter, a DNS Firewall is much faster,
more responsive, and more effective.

# NGFW Falls Short on DNS Control Plane

Signature-based products like NGFW are critical to blocking or containing phishing
attacks. But you might be missing a crucial element at a different layer of your security
defenses: DNS. The next layer on your NGFW based security solution should be
focused on the DNS control plane. NGFWs allow administrators to apply policies to
traffic based not just on port and protocol, but also applications and users accessing the
network. However, the DNS protocol is typically not “inspected” by NGFW for malware.
Most NGFWs allow traffic to pass through port 53, the protocol over which DNS queries
and responses are sent. This can make the DNS service vulnerable to malware. NGFW
is not a DNS server, and therefore, cannot interpret DNS queries and responses to
detect malware that uses the DNS protocol, which is typically allowed through the
firewall. This is not to say that all NGFWs lack DNS security-related features. Certain
NGFW products have specific DNS related security features, but these are “bolted on,”
and lack the visibility that DNS servers have into all the DNS requests and devices that
are reaching out to malicious domains, and extensive attributes of infected devices.

Using a layered approach to security is critical as network perimeters continue to erode
and confidential information is accessed through cloud services on public WiFi
networks. The best way to maintain a strong security posture is by integrating DNS
Firewall with NGFW. DNS Firewall can be installed as part of DNS either on-premises
or offered as a service via the cloud. Since DNS Firewall does not include an intrusion
prevention system, your network could be vulnerable to malformed packets or DDoS
(distributed denial of service) attacks. So the best practice is to complement the DNS
firewall with NGFW as critical elements in your layered security solution, as opposed to
simply adopting one or the other.

# What Makes DNS Firewall Special?

DNS Firewall is an optimal policy enforcement point for DNS-specific protection from
malware and APTs. DNS is increasingly being used as a pathway for data exfiltration,
either unwittingly by malware-infected devices or intentionally by malicious insiders.
DNS tunneling involves tunneling IP protocol traffic through DNS port 53 (of NGFW) for
the purposes of data exfiltration. Such attacks can result in the loss of sensitive data
such as credit card information, social security numbers, or company financials.

Internal DNS security that combines DNS-based threat intelligence and analytics helps
detect and protect against data exfiltration at the DNS control point.

DNS firewall, because it’s based on DNS, can be an ideal enforcement point for
detecting any device that tries to call ‘home’ (malicious domain) using DNS. Moreover, a
DNS server is a default service in the network with NGFW, so why not let DNS Firewall
perform tasks it’s suited for and at the scale and performance you need, without3 Raja Street, Trichy Rd, Kallimadai, Singanallur, Tamil Nadu 641005
burdening the already busy NGFW?
## Reference and Courtesy:
https://blogs.infoblox.com/security/do-i-need-both-dns-firewall-and-next-generation-firewall/


# 

<h2 align="center">
About DIMA Warrior and Deployment methods
</h2>

## DNS Vulnerabilities

1) You own a Firewall and you use third party DNS IP
2) You own a Proxy server and you use third party DNS IP
3) You own a VPN Access Server and you use third party DNS IP
4) You own a Domain Controller/Active Directory and you use third party DNS IP
5) User DNS Queries are resolved by a third party DNS Server which is not in their control
6) DNS Becomes a Data Channel
7) DNS 'A' record has 4 bytes of data, with 100 DNS Queries it can becomes 400 bytes of data which can be transferred or received
8) DNS 'AAAA' record has 16 bytes of data which can be transferred or received
9) DNS 'TXT' record has 255 character space which payload out from your network with private key (Example-Ransomware)
10) All the Browser does is WGET (HTTP GET/POST), there by downloading pictures/any executable files (Example-malware) at the backend which gives pathway to your network to the outside world in the form of DNS Queries.


## DIMA Public Cloud Intelligence

1) It has two components Intelligent Threat vector (ITV) and Secure API
2) Intelligent Threat vector (ITV) has predefined threat database (Open Source Threat Intelligence)
3) Intelligent Threat vector (ITV) prepares DNS Zone file for every 60 minutes and pushes it to the target DNS Server
4) Secure API does Live traffic inspection (Inepects DNS Queries from target DNS Server)
5) Secure API is powered by AI-ML prediction techniques (Good/Bad decision maker on DNS queries)

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/dima_cloud_intelligence.jpg" >
</p>

## About DIMA Warrior - DNS Firewall built with Open Source BIND DNS Server

1) Dima Warrior has 5 Zone Files
2) The 5 Zone files are Whitelist,Blacklist,Genius,Category and RPZ
3) Whitelist Zone file is for manual whitelisting of DNS Queries
4) Blacklist Zone file is for manual blacklisting of DNS Queries
5) Genius Zone file is powered by Secure API from DIMA Public Cloud Intelligence
6) Category Zone file is powered by Intelligent Threat vector (ITV) from DIMA Public Cloud Intelligence
7) RPZ Zone file is powered by Intelligent Threat vector (ITV) from DIMA Public Cloud Intelligence
8) DNS Service Config file is powered by DNS IP based Access control Lists to inspect destination based IP address queries, this is also governed by Intelligent Threat vector (ITV) from DIMA Public Cloud Intelligence


## Dima Warrior as a DNS Firewall/Server Compatibility

Can be a Standalone Server either in Public/Private cloud.<br>
<strong>Use Case 1 :</strong> DNS IP can be used directly as prefered DNS Server in Laptop/Desktop..etc.,<br>
<strong>Use Case 2 :</strong> DNS IP can be used in OnPremise Firewall (Instead of Depending on third party DNS IP which is a vulnerability)<br>
<strong>Use Case 3 :</strong> DNS IP can be used in OnPremise Proxy Server (Instead of Depending on third party DNS IP which is a vulnerability)<br>
<strong>Use Case 4 :</strong> DNS IP can be used in VPN Access Server (Instead of Depending on third party DNS IP which is a vulnerability)<br>

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/compatibility.jpg" >
</p>

## Deployment Method 1 : DIMA Warrior in Public Cloud

1) Dima warrior will be hosted in the public cloud, which will have a public IP
2) The public IP can be used on - On Premise Firewall, Cloud Application Servers, On Premise / Cloud Proxy Server if the IP is reachable.
3) Once the IP is reachable from On Premise LAN or Remote WiFi , we can use the IP in host computers and servers also.
4) The IP can also be used in WIFI routers if it is reachable from home or SOHO

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment1.jpg" >
</p>

## Deployment Method 2 : DIMA Warrior in Public Cloud - With on premise proxy and firewall

1) Dima warrior will be hosted in the public cloud, which will have a public IP
2) The public IP can be used on - On Premise Firewall, Cloud Application Servers, On Premise / Cloud Proxy Server if the IP is reachable
3) Once the IP is reachable from On Premise LAN or Remote WiFi , we can use the IP in host computers and servers also
4) The IP can also be used in WIFI routers if it is reachable from home or SOHO

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deplyment2.jpg" >
</p>


## Deployment Method 3 : DIMA Warrior in Public Cloud - With Proxy Server in Public Cloud

1) Dima warrior will be hosted in the public cloud, which will have a public IP
2) The public IP can be used on - On Premise Firewall, Cloud Application Servers, On Premise / Cloud Proxy Server if the IP is reachable
3) Once the IP is reachable from On Premise LAN or Remote WiFi , we can use the IP in host computers and servers also
4) The IP can also be used in WIFI routers if it is reachable from home or SOHO


<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deplyment3.jpg" >
</p>

## Deployment Method 4 : DIMA Warrior in Public Cloud - With http proxy on premise and VPN access server in public cloud

1) DIMA Warrior will be hosted in the public cloud, which will have a public IP
2) This IP will be integrated to VPN access servers in the public cloud
3) Users on premise will connect to HTTP proxy and parallely via VPN to access the Internet via DIMA Warrior
4) The user will have two credentials one for VPN and another for on premise HTTP proxy server

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deplyment4.jpg" >
</p>


## Deployment Method 5 : DIMA Warrior in Public Cloud - With VPN access server in public cloud

1) DIMA Warrior will be hosted in the public cloud, which will have a public IP
2) This IP will be integrated to the VPN access server in the public cloud.
3) Users on premise or remote will install the software and use the credentials given by DIMA in the same software.
4) Once connected the users devices will have their internet traffic routed via VPN tunnel and then access internet via DIMA warrior.

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment5.jpg" >
</p>

## Deployment Method 6 : DIMA Warrior in Public Cloud - With VPN access server in public cloud serving on premise WRT routers

1) DIMA Warrior will be hosted in the public cloud, which will have a public IP
2) This IP will be integrated to VPN access server in public cloud
3) Users will have a WRT WiFi router.
4) SOHO or Home users will have client based configuration file integrated to WRT WiFi router which is a Dima Self Signed VPN License
5) On activation the WRT WiFi router will establish a secure tunnel to VPN access server in the cloud, which enables the traffic to pass through the router and then the VPN tunnel.
6) Thereby the traffic reaches securely Dima warrior for Internet access

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment6.jpg" >
</p>


## Deployment Method 7 : DIMA Warrior in Private Cloud or On Premise

1) DIMA Warrior will be hosted in the private cloud, which will have a private IP
2) This IP address can be used by users as a local primary DNS server via DHCP (WiFi) or static.
3) This IP address can also be used by Servers on premise.
4) If the LAN or On premise users already have a DNS / domain controller, we can create a zone in Dima warrior on premise to point local requests or local application requests pointing to local DNS / domain controller.

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment7.jpg" >
</p>


## Deployment Method 8 : DIMA Warrior in Private Cloud or On Premise as primary and secondary

1) Dima warrior hosted on premise hardware or private cloud as Primary and Secondary DNS Servers
2) The two IP addresses can be used by users as local primary/secondary DNS server via DHCP (WiFi) or static
3) The two IP addresses can also be used by Servers as primary/secondary on premise
4) If the LAN or On premise users already have DNS / domain controller, we can create a zone in Dima warrior on premise (Primary / Secondary) to point local requests or local application requests pointing to local DNS / domain controller

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment8.jpg" >
</p>

## Deployment Method 9 : DIMA Warrior in Private Cloud or On Premise secondary with on premise proxy server

1) Dima warrior hosted on premise hardware or private cloud as Primary and Secondary DNS Servers
2) The two IP addresses can be used by users as local primary/secondary DNS server via DHCP (WiFi) or static
3) The two IP addresses can also be used by Servers as primary/secondary on premise
4) If the LAN or On premise users already have DNS / domain controller, we can create a zone in Dima warrior on premise (Primary / Secondary) to point local requests or local application requests pointing to local DNS / domain controller
5) The IP address of Primary and secondary Dima warrior can be integrated to On premise Proxy server

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment9.jpg" >
</p>


## Deployment Method 10 : DIMA Warrior in Public Cloud providing web application security and on premise network security along with DIMA Authentic Server

1) If you have a critical web application hosted on premise or public cloud, you can use Dima warrior as DNS to a critical web application server
2) The same Dima warrior is used as DNS in Dima Authentic server also
3) Dima Authentic server provides URL masking, mutual SSL authentication and LDAP
4) The same Dima Warrior can be used on premise firewall, cloud applications servers , on premise/cloud proxy server if the IP is found to be reachable
5) If the IP is reachable from on premise LAN or remote WiFi , we can use this IP in host computers and servers also
6) If the IP is reachable from Home or SOHO, the same IP can be used in wifi routers

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment10.jpg" >
</p>



## Deployment Method 11 : DIMA Route Zero Network Design (90% Security Assured)

1) On a manageable layer 3 switch writing a default route pointing to Firewall/Router/Modem LAN interface is very vulnerable
2) Meaning you say a hacker very clearly which way to come inside and go outside (Data Infiltration and Exfiltration)
3) To fix the above, you need to define specific routes to destination access needed and mention default route to Null0 (Discard Interface) at the end in manageable layer 3 switch
4) Example , Best practise is to write a route to Proxy alone and mention default route to Null0 (Discard Interface) at the end in manageable layer 3 switch

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment11.jpg" >
</p>

<p align="center">
<img src="https://dimabusiness.com/wp-content/uploads/2020/10/deployment12.jpg" >
</p>


# Open Source References and Inspiration

www.BlockList.de<br>
www.binarydefense.com<br>
www.danger.rulez.sk<br>
www.darklist.de<br>
www.botscout.com<br>
www.zonefiles.io<br>
www.emergingthreats.net<br>
www.greensnow.co<br>
www.myip.ms<br>
www.sblam.com<br>
www.spamhaus.org<br>
www.sslbl.abuse.ch<br>
www.stopforumspam.com<br>
www.check.torproject.org<br>
www.badips.com<br>
www.feeds.dshield.org<br> 
www.maxmind.com<br> 
www.alienvault.com<br> 
www.blocklist.net.ua<br> 
www.cruzit.com<br> 
www.talosintel.com<br>
www.voipbl.org<br> 
www.feodotracker.abuse.ch<br> 
www.dan.me.uk<br>
www.ipspamlist.com<br>
www.charles.the-haleys.org<br>
www.cinsscore.com<br> 
www.bambenekconsulting.com<br> 
www.botvrij.eu<br>
www.urlhaus.abuse.ch<br>
www.openphish.com<br> 
www.phishtank.com<br>
www.dns-bh.sagadc.org<br>
www.malwaredomainlist.com<br> 
www.joewein.net<br>
www.projecthoneypot.org<br>
www.panwdbl.appspot.com<br>
www.snort.org<br>
www.dataplane.org<br>
www.mirai.security.gives<br>
www.hosts-file.net<br> 
www.vxvault.net<br>
www.cybercrime-tracker.net<br> 
www.benkow.cc<br>
www.api.cybercure.ai<br>
www.team-cymru.org<br> 
www.ciarmy.com<br>
www.dshield.org<br>
www.squidguard.org<br>
www.shallalist.de<br>
www.dsi.ut-capitole.fr<br>

# Contributors:

Devaraj Palaniswamy - Managing Director - dev@dimabusiness.com

Sowmya Jegan - CEO - sowmya.j@dimabusiness.com

Jegan Srimohanram - CTO - jegan@dimabusiness.com

Parthiban Soundram - Software Engineer - parthiban.s@dimabusiness.com

Ayush Kurlekar - Software Engineer - ayush.k@dimabusiness.com

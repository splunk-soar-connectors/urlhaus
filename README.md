[comment]: # "Auto-generated SOAR connector documentation"
# URLhaus

Publisher: Splunk Community  
Connector Version: 1\.0\.3  
Product Vendor: abuse\.ch  
Product Name: URLhaus  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.8\.24304  

URLhaus is a project from abuse\.ch with the goal of sharing malicious URLs that are being used for malware distribution

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This app is designed to gather open source cyber threat intelligence (OSINT) from Abuse.ch's well
known "URLhaus" platform.  
  
The API is [well documented](https://urlhaus.abuse.ch/api/) , so take a look. The app aims to use
'contains' and example values as often as possible, but certain capabilities have lots of settings
which are documented here, but minimally.  
  
No API key is required for this app. Future iterations could leverage the API key for submissions.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a URLhaus asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL for URLhaus API
**api\_key** |  optional  | password | API Key \(Only required for submission\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup url](#action-lookup-url) - Check for the presence of a URL in a threat intelligence feed  
[lookup ip](#action-lookup-ip) - Check for the presence of an IP in a threat intelligence feed  
[lookup domain](#action-lookup-domain) - Check for the presence of a domain in a threat intelligence feed  
[lookup hash](#action-lookup-hash) - Check for the presence of a hash in a threat intelligence feed  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup url'
Check for the presence of a URL in a threat intelligence feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to lookup | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.blacklists\.spamhaus\_dbl | string | 
action\_result\.data\.\*\.blacklists\.surbl | string | 
action\_result\.data\.\*\.date\_added | string | 
action\_result\.data\.\*\.host | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.larted | string | 
action\_result\.data\.\*\.payloads\.\*\.file\_type | string | 
action\_result\.data\.\*\.payloads\.\*\.filename | string | 
action\_result\.data\.\*\.payloads\.\*\.firstseen | string | 
action\_result\.data\.\*\.payloads\.\*\.imphash | string |  `hash` 
action\_result\.data\.\*\.payloads\.\*\.response\_md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.payloads\.\*\.response\_sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.payloads\.\*\.response\_size | numeric | 
action\_result\.data\.\*\.payloads\.\*\.signature | string | 
action\_result\.data\.\*\.payloads\.\*\.ssdeep | string |  `hash` 
action\_result\.data\.\*\.payloads\.\*\.tlsh | string |  `hash` 
action\_result\.data\.\*\.payloads\.\*\.urlhaus\_download | string |  `url` 
action\_result\.data\.\*\.payloads\.\*\.virustotal\.link | string |  `url` 
action\_result\.data\.\*\.payloads\.\*\.virustotal\.percent | string | 
action\_result\.data\.\*\.payloads\.\*\.virustotal\.result | string | 
action\_result\.data\.\*\.query\_status | string | 
action\_result\.data\.\*\.reporter | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.takedown\_time\_seconds | numeric | 
action\_result\.data\.\*\.threat | string | 
action\_result\.data\.\*\.url\_status | string | 
action\_result\.data\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Check for the presence of an IP in a threat intelligence feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.blacklists\.spamhaus\_dbl | string | 
action\_result\.data\.\*\.blacklists\.surbl | string | 
action\_result\.data\.\*\.firstseen | string | 
action\_result\.data\.\*\.query\_status | string | 
action\_result\.data\.\*\.url\_count | numeric | 
action\_result\.data\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.date\_added | string | 
action\_result\.data\.\*\.urls\.\*\.id | string | 
action\_result\.data\.\*\.urls\.\*\.larted | boolean | 
action\_result\.data\.\*\.urls\.\*\.reporter | string | 
action\_result\.data\.\*\.urls\.\*\.tags | string | 
action\_result\.data\.\*\.urls\.\*\.takedown\_time\_seconds | numeric | 
action\_result\.data\.\*\.urls\.\*\.threat | string | 
action\_result\.data\.\*\.urls\.\*\.url\_status | string | 
action\_result\.data\.\*\.urls\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Check for the presence of a domain in a threat intelligence feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.blacklists\.spamhaus\_dbl | string | 
action\_result\.data\.\*\.blacklists\.surbl | string | 
action\_result\.data\.\*\.firstseen | string | 
action\_result\.data\.\*\.query\_status | string | 
action\_result\.data\.\*\.url\_count | numeric | 
action\_result\.data\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.date\_added | string | 
action\_result\.data\.\*\.urls\.\*\.id | string | 
action\_result\.data\.\*\.urls\.\*\.larted | boolean | 
action\_result\.data\.\*\.urls\.\*\.reporter | string | 
action\_result\.data\.\*\.urls\.\*\.tags | string | 
action\_result\.data\.\*\.urls\.\*\.takedown\_time\_seconds | numeric | 
action\_result\.data\.\*\.urls\.\*\.threat | string | 
action\_result\.data\.\*\.urls\.\*\.url\_status | string | 
action\_result\.data\.\*\.urls\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup hash'
Check for the presence of a hash in a threat intelligence feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash** |  required  | File Hash to lookup | string |  `md5`  `sha256`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `md5`  `sha256`  `hash` 
action\_result\.data | string | 
action\_result\.data\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.file\_type | string | 
action\_result\.data\.\*\.firstseen | string | 
action\_result\.data\.\*\.imphash | string |  `hash` 
action\_result\.data\.\*\.lastseen | string | 
action\_result\.data\.\*\.md5\_hash | string |  `md5`  `hash` 
action\_result\.data\.\*\.query\_status | string | 
action\_result\.data\.\*\.sha256\_hash | string |  `sha256`  `hash` 
action\_result\.data\.\*\.signature | string | 
action\_result\.data\.\*\.ssdeep | string |  `hash` 
action\_result\.data\.\*\.tlsh | string |  `hash` 
action\_result\.data\.\*\.url\_count | numeric | 
action\_result\.data\.\*\.urlhaus\_download | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.filename | string | 
action\_result\.data\.\*\.urls\.\*\.firstseen | string | 
action\_result\.data\.\*\.urls\.\*\.lastseen | string | 
action\_result\.data\.\*\.urls\.\*\.url | string | 
action\_result\.data\.\*\.urls\.\*\.url\_status | string | 
action\_result\.data\.\*\.urls\.\*\.urlhaus\_reference | string |  `url` 
action\_result\.data\.\*\.virustotal | string | 
action\_result\.data\.\*\.virustotal\.link | string |  `url` 
action\_result\.data\.\*\.virustotal\.percent | string | 
action\_result\.data\.\*\.virustotal\.result | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
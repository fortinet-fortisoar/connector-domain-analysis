# Domain Analysis

## About the connector
The connectors offers a number of enrichment actions to help analysts determine whether domains are DGAs indicating a malware activity in the network. It also offers whois lookups for various artifact types.

## Version information

Connector Version: 1.0.0

Authored By: Naili.M

Certified: No

## Installing the connector
---------------------------------------------------------------

All connectors provided by FortiSOAR™ are delivered using a FortiSOAR™ repository. Therefore, you must set up your FortiSOAR™ repository and use the `yum` command to install connectors:

`yum install domain-analysis`

For the detailed procedure to install a connector, click[ here.](https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector)

## Configuring the connector
-----------------------------------------------------------------

The connector requires no configuration, it needs Internet access though to download various components

### Actions supported by the connector
-----------------------------------------------------------------------------------

| Function | Description |
|-----|-----|
Analyze Domain|Get DGA probability. Typically an Average Probability below 4 indicates a DGA|
Get Domain Popularity|Gets the rank within the top one million popular domains (-1 = not found)
Whois|Whois lookup for domains, IP addresses and Autonomous Systems
Get Domain Report|Gets domain report with all available metrics

Included playbooks
---------------------------------------------------

Each action has a sample playbook so you can quickly test it.   
# MicrosoftSentinel-DocumentAnalytics

This is a basic python script that aims to assist SOC teams in creating 
documentation for their Microsoft Sentinel analytic rules. The script
utilizes python-docx to automate creation of a Microsoft Word document
with the relevant analytic rule details.

## Details

This script works by first obtaining a list of all analytic rules installed
in the Microsoft Sentinel workspace. From there, it will create a Microsoft 
Word document. This script will also attempt to retrieve the tables used in 
each query (**NOTE**: this will not parse out any KQL functions). The 
included document is formatted for the following details:

| | |
|----|----|
| **GUID** | Automatically generated from the analytic rule GUID |
| **Description** | Automatically generated from the analytic rule description |
| **Severity** | Automatically generated from the analytic rule severity|
| **Requirements** | Automatically generated from the Log Analytics tables used in the query|
| **Tactics** | Automatically generated with the MITRE ATT&CK tactics defined for the analtic rule|

- **Triage steps:** include steps for SOC analysts to follow for triage here

- **Change notes:** track changes made to the analytic rule here

## Requirements

This script is written in Python3 and requires the following packages:

- `azure-mgmt-securityinsight`
- `azure-mgmt-loganalytics`
- `azure-identity`
- `python-docx`

Install with `pip3 install -r requirements.txt`

**NOTE:** You may need to install `azure-mgmt-loganalytics==13.0.0b6`. I had a problem retrieving log analytics table names with the default version `12.0.0` similar to the issue shown here: https://github.com/Azure/azure-sdk-for-python/issues/28161

## Configuration

### Azure authentication

This script uses the `DefaultAzureCredential` credential class for 
authenticating to Azure. See the Azure 
[documentation](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme?view=azure-python#defaultazurecredential) 
page to learn how to configure your local environment.


### Document styling

To customize the look of the resulting Word document, open 
[`NewDocTemplate.docx`](./NewDocTemplate.docx) in Microsoft Word and make your 
changes. The table is configured to use the "NewStyle" table style.

The screenshot below shows the default styling:

![](/images/document_example.png)

## Usage

```shell
python analytics2docx.py --help
usage: analytics2docx.py [-h] [-s] [-e] -r RESOURCE_GROUP -w WORKSPACE -i SUBSCRIPTION_ID

Create a Microsoft Word document from analytic rules in a Microsoft Sentinel workspace

optional arguments:
  -h, --help            show this help message and exit
  -s, --scheduled       only include scheduled analytic rules
  -e, --enabled         only include enabled analytic rules
  -r RESOURCE_GROUP, --resource-group RESOURCE_GROUP
                        resource group name
  -w WORKSPACE, --workspace WORKSPACE
                        workspace name
  -i SUBSCRIPTION_ID, --subscription-id SUBSCRIPTION_ID
                        subscription id
```



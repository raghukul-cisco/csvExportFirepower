# csvExportFirepower

This tool helps in taking CSV export of policies on firepower. A CSV backup of policies is usually a requirement as part of audit/compliance. However, this is not an official backup and restore option. The utility is designed to just take CSV export.

 
## Use Case Description

The tool is developed to address the concern of taking a CSV backup of access control policies configured on the FMC. The FMC by design supports SFO, PDF and full backup as option to take export. However, many a times there is a need to take CSV export of the policies configured on the FMC. In the current version of the tool the support is available for single domain deployments with access control policy. More details are availabe in the usage section.

## Installation

Requirements for installation:

	1. pip3 install fireREST
	2. pip3 install netaddr
	3. pip3 install datetime
	4. pip3 install ipaddress

Or alternatively you can the command below to download dependencies via the requirements.txt file, this has to be executed from the downloaded script directory.
	pip3 install -r ./requirements.txt


## Usage

Once the dependencies are installed and the code is pulled from GitHub, it is good to go.
Below mentioned are the steps to follow in order to execute it:

 1. First thing to ensure is, the machine where the code will be installed should have connectivity with the FMC under concern.
 2. It is recommended to create a different user for the tool, so that it does not block existing users from logging into the FMC for operational changes.
 3. Navigate to the location where the script is installed.

In order to execute the script, run the below command:

# python3 policyCSV.py 
Enter the IP Address of the FMC: 
Enter the username for the FMC: 
Enter the password associated with the username entered: 
Once the credentials are entered, the script connects to the FMC and provides the list of Access Control Policy that are available in Global Domain.

Example:

ACP available in global domain: 
	Name:  Default
	Name:  Snort3

Now, the policies listed are case sensitive. Hence, while choosing the ACP which has to be exported the user can enter one of three possibilities:

 1. Name of a single ACP (case sensitive) and press return.
 2. Comma seperated ACP names in case multiple ACP have to exported and press return. (All the ACP names should be case sensitive)
 3. Default behavior with just return pressed. (All the ACP available/listed would exported)

Once the user choice is entered, the script executes and you will see output as shown below:

Enter the ACP Name (case sensitive) if you want specific ACP to export(multiple values should be comma seperated). By default all the ACP would be exported, press return for default behaviour: Default
Inside ACP
Writing rule #1 to CSV...
Writing rule #2 to CSV...
Writing rule #3 to CSV...
Writing rule #4 to CSV...
Writing rule #5 to CSV...
Writing rule #6 to CSV...
Writing rule #7 to CSV...
Writing rule #8 to CSV...
Writing rule #9 to CSV...
Writing rule #10 to CSV...
Writing rule #11 to CSV...
File is at: ./E00EDAC5-CFAC-0ed3-0000-253403070825.csv

Output Generated:

 1. The CSV generated is located in the same folder as that of script installation.
 2. The name of the CSV file generated is UUID of the ACP to ensure uniqueness.
 3. In case of multiple ACP being entered or default behavior, the export of ACP is in sequential order similar to policies listed after we enter the credentials for the script.
 4. The output on console also displays the rule number that is being exported to help determine progress and troubleshoot in case of problems.


## Known issues

Currently the tool is limited to export of ACP in CSV format.
The below fields from ACP are not supported currently:
 1. Username/UserGroups
 2. Security Group Tags (Source and Destination)

Additionally, support for multi-domains is not available yet.

## Getting help

If you have questions, concerns, bug reports, etc., please create an issue against this repository.

DevNet Learning Lab
Please go to the DevNet Learning Lab for Firepower Management Center (FMC) to learn how to use these scripts:
https://developer.cisco.com/learning/modules/fmc-api

DevNet Sandbox
The Sandbox which can implement this script is at: https://devnetsandbox.cisco.com/RM/Diagram/Index/1228cb22-b2ba-48d3-a70a-86a53f4eecc0?diagramType=Topology


## Roadmap

The next version of the tool/utility will have the following items included:
 1. Support for User,Groups and Security Group Tags
 2. Inline expansion of Network objects (source and destination)
 3. Support for exporting NAT policies as CSV

## Author(s)

This project was written and is maintained by the following individuals:

* Raghunath Kulkarni <raghukul@cisco.com>

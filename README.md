# FMC Policy Export Tool

Python script to extract multiple policy types from Cisco Firepower Management Center (FMC) via REST API and export them to CSV format.

## Features

- **Authentication**: Secure API authentication with FMC 10.0
- **Multi-Domain Support**: Automatic detection and selection of FMC domains
  - Auto-selects if only one domain (Global)
  - Interactive selection for multi-domain deployments
- **Multi-Policy Support**: Export 5 different policy types:
  - Access Control Policies
  - NAT Policies
  - Prefilter Policies
  - SSL Policies
  - DNS Policies
- **Detailed Extraction**: Retrieves complete rule details for each policy type
- **CSV Export**: Generates CSV files with policy-specific columns
- **Pagination Handling**: Automatically handles large policy sets
- **Rate Limiting**: Manages API rate limits with automatic retry

## Requirements

- Python 3.7+
- Cisco FMC 10.0 or compatible version
- API user credentials with read access to access control policies
- For multi-domain environments: access permissions to desired domains

## Multi-Domain Support

The script automatically detects and handles FMC domain configurations:

### Single Domain (Global)
- **Behavior**: Automatically selects the only available domain
- **Use Case**: Standard single-tenant FMC deployments
- **Output**: Domain auto-selected, proceeds directly to policy selection

### Multi-Domain Deployments
- **Behavior**: Presents interactive domain selection menu
- **Use Case**: Multi-tenant FMC (MSP environments, large enterprises)
- **Domains Displayed**: All domains the API user has access to
- **Selection**: User chooses domain by number (1, 2, 3...)

### Domain Permissions
The API user must have appropriate permissions in the target domain:
- **Global Admin**: Access to all domains
- **Domain Admin**: Access to assigned domain(s) only
- **Read-Only**: Must have policy read access in the selected domain

### Example Multi-Domain Scenarios

**Scenario 1: MSP with Multiple Customers**
```
1. Global (DOMAIN) - Management domain
2. Customer_A (DOMAIN) - Tenant A policies
3. Customer_B (DOMAIN) - Tenant B policies
4. Customer_C (DOMAIN) - Tenant C policies

Select: 2 → Export policies for Customer_A
```

**Scenario 2: Large Enterprise with Regional Domains**
```
1. Global (DOMAIN) - Corporate global policies
2. Americas (DOMAIN) - North/South America policies
3. EMEA (DOMAIN) - Europe/Middle East/Africa policies
4. APAC (DOMAIN) - Asia-Pacific policies

Select: 3 → Export policies for EMEA region
```

**Scenario 3: Development/Production Separation**
```
1. Global (DOMAIN) - Production policies
2. Development (DOMAIN) - Dev/Test policies

Select: 1 → Export production policies
```

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests urllib3
```

## Usage

### Basic Usage

```bash
python3 fmc_get_config.py
```

The script will prompt for:
1. FMC IP address or hostname
2. API username
3. API password (hidden input)

### Interactive Workflow

1. **Authentication**: Script authenticates with FMC and retrieves domain UUID
2. **Policy Selection**: Displays all available access control policies
3. **Rule Extraction**: Fetches detailed information for each rule in selected policy
4. **CSV Export**: Generates CSV file named `fmc_access_policy_<POLICY_NAME>.csv`

### Example Session

```
================================================================================
FMC POLICY EXPORT TOOL
Cisco Firepower Management Center API v10.0
================================================================================

[*] Enter FMC connection details:
FMC IP Address or Hostname: 10.0.0.100
API Username: admin
API Password: ********

[*] Authenticating to FMC: 10.0.0.100
[✓] Authentication successful
[✓] Default Domain UUID: e276abec-e0f2-11e3-8169-6d9ed49b625f
[✓] Found 3 domain(s)

================================================================================
DOMAIN SELECTION
================================================================================
1. Global (DOMAIN)
2. Americas (DOMAIN)
3. EMEA (DOMAIN)

[*] Select domain (enter number):
Domain: 1
[✓] Selected domain UUID: e276abec-e0f2-11e3-8169-6d9ed49b625f
[✓] Selected domain: Global

================================================================================
POLICY TYPE SELECTION
================================================================================
1. Access Control Policies
2. NAT Policies
3. Prefilter Policies
4. SSL Policies
5. DNS Policies

[*] Select policy type (enter number):
Policy type: 1

[*] Fetching Access Control Policies...
[✓] Found 2 access control policies

================================================================================
AVAILABLE ACCESS CONTROL POLICIES
================================================================================
1. Corporate_Policy (ID: abc123...)
2. Guest_Policy (ID: def456...)

[*] Select policy to export (enter number):
Policy number: 1

[*] Selected policy: Corporate_Policy
[*] Fetching access control rules for policy ID: abc123...
[✓] Found 50 access control rules

[*] Exporting 50 rules to CSV: fmc_access_policy_Corporate_Policy.csv
[✓] CSV export complete

================================================================================
EXPORT COMPLETE
================================================================================
Policy Type: Access Control Policies
Policy Name: Corporate_Policy
Rules exported: 50
Output file: fmc_access_policy_Corporate_Policy.csv
================================================================================
```

### Single Domain (Auto-Selected)

```
[*] Authenticating to FMC: 10.0.0.100
[✓] Authentication successful
[✓] Default Domain UUID: e276abec-e0f2-11e3-8169-6d9ed49b625f
[✓] Found 1 domain(s)

[✓] Auto-selected domain: Global (UUID: e276abec-e0f2-11e3-8169-6d9ed49b625f)
[✓] Selected domain UUID: e276abec-e0f2-11e3-8169-6d9ed49b625f

================================================================================
POLICY TYPE SELECTION
================================================================================
```

## CSV Output Formats

The generated CSV format varies by policy type:

### Access Control Policy Columns
Policy, Rule ID, Rule Name, Enabled, Action, Source Zones, Source Networks, Source Ports, Destination Zones, Destination Networks, Destination Ports, Protocol, Applications, URLs, Users, IPS Policy, File Policy, Variable Set, Logging, Send Events To, Log Files, Log Connections, Comment, Section, Category

### NAT Policy Columns
Policy, Rule ID, Rule Name, Enabled, NAT Type, Interface In, Interface Out, Original Source, Original Destination, Original Source Port, Original Destination Port, Translated Source, Translated Destination, Translated Source Port, Translated Destination Port, Comment

### Prefilter Policy Columns
Policy, Rule ID, Rule Name, Enabled, Action, Source Zones, Source Networks, Source Ports, Destination Zones, Destination Networks, Destination Ports, Protocol, VLAN Tags, Logging, Comment

### SSL Policy Columns
Policy, Rule ID, Rule Name, Enabled, Action, Source Zones, Source Networks, Destination Zones, Destination Networks, Destination Ports, Certificate, URL Categories, URLs, Logging, Comment

### DNS Policy Columns
Policy, Rule ID, Rule Name, Enabled, Action, Source Zones, Source Networks, DNS Lists, URL Categories, Logging, Sinkhole, Comment

## API Endpoints Used

### Authentication & Domain Discovery
- `/api/fmc_platform/v1/auth/generatetoken` - Authentication
- `/api/fmc_platform/v1/info/domain` - List available domains

### Policy Discovery
- `/api/fmc_platform/v1/domain/{uuid}/policy/accesspolicies` - Access Control Policies
- `/api/fmc_platform/v1/domain/{uuid}/policy/ftdnatpolicies` - NAT Policies
- `/api/fmc_platform/v1/domain/{uuid}/policy/prefilterpolicies` - Prefilter Policies
- `/api/fmc_platform/v1/domain/{uuid}/policy/sslpolicies` - SSL Policies
- `/api/fmc_platform/v1/domain/{uuid}/policy/dnspolicies` - DNS Policies

### Rule Extraction
- `/api/fmc_platform/v1/domain/{uuid}/policy/accesspolicies/{id}/accessrules`
- `/api/fmc_platform/v1/domain/{uuid}/policy/ftdnatpolicies/{id}/natrules`
- `/api/fmc_platform/v1/domain/{uuid}/policy/prefilterpolicies/{id}/prefilterrules`
- `/api/fmc_platform/v1/domain/{uuid}/policy/sslpolicies/{id}/sslrules`
- `/api/fmc_platform/v1/domain/{uuid}/policy/dnspolicies/{id}/dnsrules`

## Troubleshooting

### SSL Certificate Errors
The script disables SSL verification by default for self-signed certificates. For production, consider:
```python
verify='/path/to/ca-bundle.crt'  # Instead of verify=False
```

### Rate Limiting
If you hit FMC API rate limits (429 errors), the script automatically waits 60 seconds and retries.

### Authentication Failures
- Verify credentials are correct
- Ensure user has API access enabled
- Check FMC is reachable on port 443
- Verify user has read permissions for access control policies

### Empty Results
- Check user permissions
- Verify policy exists and has rules
- Review FMC API logs: System > Integration > REST API Explorer

## FMC API Version Compatibility

This script is designed for **FMC API version 10.0** but should work with:
- FMC 7.0+ (API v1)
- Compatible with minor version differences

Check your FMC version:
```bash
curl -k -X POST https://<FMC-IP>/api/fmc_platform/v1/auth/generatetoken \
  -u username:password -I | grep "X-auth-access-token"
```

## Security Notes

- Passwords are not echoed to terminal (uses `getpass`)
- API tokens are stored in memory only
- SSL verification disabled for lab environments (modify for production)
- Credentials are never logged or written to disk


# Object Value Resolution Feature

## Overview
The FMC Policy Export Tool now includes **object value resolution** to expand object references and display their actual values in the CSV export.

## What This Means

### Before (Object Names Only)
```csv
Source Networks
ServerNetwork, WebServers
```

### After (With Values)
```csv
Source Networks,Source Networks (Values)
ServerNetwork, WebServers,"192.168.1.0/24, 10.0.1.10, 10.0.1.11"
```

## Expanded Columns

For Access Control Policies, the following additional columns are now included:

1. **Source Zones (Values)** - Zone details
2. **Source Networks (Values)** - IP addresses, CIDR blocks, ranges
3. **Source Ports (Values)** - Protocol/port combinations (e.g., TCP/443, UDP/53)
4. **Destination Zones (Values)** - Zone details
5. **Destination Networks (Values)** - IP addresses, CIDR blocks, ranges
6. **Destination Ports (Values)** - Protocol/port combinations
7. **Protocol (Values)** - Protocol specifications
8. **Applications (Values)** - Application details
9. **URLs (Values)** - URL patterns

## How It Works

### Object Resolution
The tool fetches detailed information for each object reference using FMC REST API:

- **Network Objects** → Resolved to IP addresses (192.168.1.10)
- **Network Groups** → Expanded to member IPs: `[GroupName=192.168.1.0/24, 10.0.1.0/24]`
- **Port Objects** → Resolved to protocol/port (TCP/443, UDP/53)
- **Port Groups** → Expanded to member ports: `[HTTPSPorts=TCP/443, TCP/8443]`
- **Host Objects** → IP address
- **Range Objects** → IP range (192.168.1.1-192.168.1.100)
- **FQDN Objects** → Domain name (example.com)

### Caching
- Object details are cached during export to minimize API calls
- If the same object appears in multiple rules, it's only fetched once
- Significantly improves performance for large policies

### Recursive Group Resolution
- Object groups are recursively expanded
- Nested groups show as: `[ParentGroup=[ChildGroup=values]]`
- Provides complete visibility into group membership

## Performance Considerations

### Export Time
- **Without value resolution**: ~1-2 seconds per rule
- **With value resolution**: ~5-10 seconds per rule (depending on object count)
- Progress updates shown every 5 rules

### API Rate Limiting
- Built-in delays (0.1s) between object lookups to avoid rate limiting
- FMC 429 (Rate Limit) responses are handled with automatic retry

## Usage

The feature is **automatically enabled** for Access Control Policy exports. When you export a policy:

```bash
python3 fmc_get_config.py
```

The tool will:
1. Fetch all policy rules
2. For each rule, resolve all object references to their values
3. Export both names and values to CSV

Console output will show:
```
[*] Exporting 50 rules to CSV: fmc_access_policy_MyPolicy.csv
[*] Object value resolution enabled - this may take a few minutes...
[*] Processing rule 5/50 for CSV export...
[*] Processing rule 10/50 for CSV export...
...
[✓] CSV export complete: fmc_access_policy_MyPolicy.csv
```

## Object Types Supported

| Object Type | API Endpoint | Value Format |
|------------|--------------|--------------|
| Host | `/object/hosts` | IP address |
| Network | `/object/networks` | CIDR notation |
| Range | `/object/ranges` | Start-End IPs |
| FQDN | `/object/fqdns` | Domain name |
| NetworkGroup | `/object/networkgroups` | Expanded members |
| ProtocolPortObject | `/object/protocolportobjects` | Protocol/Port |
| PortObjectGroup | `/object/portobjectgroups` | Expanded members |
| SecurityZone | `/object/securityzones` | Zone name |
| URL | `/object/urls` | URL pattern |

## CSV Output Structure

Each rule will have paired columns:

```csv
Source Networks, Source Networks (Values)
"ServerNetwork", "192.168.1.0/24"
"WebServerGroup", "[WebServerGroup=10.0.1.10, 10.0.1.11, 10.0.1.12]"
```

## Error Handling

If object details cannot be fetched:
- Falls back to object name
- Continues processing remaining objects
- No interruption to export process

## Future Enhancements

Planned for other policy types:
- NAT Policies - Original/translated object values
- Prefilter Policies - Network and port values
- SSL Policies - Certificate and URL values
- DNS Policies - DNS list values

## Technical Implementation

### Key Methods

**`FMCPolicyExtractor.get_object_details()`**
- Fetches object details from FMC API
- Maps object types to API endpoints
- Implements caching strategy

**`FMCPolicyExtractor.resolve_object_values()`**
- Resolves object references to values
- Handles literals and object groups
- Supports recursive expansion

**`CSVExporter.export_access_rules()`**
- Accepts optional `extractor` parameter
- Passes extractor to `_extract_rule_data()`
- Shows progress updates during export

### Cache Structure
```python
object_cache = {
    "Host:uuid-1234": {"type": "Host", "value": "192.168.1.10", ...},
    "Network:uuid-5678": {"type": "Network", "value": "10.0.0.0/24", ...}
}
```

## Example Output

### Rule Export
```csv
Policy,Rule ID,Rule Name,Action,Source Networks,Source Networks (Values),Destination Ports,Destination Ports (Values)
MyPolicy,1,Allow Web,ALLOW,"WebServers","[WebServers=192.168.1.10, 192.168.1.11]","HTTPS","[HTTPS=TCP/443]"
MyPolicy,2,Block External,BLOCK,"External-Net","[External-Net=0.0.0.0/0]","any","any"
```

## Troubleshooting

### Slow Export
- Normal for policies with many objects
- Progress updates shown every 5 rules
- Can take 5-10 minutes for 100+ rule policies

### Missing Values
- Check FMC API connectivity
- Verify object permissions
- Review console for API errors

### Incomplete Groups
- Nested groups may not fully expand if depth > 3 levels
- Check object references in FMC GUI

## API Reference

All object APIs follow pattern:
```
GET https://{fmc}/api/fmc_config/v1/domain/{uuid}/object/{type}/{id}
```

Response format:
```json
{
  "id": "uuid",
  "name": "ObjectName",
  "type": "Host",
  "value": "192.168.1.10",
  ...
}
```

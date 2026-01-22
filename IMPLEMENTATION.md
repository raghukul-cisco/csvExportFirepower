# FMC Access Control Policy Export - Implementation Summary

## What Was Created

A complete Python-based solution for extracting Cisco Firepower Management Center (FMC) access control policies via REST API and exporting them to CSV format.

### Files Created

1. **fmc_get_config.py** (19KB) - Main script with three core classes:
   - `FMCAuthenticator` - Handles API authentication and token management
   - `FMCPolicyExtractor` - Extracts policies and rules with full details
   - `CSVExporter` - Converts JSON data to CSV format

2. **requirements.txt** - Python dependencies (requests, urllib3)

3. **README.md** - Complete documentation with usage examples and troubleshooting

4. **example_usage.py** - Programmatic usage examples for developers

## Key Features Implemented

### 1. Authentication (FMCAuthenticator class)
```python
authenticator = FMCAuthenticator(fmc_host, username, password)
authenticator.authenticate()
```

**Implements:**
- Token-based authentication using `/api/fmc_platform/v1/auth/generatetoken`
- Extracts and stores X-auth-access-token and X-auth-refresh-token
- Automatically retrieves domain UUID from response headers
- Maintains authenticated session for subsequent API calls

**Key Method:**
- `authenticate()` - Returns True/False, stores tokens in headers

### 2. Policy & Rule Extraction (FMCPolicyExtractor class)

**Core Methods:**
- `get_access_policies()` - Lists all access control policies
- `get_access_rules(policy_id)` - Gets all rules for a specific policy
- `_paginate_results()` - Handles API pagination (100 items per page)
- `_make_request()` - Generic API request handler with rate limit retry

**Parameters Extracted Per Rule:**
- Source/Destination zones (security zones)
- Source/Destination networks (objects + literal IPs)
- Source/Destination ports (protocol/port objects)
- Protocols (TCP/UDP/ICMP/etc.)
- Applications (Layer 7 app filtering)
- URLs (URL filtering)
- Users (identity-based rules)
- IPS Policy (intrusion prevention)
- File Policy (file inspection/malware)
- Variable Set (policy variables)
- Logging configuration (begin/end/files)
- Action (ALLOW/BLOCK/TRUST/MONITOR)
- Enabled status
- Comments and metadata

**API Endpoints Used:**
```
GET /policy/accesspolicies                           # List policies
GET /policy/accesspolicies/{id}/accessrules          # List rules
GET /policy/accesspolicies/{id}/accessrules/{rule_id} # Rule details
```

**Pagination & Rate Limiting:**
- Automatically handles pagination with offset/limit
- Detects HTTP 429 (rate limit) and waits 60 seconds
- Expanded mode (`?expanded=true`) for detailed object info

### 3. CSV Export (CSVExporter class)

**CSV Columns (24 fields):**
```
Policy, Rule ID, Rule Name, Enabled, Action,
Source Zones, Source Networks, Source Ports,
Destination Zones, Destination Networks, Destination Ports,
Protocol, Applications, URLs, Users,
IPS Policy, File Policy, Variable Set,
Logging, Send Events To, Log Files, Log Connections,
Comment, Section, Category
```

**Export Method:**
- `export_access_rules(policy_name, rules)` - Writes CSV with all rule details
- Handles nested object structures (zones, networks, etc.)
- Converts object references to human-readable names
- Merges object names and literal values

## Usage Examples

### Interactive Mode (End User)
```bash
python3 fmc_get_config.py
# Prompts for: FMC IP, username, password
# Lists policies, asks for selection
# Exports to: fmc_access_policy_<POLICY_NAME>.csv
```

### Programmatic Mode (Automation)
```python
from fmc_get_config import FMCAuthenticator, FMCPolicyExtractor, CSVExporter

# Authenticate
auth = FMCAuthenticator("10.0.0.100", "admin", "password")
auth.authenticate()

# Extract
extractor = FMCPolicyExtractor(auth)
policies = extractor.get_access_policies()
rules = extractor.get_access_rules(policies[0]['id'])

# Export
exporter = CSVExporter("output.csv")
exporter.export_access_rules(policies[0]['name'], rules)
```

## FMC API v10.0 Compliance

### Authentication Flow
1. POST to `/auth/generatetoken` with Basic Auth
2. Receive tokens in response headers:
   - `X-auth-access-token` - Used for subsequent requests
   - `X-auth-refresh-token` - For token refresh (not currently used)
   - `DOMAIN_UUID` - Required for all API paths

3. Include token in all requests:
   ```
   X-auth-access-token: <token>
   ```

### API Request Pattern
```
https://{fmc_host}/api/fmc_platform/v1/domain/{uuid}/{endpoint}?offset=0&limit=100&expanded=true
```

**Query Parameters:**
- `offset` - Pagination offset (starts at 0)
- `limit` - Results per page (max 100)
- `expanded` - Get full object details (not just references)

### Response Structure
```json
{
  "items": [...],  // Array of objects
  "paging": {
    "offset": 0,
    "limit": 100,
    "count": 250,   // Total items
    "pages": 3
  }
}
```

## Detailed Parameter Extraction Logic

### Network Objects
```python
# Extract object names
source_networks = rule.get('sourceNetworks', {}).get('objects', [])
names = [obj.get('name') for obj in source_networks]

# Extract literal IPs
literals = rule.get('sourceNetworks', {}).get('literals', [])
ips = [lit.get('value') for lit in literals]

# Combined output: "OBJ-SUBNET-1, OBJ-HOST-2, 192.168.1.100, 10.0.0.0/24"
```

### Port Objects
```python
ports = rule.get('destinationPorts', {}).get('objects', [])
for port in ports:
    if port.get('type') == 'ProtocolPortObject':
        protocol = port.get('protocol')  # tcp/udp
        port_val = port.get('port')      # 443, 8080-8090
        # Output: "tcp/443", "udp/53"
```

### Logging Configuration
```python
log_begin = rule.get('logBegin', False)    # Log at session start
log_end = rule.get('logEnd', False)        # Log at session end
log_files = rule.get('logFiles', False)    # Log file events
send_to_fmc = rule.get('sendEventsToFMC', False)

# Output: "At Beginning, At End" or "Disabled"
```

### Action Values
- `ALLOW` - Permit traffic
- `TRUST` - Trust traffic (no deep inspection)
- `BLOCK` - Drop traffic with reset
- `BLOCK_RESET` - Drop traffic with reset
- `BLOCK_INTERACTIVE` - Block with user notification
- `MONITOR` - Allow and log

## Error Handling

**Authentication Errors:**
- HTTP 401: Invalid credentials
- HTTP 403: Insufficient permissions
- Connection timeout: FMC unreachable

**API Request Errors:**
- HTTP 404: Policy/rule not found
- HTTP 429: Rate limit exceeded (auto-retry after 60s)
- HTTP 500: FMC internal error

**CSV Export Errors:**
- File write permissions
- Disk space
- Invalid characters in policy name

## Integration with NG-FMT

### Combined Migration Workflow

**Phase 1: ASA Object Migration (NG-FMT)**
```bash
# Parse ASA config to JSON
python3 parseObjectsToJSON.py

# Generate Terraform for FMC
python3 generate_terraform_fmc.py

# Deploy to FMC
cd terraform_fmc && terraform apply
```

**Phase 2: Policy Documentation (fmc_get_config.py)**
```bash
# Export FMC policies for validation
python3 fmc_get_config.py
```

**Validation Use Cases:**
1. Compare ASA access-lists with FMC policies
2. Document post-migration policy state
3. Backup policies before changes
4. Generate compliance reports

### Data Flow Diagram
```
ASA "show tech" 
    ↓
[parseObjectsToJSON.py]
    ↓
json_output/*.json
    ↓
[generate_terraform_fmc.py]
    ↓
terraform_fmc/*.tf
    ↓
[terraform apply]
    ↓
FMC (Network Objects)
    ↓
[fmc_get_config.py]
    ↓
CSV Export (Access Policies)
```

## Security Considerations

1. **Password Handling:**
   - Uses `getpass` module (no echo to terminal)
   - Never logged or written to disk
   - Stored only in memory during execution

2. **SSL/TLS:**
   - Currently disables certificate verification (lab environments)
   - For production, use: `verify='/path/to/ca-bundle.crt'`

3. **Token Storage:**
   - Tokens stored in memory only
   - No persistent storage
   - Cleared on script exit

4. **API Permissions:**
   - Requires only read access to access control policies
   - No write/modify capabilities
   - Safe for production use

## Performance Optimization

**Current Implementation:**
- Pagination: 100 items per request (FMC max)
- Rate limiting: 60-second wait on HTTP 429
- Per-rule detail fetch: 0.5 second delay between requests

**For Large Policies:**
- 100 rules: ~60 seconds
- 500 rules: ~300 seconds (5 minutes)
- 1000 rules: ~600 seconds (10 minutes)

**Bottleneck:** Individual rule detail fetching (1 API call per rule)

**Future Optimization:**
- Batch rule fetching if API supports it
- Parallel requests with threading
- Rule detail caching

## Testing Recommendations

### Unit Tests
```python
# Test authentication
def test_authentication():
    auth = FMCAuthenticator("10.0.0.100", "user", "pass")
    assert auth.authenticate() == True

# Test pagination
def test_pagination():
    # Mock large response (>100 items)
    # Verify all items retrieved

# Test CSV export
def test_csv_generation():
    # Mock rules
    # Verify CSV columns and values
```

### Integration Tests
1. Test against FMC lab instance
2. Verify all rule parameters extracted
3. Compare CSV with manual FMC export
4. Test rate limiting behavior
5. Test authentication failure scenarios

## Known Limitations

1. **Refresh Token:** Not currently implemented (would extend session)
2. **Prefilter Policies:** Only access control policies supported
3. **Rule Sections:** Basic support (category/section fields)
4. **Object Details:** Only names extracted, not full object definitions
5. **Write Operations:** Read-only implementation

## Future Enhancements

1. **Export All Policies:** Batch export all policies without selection
2. **Object Resolution:** Expand object groups to show member details
3. **Policy Comparison:** Compare two policies and show differences
4. **Import Capability:** Create policies from CSV (reverse operation)
5. **NAT Policy Export:** Similar export for NAT policies
6. **VPN Export:** Export VPN configurations
7. **Terraform Generation:** Generate Terraform from FMC policies (reverse of NG-FMT)

## Maintenance Notes

**FMC API Version Updates:**
- Script targets v1 endpoint (`/api/fmc_platform/v1/`)
- FMC maintains backward compatibility
- Test with new FMC versions before production use

**Dependency Updates:**
- `requests`: Update for security patches
- `urllib3`: Keep in sync with requests

**Breaking Changes to Watch For:**
- Authentication mechanism changes
- Response structure modifications
- New required fields in rule objects
- Rate limit policy changes

## Documentation References

- **FMC REST API Guide:** https://www.cisco.com/c/en/us/td/docs/security/firepower/api/
- **API Explorer:** Available at `https://{FMC-IP}/api/api-explorer/`
- **CiscoDevNet FMC Provider:** https://registry.terraform.io/providers/CiscoDevNet/fmc/

---

**Created:** January 22, 2026
**Version:** 1.0
**Python:** 3.7+
**FMC API:** 10.0

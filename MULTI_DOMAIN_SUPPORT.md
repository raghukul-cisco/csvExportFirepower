# Multi-Domain Support - Implementation Summary

## Overview
Added comprehensive multi-domain support to the FMC Policy Export Tool, enabling seamless operation across single and multi-tenant FMC deployments.

## Key Features

### 1. Automatic Domain Detection
- Queries `/api/fmc_platform/v1/info/domain` after authentication
- Retrieves all domains the authenticated user has access to
- Stores domain information including UUID, name, and type

### 2. Intelligent Domain Selection

#### Single Domain Behavior (Auto-Select)
```
[✓] Found 1 domain(s)
[✓] Auto-selected domain: Global (UUID: e276abec-...)
```
- **When**: Only one domain exists (typically Global domain)
- **Action**: Automatically selects the domain
- **User Interaction**: None - proceeds directly to policy selection
- **Use Case**: Standard single-tenant FMC deployments

#### Multi-Domain Behavior (Interactive)
```
================================================================================
DOMAIN SELECTION
================================================================================
1. Global (DOMAIN)
2. Americas (DOMAIN)
3. EMEA (DOMAIN)

[*] Select domain (enter number):
Domain: 2
[✓] Selected domain: Americas
```
- **When**: Multiple domains exist
- **Action**: Displays interactive selection menu
- **User Interaction**: User selects domain by number
- **Use Case**: Multi-tenant FMC, MSP environments, large enterprises

### 3. Graceful Error Handling
- Falls back to default domain if domain fetch fails
- Handles network errors during domain retrieval
- Validates user domain selection input

## Code Changes

### FMCAuthenticator Class Updates

#### New Attributes
```python
self.available_domains = []  # List of domain dictionaries
```

#### New Methods
```python
def _fetch_domains(self) -> None:
    """Fetch available domains from FMC after authentication"""

def get_domains(self) -> List[Dict]:
    """Get list of available domains for user selection"""

def select_domain(self, domain_uuid: str) -> None:
    """Select a specific domain by UUID"""
```

#### Modified Methods
```python
def authenticate(self) -> bool:
    # ... existing auth logic ...
    # Now calls _fetch_domains() after successful auth
    self._fetch_domains()
    return True
```

### Main Function Updates

Added domain selection logic between authentication and policy type selection:

```python
# Domain selection
domains = authenticator.get_domains()

if len(domains) == 1:
    # Auto-select single domain
    domain = domains[0]
    print(f"Auto-selected domain: {domain.get('name')}")
    authenticator.select_domain(domain.get('uuid'))
else:
    # Multiple domains - user selection menu
    # Display numbered list
    # Get user input
    # Validate and select domain
```

## API Integration

### Domain Information Endpoint
```
GET /api/fmc_platform/v1/info/domain
```

**Response Format:**
```json
{
  "items": [
    {
      "uuid": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
      "name": "Global",
      "type": "DOMAIN"
    },
    {
      "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "Americas",
      "type": "DOMAIN"
    }
  ]
}
```

**Headers Required:**
- `X-auth-access-token`: Authentication token from login
- `Content-Type`: application/json

## Use Cases

### Use Case 1: Managed Service Provider (MSP)
**Scenario:** MSP managing multiple customer firewalls on single FMC

**Domain Structure:**
- Global (Management)
- Customer_A
- Customer_B
- Customer_C
- Customer_D

**Workflow:**
1. Admin logs in with credentials
2. Selects Customer_A domain
3. Exports all policies for Customer_A
4. Repeats for other customers as needed

**Benefit:** Clear separation of customer policies, no cross-contamination

---

### Use Case 2: Large Enterprise - Regional Deployment
**Scenario:** Global company with regional FMC domains

**Domain Structure:**
- Global (Corporate policies)
- Americas (North/South America)
- EMEA (Europe, Middle East, Africa)
- APAC (Asia-Pacific)

**Workflow:**
1. Regional admin logs in
2. Selects their region (e.g., EMEA)
3. Exports regional access control policies
4. Exports regional NAT policies for documentation

**Benefit:** Regional autonomy, compliance with data residency requirements

---

### Use Case 3: Development/Test/Production Separation
**Scenario:** Separate domains for different environments

**Domain Structure:**
- Global (Production)
- Development
- Staging
- DR (Disaster Recovery)

**Workflow:**
1. DevOps logs in
2. Selects Development domain
3. Exports policies for comparison with Production
4. Validates changes before promoting to Production

**Benefit:** Safe testing environment, policy drift detection

---

### Use Case 4: Compliance Auditing
**Scenario:** Security auditor reviewing multi-domain policies

**Workflow:**
1. Auditor logs in with read-only access
2. For each domain:
   - Select domain
   - Export Access Control policies
   - Export NAT policies
   - Export SSL policies
3. Generate compliance reports per domain

**Benefit:** Comprehensive audit trail, per-domain compliance verification

## User Experience Flow

### Flow 1: Single Domain (Typical)
```
┌─────────────────────────────────────┐
│ 1. Enter credentials                │
├─────────────────────────────────────┤
│ 2. Authenticate                     │
├─────────────────────────────────────┤
│ 3. Fetch domains → 1 found          │
├─────────────────────────────────────┤
│ 4. Auto-select Global               │ ← No user interaction
├─────────────────────────────────────┤
│ 5. Select policy type               │
├─────────────────────────────────────┤
│ 6. Select policy                    │
├─────────────────────────────────────┤
│ 7. Export to CSV                    │
└─────────────────────────────────────┘
```

### Flow 2: Multi-Domain
```
┌─────────────────────────────────────┐
│ 1. Enter credentials                │
├─────────────────────────────────────┤
│ 2. Authenticate                     │
├─────────────────────────────────────┤
│ 3. Fetch domains → 4 found          │
├─────────────────────────────────────┤
│ 4. Display domain menu              │
│    1. Global                        │
│    2. Americas                      │
│    3. EMEA                          │
│    4. APAC                          │
├─────────────────────────────────────┤
│ 5. User selects domain (e.g., 2)   │ ← User interaction
├─────────────────────────────────────┤
│ 6. Select policy type               │
├─────────────────────────────────────┤
│ 7. Select policy                    │
├─────────────────────────────────────┤
│ 8. Export to CSV                    │
└─────────────────────────────────────┘
```

## Error Handling

### Scenario 1: Domain Fetch Failure
```python
# Network error or API unavailable
# Fallback to default domain from auth headers
self.available_domains = [{'uuid': self.domain_uuid, 'name': 'Global', 'type': 'DOMAIN'}]
```

### Scenario 2: Invalid Domain Selection
```python
# User enters invalid number or non-numeric input
print("[✗] Invalid selection. Exiting.")
sys.exit(1)
```

### Scenario 3: No Domains Available
```python
# User has no domain access (shouldn't happen after successful auth)
print("[✗] No domains available. Exiting.")
sys.exit(1)
```

## Programmatic Usage

### Example 1: Explicit Domain Selection
```python
from fmc_get_config import FMCAuthenticator, FMCPolicyExtractor, CSVExporter

# Authenticate
auth = FMCAuthenticator("10.0.0.100", "admin", "password")
auth.authenticate()

# Get available domains
domains = auth.get_domains()
print(f"Available domains: {[d['name'] for d in domains]}")

# Select specific domain by name
for domain in domains:
    if domain['name'] == 'Americas':
        auth.select_domain(domain['uuid'])
        break

# Now extract policies from Americas domain
extractor = FMCPolicyExtractor(auth)
policies = extractor.get_policies('access')
```

### Example 2: Iterate Through All Domains
```python
auth = FMCAuthenticator("10.0.0.100", "admin", "password")
auth.authenticate()

# Export policies from all domains
for domain in auth.get_domains():
    print(f"Processing domain: {domain['name']}")
    auth.select_domain(domain['uuid'])
    
    extractor = FMCPolicyExtractor(auth)
    
    # Export Access Control policies
    access_policies = extractor.get_policies('access')
    for policy in access_policies:
        rules = extractor.get_access_rules(policy['id'])
        output_file = f"{domain['name']}_access_{policy['name']}.csv"
        exporter = CSVExporter(output_file)
        exporter.export_access_rules(policy['name'], rules)
    
    # Export NAT policies
    nat_policies = extractor.get_policies('nat')
    for policy in nat_policies:
        rules = extractor.get_nat_rules(policy['id'])
        output_file = f"{domain['name']}_nat_{policy['name']}.csv"
        exporter = CSVExporter(output_file)
        exporter.export_nat_rules(policy['name'], rules)
```

### Example 3: Domain-Aware Batch Export
```python
def export_all_domains(fmc_host, username, password):
    """Export policies from all domains to separate directories"""
    import os
    
    auth = FMCAuthenticator(fmc_host, username, password)
    auth.authenticate()
    
    for domain in auth.get_domains():
        domain_name = domain['name'].replace(' ', '_')
        output_dir = f"exports/{domain_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        auth.select_domain(domain['uuid'])
        extractor = FMCPolicyExtractor(auth)
        
        # Export all policy types
        for policy_type in ['access', 'nat', 'prefilter', 'ssl', 'dns']:
            policies = extractor.get_policies(policy_type)
            for policy in policies:
                # Extract and export based on type
                # ... (implementation details)
                
        print(f"Completed export for domain: {domain_name}")
```

## Testing Recommendations

### Test Case 1: Single Domain Environment
```bash
# Test with standard FMC (single Global domain)
python3 fmc_get_config.py

Expected:
- Auto-select Global domain
- No domain selection menu
- Proceed to policy type selection
```

### Test Case 2: Multi-Domain Environment
```bash
# Test with MSP or multi-tenant FMC
python3 fmc_get_config.py

Expected:
- Display domain selection menu
- Show all accessible domains
- Accept valid domain number selection
- Reject invalid selections
```

### Test Case 3: Limited Domain Access
```bash
# Test with user that has access to specific domain only
python3 fmc_get_config.py

Expected:
- Show only authorized domains
- May auto-select if only one accessible
- No Global domain if user is domain-specific
```

### Test Case 4: Domain API Failure
```bash
# Simulate network issue during domain fetch
# (requires test harness or network simulation)

Expected:
- Fallback to default domain from auth
- Display warning message
- Continue with default domain
```

## Security Considerations

### Domain Isolation
- Users only see domains they have permissions for
- API enforces domain-level RBAC
- No cross-domain data leakage

### Audit Trail
- Domain selection logged in script output
- CSV files can be tagged with domain name
- Clear traceability for compliance

### Principle of Least Privilege
- Users should only have access to domains they need
- Read-only access sufficient for policy export
- No write operations performed

## Performance Impact

### Additional API Call
- 1 extra API call to `/info/domain` after auth
- Typical response time: < 500ms
- Negligible impact on overall execution time

### Memory Footprint
- Domain list typically small (< 100 domains)
- Minimal memory overhead
- No performance degradation

## Documentation Updates

### Updated Files
- ✅ `fmc_get_config.py` - Core implementation
- ✅ `README.md` - User documentation with multi-domain examples
- ✅ `example_usage.py` - Programmatic examples
- ✅ `MULTI_DOMAIN_SUPPORT.md` - This comprehensive guide

### Recommended Updates
- 📝 `TESTING.md` - Add multi-domain test cases
- 📝 `IMPLEMENTATION.md` - Update architecture diagrams

## Future Enhancements

### 1. Domain Filtering
```python
# Filter domains by type or name pattern
python3 fmc_get_config.py --domain-filter "Customer_*"
```

### 2. Parallel Domain Export
```python
# Export from multiple domains simultaneously
python3 fmc_get_config.py --export-all-domains --parallel
```

### 3. Domain Comparison
```python
# Compare policies across domains
python3 fmc_get_config.py --compare-domains \
  --domain1 "Production" \
  --domain2 "Development"
```

### 4. Domain Configuration Export
```python
# Export domain-level settings (not just policies)
python3 fmc_get_config.py --export-domain-config
```

## Backward Compatibility

The changes are **fully backward compatible**:

- Existing single-domain deployments work without modification
- No breaking changes to API interfaces
- Legacy code using `authenticator.domain_uuid` continues to work
- Auto-selection in single-domain scenarios maintains previous UX

---

**Version:** 2.1  
**Release Date:** January 22, 2026  
**Changes:** Added multi-domain support with auto-selection and interactive menu

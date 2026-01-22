# Multi-Policy Support - Feature Summary

## Overview
The FMC Policy Export Tool now supports **5 different policy types** instead of just Access Control Policies.

## Supported Policy Types

### 1. Access Control Policies (Original)
**API Endpoint:** `/policy/accesspolicies/{id}/accessrules`

**Exported Parameters:**
- Source/Destination zones and networks
- Ports and protocols
- Applications and URLs
- User-based rules
- IPS and File policies
- Logging configuration
- Actions: ALLOW, BLOCK, TRUST, MONITOR

**CSV Columns:** 24 fields

---

### 2. NAT Policies (NEW)
**API Endpoint:** `/policy/ftdnatpolicies/{id}/natrules`

**Exported Parameters:**
- NAT Type (Auto, Manual, Static, Dynamic)
- Interface In/Out
- Original Source/Destination networks
- Translated Source/Destination networks
- Port translations (PAT)
- Original/Translated ports

**CSV Columns:** 16 fields

**Use Cases:**
- Document NAT configurations
- Audit address translations
- Compare ASA NAT with FMC NAT rules

---

### 3. Prefilter Policies (NEW)
**API Endpoint:** `/policy/prefilterpolicies/{id}/prefilterrules`

**Exported Parameters:**
- Source/Destination zones and networks
- Ports and protocols
- VLAN tags
- Tunnel endpoints
- Actions: FASTPATH, ANALYZE, BLOCK
- Logging configuration

**CSV Columns:** 15 fields

**Use Cases:**
- High-performance rule optimization
- Tunnel traffic handling
- VLAN-based filtering

---

### 4. SSL Policies (NEW)
**API Endpoint:** `/policy/sslpolicies/{id}/sslrules`

**Exported Parameters:**
- Source/Destination zones and networks
- Destination ports
- SSL certificates
- URL categories and URLs
- Actions: DO_NOT_DECRYPT, DECRYPT_RESIGN, DECRYPT_KNOWN_KEY
- Logging configuration

**CSV Columns:** 15 fields

**Use Cases:**
- SSL/TLS decryption policies
- Certificate management
- Privacy compliance documentation

---

### 5. DNS Policies (NEW)
**API Endpoint:** `/policy/dnspolicies/{id}/dnsrules`

**Exported Parameters:**
- Source zones and networks
- DNS lists (domain names)
- URL categories
- Sinkhole configuration
- Actions: MONITOR, BLOCK
- Logging configuration

**CSV Columns:** 12 fields

**Use Cases:**
- DNS-based threat blocking
- Malicious domain filtering
- DNS sinkhole configuration

---

## User Interface Updates

### Policy Type Selection Menu
```
================================================================================
POLICY TYPE SELECTION
================================================================================
1. Access Control Policies
2. NAT Policies
3. Prefilter Policies
4. SSL Policies
5. DNS Policies

[*] Select policy type (enter number):
Policy type: _
```

### Output File Naming
Files are named based on policy type:
- `fmc_access_policy_{name}.csv`
- `fmc_nat_policy_{name}.csv`
- `fmc_prefilter_policy_{name}.csv`
- `fmc_ssl_policy_{name}.csv`
- `fmc_dns_policy_{name}.csv`

---

## Code Architecture

### New Methods in FMCPolicyExtractor

```python
# Generic policy fetcher
get_policies(policy_type: str) -> List[Dict]

# Policy-specific rule extractors
get_nat_rules(policy_id: str) -> List[Dict]
get_prefilter_rules(policy_id: str) -> List[Dict]
get_ssl_rules(policy_id: str) -> List[Dict]
get_dns_rules(policy_id: str) -> List[Dict]
```

### New Methods in CSVExporter

```python
# Policy-specific CSV exporters
export_nat_rules(policy_name: str, rules: List[Dict]) -> None
export_prefilter_rules(policy_name: str, rules: List[Dict]) -> None
export_ssl_rules(policy_name: str, rules: List[Dict]) -> None
export_dns_rules(policy_name: str, rules: List[Dict]) -> None

# Policy-specific data extractors
_extract_nat_rule_data(policy_name: str, rule: Dict) -> Dict[str, str]
_extract_prefilter_rule_data(policy_name: str, rule: Dict) -> Dict[str, str]
_extract_ssl_rule_data(policy_name: str, rule: Dict) -> Dict[str, str]
_extract_dns_rule_data(policy_name: str, rule: Dict) -> Dict[str, str]
```

### Policy Type Constants

```python
POLICY_TYPES = {
    'access': {'name': 'Access Control Policies', 'endpoint': 'policy/accesspolicies'},
    'nat': {'name': 'NAT Policies', 'endpoint': 'policy/ftdnatpolicies'},
    'prefilter': {'name': 'Prefilter Policies', 'endpoint': 'policy/prefilterpolicies'},
    'ssl': {'name': 'SSL Policies', 'endpoint': 'policy/sslpolicies'},
    'dns': {'name': 'DNS Policies', 'endpoint': 'policy/dnspolicies'}
}
```

---

## Usage Examples

### Export NAT Policy
```bash
python3 fmc_get_config.py
# Select: 2. NAT Policies
# Choose policy from list
# Output: fmc_nat_policy_FTD_NAT.csv
```

### Export Prefilter Policy
```bash
python3 fmc_get_config.py
# Select: 3. Prefilter Policies
# Choose policy from list
# Output: fmc_prefilter_policy_Tunnel_Rules.csv
```

### Export SSL Policy
```bash
python3 fmc_get_config.py
# Select: 4. SSL Policies
# Choose policy from list
# Output: fmc_ssl_policy_SSL_Decrypt.csv
```

### Export DNS Policy
```bash
python3 fmc_get_config.py
# Select: 5. DNS Policies
# Choose policy from list
# Output: fmc_dns_policy_DNS_Security.csv
```

---

## Programmatic Usage

```python
from fmc_get_config import FMCAuthenticator, FMCPolicyExtractor, CSVExporter

# Authenticate
auth = FMCAuthenticator("10.0.0.100", "admin", "password")
auth.authenticate()

extractor = FMCPolicyExtractor(auth)

# Export NAT policies
nat_policies = extractor.get_policies('nat')
nat_rules = extractor.get_nat_rules(nat_policies[0]['id'])
exporter = CSVExporter("nat_export.csv")
exporter.export_nat_rules(nat_policies[0]['name'], nat_rules)

# Export Prefilter policies
prefilter_policies = extractor.get_policies('prefilter')
prefilter_rules = extractor.get_prefilter_rules(prefilter_policies[0]['id'])
exporter = CSVExporter("prefilter_export.csv")
exporter.export_prefilter_rules(prefilter_policies[0]['name'], prefilter_rules)

# Export SSL policies
ssl_policies = extractor.get_policies('ssl')
ssl_rules = extractor.get_ssl_rules(ssl_policies[0]['id'])
exporter = CSVExporter("ssl_export.csv")
exporter.export_ssl_rules(ssl_policies[0]['name'], ssl_rules)

# Export DNS policies
dns_policies = extractor.get_policies('dns')
dns_rules = extractor.get_dns_rules(dns_policies[0]['id'])
exporter = CSVExporter("dns_export.csv")
exporter.export_dns_rules(dns_policies[0]['name'], dns_rules)
```

---

## Testing Checklist

### NAT Policies
- [ ] Export auto NAT rules
- [ ] Export manual NAT rules
- [ ] Verify source/destination translations
- [ ] Check port translations (PAT)
- [ ] Validate interface assignments

### Prefilter Policies
- [ ] Export FASTPATH rules
- [ ] Export ANALYZE rules
- [ ] Verify VLAN tag filtering
- [ ] Check tunnel endpoint rules
- [ ] Validate high-speed bypass rules

### SSL Policies
- [ ] Export decrypt-resign rules
- [ ] Export do-not-decrypt rules
- [ ] Verify certificate assignments
- [ ] Check URL category filtering
- [ ] Validate known-key decryption

### DNS Policies
- [ ] Export DNS block rules
- [ ] Export DNS monitor rules
- [ ] Verify DNS list assignments
- [ ] Check sinkhole configuration
- [ ] Validate URL category filtering

---

## Migration Impact

### ASA to FMC Migration
The multi-policy support enhances the NG-FMT workflow:

1. **ASA NAT → FMC NAT**: Export FMC NAT policies to compare with ASA NAT rules
2. **ASA ACLs → FMC Access/Prefilter**: Export both policy types for validation
3. **Documentation**: Export all policy types for complete migration documentation

### Validation Workflow
```bash
# Phase 1: Migrate objects (NG-FMT)
python3 parseObjectsToJSON.py
python3 generate_terraform_fmc.py
terraform apply

# Phase 2: Export all FMC policies (Policy-CSV-Generation)
python3 fmc_get_config.py  # Select Access Control
python3 fmc_get_config.py  # Select NAT
python3 fmc_get_config.py  # Select Prefilter
python3 fmc_get_config.py  # Select SSL
python3 fmc_get_config.py  # Select DNS

# Phase 3: Compare and validate
# - Compare ASA NAT with FMC NAT CSV
# - Compare ASA ACLs with FMC Access Control CSV
# - Document any discrepancies
```

---

## Backward Compatibility

The original `get_access_policies()` method is preserved as a legacy wrapper:

```python
def get_access_policies(self) -> List[Dict]:
    """Legacy method - Get all access control policies"""
    return self.get_policies('access')
```

This ensures existing code/scripts continue to work without modification.

---

## Future Enhancements

### Potential Additional Policy Types
1. **Network Analysis Policies** (IPS/Intrusion)
2. **File Policies** (Malware/File inspection)
3. **Security Intelligence Policies**
4. **Correlation Policies**
5. **Identity Policies**

### Batch Export Feature
```python
# Export all policy types at once
python3 fmc_get_config.py --export-all --policy-name "Corporate"
# Output:
# - fmc_access_policy_Corporate.csv
# - fmc_nat_policy_Corporate.csv
# - fmc_prefilter_policy_Corporate.csv
# - fmc_ssl_policy_Corporate.csv
# - fmc_dns_policy_Corporate.csv
```

### Policy Comparison
```python
# Compare two policies of the same type
python3 fmc_get_config.py --compare \
  --policy1 "Old_NAT_Policy" \
  --policy2 "New_NAT_Policy" \
  --output diff_report.csv
```

---

## Performance Notes

**Per-Policy Type:**
- Access Control: Most complex, slowest (detailed rule fetch)
- NAT: Medium speed (simpler rule structure)
- Prefilter: Fast (fewer parameters)
- SSL: Fast (fewer parameters)
- DNS: Fastest (simplest rule structure)

**Estimation:**
- Access Control: ~0.5s per rule
- NAT: ~0.3s per rule
- Prefilter/SSL/DNS: ~0.2s per rule

---

## Documentation Updates

Updated files:
- ✅ `fmc_get_config.py` - Core implementation
- ✅ `README.md` - User documentation
- ⚠️  `IMPLEMENTATION.md` - Needs update for new policy types
- ⚠️  `example_usage.py` - Needs examples for new policy types
- ⚠️  `TESTING.md` - Needs test cases for new policy types

---

**Version:** 2.0  
**Release Date:** January 22, 2026  
**Changes:** Added NAT, Prefilter, SSL, and DNS policy support

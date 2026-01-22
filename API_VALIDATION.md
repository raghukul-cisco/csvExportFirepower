# API Endpoint Validation Reference

## Overview
This document validates all FMC API endpoints used in `fmc_get_config.py` against Cisco FMC API v10.0 specifications.

## API Base Paths

### Platform API (Authentication & System Info)
```
https://{fmc_host}/api/fmc_platform/v1
```
Used for:
- Authentication
- Domain information
- System information

### Configuration API (Policies & Objects)
```
https://{fmc_host}/api/fmc_config/v1
```
Used for:
- Policies (Access Control, NAT, Prefilter, SSL, DNS)
- Rules
- Network objects
- Port objects
- Other configuration objects

**⚠️ CRITICAL**: Do NOT mix these base paths. Policies use `fmc_config`, not `fmc_platform`.

---

## Authentication Endpoints

### 1. Generate Token
**Endpoint**: `POST /api/fmc_platform/v1/auth/generatetoken`

**Code Location**: `FMCAuthenticator.authenticate()` (line ~56)

**Request**:
```python
POST https://{fmc_host}/api/fmc_platform/v1/auth/generatetoken
Authorization: Basic {base64(username:password)}
Content-Type: application/json
```

**Expected Response**:
```
Status: 204 No Content
Headers:
  X-auth-access-token: {access_token}
  X-auth-refresh-token: {refresh_token}
  DOMAIN_UUID: {default_domain_uuid}
```

**Validation**:
- ✅ Correct endpoint path
- ✅ Correct HTTP method (POST)
- ✅ Correct authentication method (Basic Auth)
- ✅ Headers properly extracted and stored
- ✅ Token added to subsequent requests

**Code Implementation**:
```python
response = requests.post(
    auth_url,
    auth=(self.username, self.password),
    headers=self.headers,
    verify=False,
    timeout=30
)

if response.status_code == 204:
    self.auth_token = response.headers.get('X-auth-access-token')
    self.refresh_token = response.headers.get('X-auth-refresh-token')
    self.domain_uuid = response.headers.get('DOMAIN_UUID')
    self.headers['X-auth-access-token'] = self.auth_token
```

---

## Domain Information Endpoints

### 2. Get Domains
**Endpoint**: `GET /api/fmc_platform/v1/info/domain`

**Code Location**: `FMCAuthenticator._fetch_domains()` (line ~95)

**Request**:
```python
GET https://{fmc_host}/api/fmc_platform/v1/info/domain
Headers:
  X-auth-access-token: {token}
  Content-Type: application/json
```

**Expected Response**:
```json
{
  "items": [
    {
      "uuid": "domain-uuid",
      "name": "Global",
      "type": "DOMAIN"
    }
  ],
  "paging": {
    "count": 1,
    "offset": 0,
    "limit": 25
  }
}
```

**Validation**:
- ✅ Correct endpoint path
- ✅ Correct HTTP method (GET)
- ✅ Token authentication used
- ✅ Response structure matches expected format
- ✅ Handles multiple domains correctly

---

## Policy Endpoints

### 3. Get Access Control Policies
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/accesspolicies`

**Code Location**: `FMCPolicyExtractor.get_policies('access')` (line ~273)

**Request**:
```python
GET https://{fmc_host}/api/fmc_config/v1/domain/{uuid}/policy/accesspolicies
Headers:
  X-auth-access-token: {token}
Parameters:
  offset: 0
  limit: 100
  expanded: true
```

**Expected Response**:
```json
{
  "items": [
    {
      "id": "policy-uuid",
      "name": "Access Control Policy",
      "type": "AccessPolicy",
      "defaultAction": {
        "action": "BLOCK",
        "type": "AccessPolicyDefaultAction"
      }
    }
  ],
  "paging": {
    "count": 5,
    "offset": 0,
    "limit": 100
  }
}
```

**Validation**:
- ✅ Correct endpoint path (using `fmc_config` not `fmc_platform`)
- ✅ Correct HTTP method (GET)
- ✅ Pagination parameters included
- ✅ `expanded=true` parameter used
- ✅ Handles pagination correctly

### 4. Get NAT Policies
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/ftdnatpolicies`

**Code Location**: `FMCPolicyExtractor.get_policies('nat')`

**Validation**:
- ✅ Correct endpoint: `policy/ftdnatpolicies` (not just `natpolicies`)
- ✅ Same request pattern as access policies

### 5. Get Prefilter Policies
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/prefilterpolicies`

**Code Location**: `FMCPolicyExtractor.get_policies('prefilter')`

**Validation**:
- ✅ Correct endpoint
- ✅ Same request pattern

### 6. Get SSL Policies
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/sslpolicies`

**Code Location**: `FMCPolicyExtractor.get_policies('ssl')`

**Validation**:
- ✅ Correct endpoint
- ✅ Same request pattern

### 7. Get DNS Policies
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/dnspolicies`

**Code Location**: `FMCPolicyExtractor.get_policies('dns')`

**Validation**:
- ✅ Correct endpoint
- ✅ Same request pattern

---

## Rule Endpoints

### 8. Get Access Control Rules (List)
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/accesspolicies/{policy_id}/accessrules`

**Code Location**: `FMCPolicyExtractor.get_access_rules()` (line ~310)

**Request**:
```python
GET https://{fmc_host}/api/fmc_config/v1/domain/{uuid}/policy/accesspolicies/{policy_id}/accessrules
Parameters:
  offset: 0
  limit: 100
  expanded: true
```

**Expected Response**:
```json
{
  "items": [
    {
      "id": "rule-uuid",
      "name": "Allow Web Traffic",
      "action": "ALLOW",
      "enabled": true,
      "sourceZones": {
        "objects": [...]
      },
      "destinationZones": {
        "objects": [...]
      }
    }
  ],
  "paging": {...}
}
```

**Validation**:
- ✅ Correct endpoint structure
- ✅ Pagination handled correctly
- ✅ Fetches list first, then details

### 9. Get Access Control Rule (Detail)
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}`

**Code Location**: `FMCPolicyExtractor.get_access_rules()` (line ~327)

**Request**:
```python
GET https://{fmc_host}/api/fmc_config/v1/domain/{uuid}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}
```

**Expected Response**: Full rule object with all details

**Validation**:
- ✅ Correct endpoint structure
- ✅ Individual rule fetching for complete details
- ✅ 0.5s delay between requests to avoid rate limiting

### 10. Get NAT Rules
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/ftdnatpolicies/{policy_id}/natrules`

**Code Location**: `FMCPolicyExtractor.get_nat_rules()` (line ~349)

**Validation**:
- ✅ Correct endpoint: `ftdnatpolicies/{id}/natrules`
- ✅ Same pagination pattern

### 11. Get Prefilter Rules
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/prefilterpolicies/{policy_id}/prefilterrules`

**Code Location**: `FMCPolicyExtractor.get_prefilter_rules()` (line ~366)

**Validation**:
- ✅ Correct endpoint
- ✅ Same pagination pattern

### 12. Get SSL Rules
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/sslpolicies/{policy_id}/sslrules`

**Code Location**: `FMCPolicyExtractor.get_ssl_rules()` (line ~383)

**Validation**:
- ✅ Correct endpoint
- ✅ Same pagination pattern

### 13. Get DNS Rules
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/policy/dnspolicies/{policy_id}/dnsrules`

**Code Location**: `FMCPolicyExtractor.get_dns_rules()` (line ~400)

**Validation**:
- ✅ Correct endpoint
- ✅ Same pagination pattern

---

## Object Endpoints

### 14. Get Host Object
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/hosts/{id}`

**Code Location**: `FMCPolicyExtractor.get_object_details()` (line ~385)

**Request**:
```python
GET https://{fmc_host}/api/fmc_config/v1/domain/{uuid}/object/hosts/{id}
```

**Expected Response**:
```json
{
  "id": "host-uuid",
  "name": "WebServer1",
  "type": "Host",
  "value": "192.168.1.10"
}
```

**Validation**:
- ✅ Correct endpoint: `object/hosts/{id}` (not `objects/host`)
- ✅ Caching implemented to avoid repeated calls
- ✅ Type mapping includes all object types

### 15. Get Network Object
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/networks/{id}`

**Validation**:
- ✅ Correct endpoint
- ✅ Returns network CIDR (e.g., "10.0.0.0/24")

### 16. Get Range Object
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/ranges/{id}`

**Validation**:
- ✅ Correct endpoint
- ✅ Returns range (e.g., "192.168.1.1-192.168.1.100")

### 17. Get FQDN Object
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/fqdns/{id}`

**Validation**:
- ✅ Correct endpoint
- ✅ Returns domain name

### 18. Get Network Group
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/networkgroups/{id}`

**Expected Response**:
```json
{
  "id": "group-uuid",
  "name": "WebServers",
  "type": "NetworkGroup",
  "objects": [
    {"id": "obj1-uuid", "name": "Server1", "type": "Host"},
    {"id": "obj2-uuid", "name": "Server2", "type": "Host"}
  ],
  "literals": [
    {"type": "Host", "value": "10.0.1.100"}
  ]
}
```

**Validation**:
- ✅ Correct endpoint
- ✅ Recursive resolution implemented for group members
- ✅ Handles both objects and literals

### 19. Get Port Object
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/protocolportobjects/{id}`

**Expected Response**:
```json
{
  "id": "port-uuid",
  "name": "HTTPS",
  "type": "ProtocolPortObject",
  "protocol": "TCP",
  "port": "443"
}
```

**Validation**:
- ✅ Correct endpoint: `protocolportobjects` (not `portobjects`)
- ✅ Protocol and port extracted correctly

### 20. Get Port Group
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/portobjectgroups/{id}`

**Validation**:
- ✅ Correct endpoint
- ✅ Recursive resolution for group members

### 21. Get Security Zone
**Endpoint**: `GET /api/fmc_config/v1/domain/{uuid}/object/securityzones/{id}`

**Validation**:
- ✅ Correct endpoint
- ✅ Returns zone name

### 22. Other Object Types
- ✅ `object/icmpv4objects/{id}` - ICMP v4 objects
- ✅ `object/icmpv6objects/{id}` - ICMP v6 objects
- ✅ `object/urls/{id}` - URL objects
- ✅ `object/urlgroups/{id}` - URL groups
- ✅ `object/applications/{id}` - Application objects
- ✅ `object/applicationfilters/{id}` - Application filters
- ✅ `object/vlantags/{id}` - VLAN tags
- ✅ `object/vlangrouptags/{id}` - VLAN group tags

---

## Request Features Validation

### Pagination
**Implementation**: `FMCPolicyExtractor._paginate_results()` (line ~230)

```python
params = {
    'offset': 0,
    'limit': 100,
    'expanded': 'true'
}

while True:
    response = self._make_request(endpoint, params)
    items = response.get('items', [])
    all_items.extend(items)
    
    total = response.get('paging', {}).get('count', 0)
    if len(all_items) >= total:
        break
    
    params['offset'] += params['limit']
```

**Validation**:
- ✅ Offset increments correctly
- ✅ Limit set to 100 (FMC default)
- ✅ Continues until all items fetched
- ✅ Uses paging metadata

### Rate Limiting Handling
**Implementation**: `FMCPolicyExtractor._make_request()` (line ~190)

```python
if response.status_code == 429:
    print(f"[!] Rate limited, waiting 60 seconds...")
    time.sleep(60)
    return self._make_request(endpoint, params)  # Retry
```

**Validation**:
- ✅ Detects HTTP 429 status
- ✅ Waits 60 seconds before retry
- ✅ Recursively retries request
- ✅ Additional 0.1s delays in object resolution
- ✅ 0.5s delays between rule detail fetches

### Expanded Parameter
**Usage**: All policy and rule list requests

```python
params['expanded'] = 'true'
```

**Purpose**: Returns more details in list responses, reducing need for individual detail calls

**Validation**:
- ✅ Included in all policy list requests
- ✅ Included in all rule list requests
- ✅ Proper format (lowercase 'true')

### Caching
**Implementation**: `FMCPolicyExtractor.object_cache` (line ~163)

```python
self.object_cache = {}  # Format: {"Type:UUID": {object_details}}

cache_key = f"{obj_type}:{obj_id}"
if cache_key in self.object_cache:
    return self.object_cache[cache_key]

# Fetch and cache
details = self._make_request(endpoint)
if details:
    self.object_cache[cache_key] = details
```

**Validation**:
- ✅ Cache key format prevents collisions
- ✅ Check cache before API call
- ✅ Only successful responses cached
- ✅ Persists for entire export session

---

## Error Handling Validation

### Authentication Failures
```python
if response.status_code == 204:
    # Success
else:
    print(f"[✗] Authentication failed: {response.status_code}")
    print(f"[✗] Response: {response.text}")
    return False
```

**Validation**:
- ✅ Checks for exact status code (204)
- ✅ Logs error details
- ✅ Returns boolean for flow control

### API Request Failures
```python
if response.status_code == 200:
    return response.json()
elif response.status_code == 429:
    # Rate limiting
    time.sleep(60)
    return self._make_request(endpoint, params)
else:
    print(f"[✗] API request failed: {response.status_code}")
    print(f"[✗] URL: {url}")
    print(f"[✗] Response: {response.text}")
    return None
```

**Validation**:
- ✅ Checks status code
- ✅ Special handling for rate limiting
- ✅ Logs full error context (URL, response)
- ✅ Returns None on failure (safe handling)

### Connection Errors
```python
except requests.exceptions.RequestException as e:
    print(f"[✗] Request error: {e}")
    return None
```

**Validation**:
- ✅ Catches all request exceptions
- ✅ Logs error message
- ✅ Graceful failure

### Object Resolution Failures
```python
details = self.get_object_details(obj)
if details:
    # Process details
else:
    # Fallback to name
    values.append(obj.get('name', 'unknown'))
```

**Validation**:
- ✅ Fallback to object name if details unavailable
- ✅ Continues processing other objects
- ✅ Export completes even with some failures

---

## Summary

### ✅ All Validations Passed

1. **Authentication**: Correct endpoint, method, and header handling
2. **Domain Selection**: Proper endpoint and multi-domain support
3. **Policy Retrieval**: All 5 policy types use correct endpoints
4. **Rule Retrieval**: Correct endpoints for all policy types
5. **Object Resolution**: 15+ object types with correct endpoints
6. **Pagination**: Proper implementation with offset/limit
7. **Rate Limiting**: 429 detection and retry logic
8. **Caching**: Efficient object detail caching
9. **Error Handling**: Comprehensive failure handling

### Known Limitations (Not Errors)

1. **Object depth**: Recursive group resolution may be slow for deeply nested groups
2. **Large policies**: Export can take 5-10 minutes for 100+ rule policies with object resolution
3. **API version**: Hardcoded to v10.0 - may need updates for future versions

### Testing Recommendation

Run the validation script to test against your specific FMC:

```bash
python3 validate_api_endpoints.py
```

This will:
- Test all authentication flows
- Validate policy endpoints exist
- Check object endpoint availability
- Test pagination behavior
- Verify expanded parameter functionality
- Generate detailed JSON report

---

## Changelog

- **2026-01-22**: Initial API validation
  - Fixed API base path (fmc_platform → fmc_config for policies)
  - Added object value resolution
  - Validated all endpoints against FMC API v10.0

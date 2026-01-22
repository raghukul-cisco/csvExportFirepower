#!/usr/bin/env python3
"""
FMC API Endpoint Validation Tool
Validates all API endpoints used in fmc_get_config.py against a live FMC instance
"""

import requests
import json
import sys
import getpass
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Tuple
import time

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class FMCAPIValidator:
    """Validates FMC API endpoints"""
    
    def __init__(self, fmc_host: str, username: str, password: str):
        self.fmc_host = fmc_host.rstrip('/')
        self.username = username
        self.password = password
        self.auth_token = None
        self.domain_uuid = None
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.results = []
        
    def log_result(self, endpoint: str, method: str, status: str, details: str = ""):
        """Log validation result"""
        result = {
            'endpoint': endpoint,
            'method': method,
            'status': status,
            'details': details
        }
        self.results.append(result)
        
        status_symbol = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
        print(f"[{status_symbol}] {method} {endpoint}: {status} {details}")
    
    def test_authentication(self) -> bool:
        """Test authentication endpoint"""
        print("\n" + "="*80)
        print("TESTING AUTHENTICATION")
        print("="*80)
        
        endpoint = "/api/fmc_platform/v1/auth/generatetoken"
        url = f"https://{self.fmc_host}{endpoint}"
        
        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 204:
                # Validate response headers
                self.auth_token = response.headers.get('X-auth-access-token')
                self.domain_uuid = response.headers.get('DOMAIN_UUID')
                refresh_token = response.headers.get('X-auth-refresh-token')
                
                if self.auth_token and self.domain_uuid:
                    self.headers['X-auth-access-token'] = self.auth_token
                    self.log_result(endpoint, "POST", "PASS", 
                                  f"Token: {self.auth_token[:20]}..., Domain: {self.domain_uuid}")
                    return True
                else:
                    self.log_result(endpoint, "POST", "FAIL", "Missing required headers")
                    return False
            else:
                self.log_result(endpoint, "POST", "FAIL", 
                              f"Status {response.status_code}: {response.text[:100]}")
                return False
                
        except Exception as e:
            self.log_result(endpoint, "POST", "FAIL", f"Exception: {str(e)}")
            return False
    
    def test_domain_info(self) -> bool:
        """Test domain information endpoint"""
        print("\n" + "="*80)
        print("TESTING DOMAIN INFORMATION")
        print("="*80)
        
        endpoint = "/api/fmc_platform/v1/info/domain"
        url = f"https://{self.fmc_host}{endpoint}"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                domains = data.get('items', [])
                
                if domains:
                    self.log_result(endpoint, "GET", "PASS", 
                                  f"Found {len(domains)} domain(s)")
                    for domain in domains:
                        print(f"    - {domain.get('name')} ({domain.get('type')}): {domain.get('uuid')}")
                    return True
                else:
                    self.log_result(endpoint, "GET", "WARN", "No domains found")
                    return True
            else:
                self.log_result(endpoint, "GET", "FAIL", 
                              f"Status {response.status_code}: {response.text[:100]}")
                return False
                
        except Exception as e:
            self.log_result(endpoint, "GET", "FAIL", f"Exception: {str(e)}")
            return False
    
    def test_policy_endpoints(self) -> bool:
        """Test policy list endpoints for all policy types"""
        print("\n" + "="*80)
        print("TESTING POLICY ENDPOINTS")
        print("="*80)
        
        policy_types = {
            'Access Control': 'policy/accesspolicies',
            'NAT': 'policy/ftdnatpolicies',
            'Prefilter': 'policy/prefilterpolicies',
            'SSL': 'policy/sslpolicies',
            'DNS': 'policy/dnspolicies'
        }
        
        all_passed = True
        
        for name, endpoint_path in policy_types.items():
            endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/{endpoint_path}"
            url = f"https://{self.fmc_host}{endpoint}"
            
            try:
                params = {
                    'limit': 10,
                    'offset': 0,
                    'expanded': 'true'
                }
                
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    verify=False,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    paging = data.get('paging', {})
                    
                    self.log_result(endpoint, "GET", "PASS", 
                                  f"{name}: {len(items)} found (Total: {paging.get('count', 0)})")
                    
                    # Show first policy if any exist
                    if items:
                        first_policy = items[0]
                        print(f"    Sample: {first_policy.get('name')} (ID: {first_policy.get('id')})")
                        
                        # Store first policy ID for rule testing
                        if name == 'Access Control' and not hasattr(self, 'sample_access_policy_id'):
                            self.sample_access_policy_id = first_policy.get('id')
                        elif name == 'NAT' and not hasattr(self, 'sample_nat_policy_id'):
                            self.sample_nat_policy_id = first_policy.get('id')
                            
                elif response.status_code == 404:
                    self.log_result(endpoint, "GET", "WARN", 
                                  f"{name}: Endpoint not found (may not be licensed)")
                else:
                    self.log_result(endpoint, "GET", "FAIL", 
                                  f"{name}: Status {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                self.log_result(endpoint, "GET", "FAIL", f"{name}: Exception: {str(e)}")
                all_passed = False
        
        return all_passed
    
    def test_access_rule_endpoints(self) -> bool:
        """Test access control rule endpoints"""
        print("\n" + "="*80)
        print("TESTING ACCESS CONTROL RULE ENDPOINTS")
        print("="*80)
        
        if not hasattr(self, 'sample_access_policy_id') or not self.sample_access_policy_id:
            self.log_result("N/A", "GET", "SKIP", "No access control policy found")
            return True
        
        policy_id = self.sample_access_policy_id
        
        # Test rule list endpoint
        endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
        url = f"https://{self.fmc_host}{endpoint}"
        
        try:
            params = {
                'limit': 5,
                'offset': 0,
                'expanded': 'true'
            }
            
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                self.log_result(endpoint, "GET", "PASS", 
                              f"Found {len(items)} rule(s)")
                
                # Test individual rule detail endpoint if rules exist
                if items:
                    rule_id = items[0].get('id')
                    rule_name = items[0].get('name', 'unnamed')
                    
                    detail_endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}"
                    detail_url = f"https://{self.fmc_host}{detail_endpoint}"
                    
                    detail_response = requests.get(
                        detail_url,
                        headers=self.headers,
                        verify=False,
                        timeout=30
                    )
                    
                    if detail_response.status_code == 200:
                        rule_data = detail_response.json()
                        self.log_result(detail_endpoint, "GET", "PASS", 
                                      f"Rule '{rule_name}' details retrieved")
                        
                        # Store sample object IDs for object testing
                        self._extract_sample_objects(rule_data)
                        return True
                    else:
                        self.log_result(detail_endpoint, "GET", "FAIL", 
                                      f"Status {detail_response.status_code}")
                        return False
                else:
                    self.log_result(endpoint, "GET", "WARN", "No rules found in policy")
                    return True
            else:
                self.log_result(endpoint, "GET", "FAIL", 
                              f"Status {response.status_code}: {response.text[:100]}")
                return False
                
        except Exception as e:
            self.log_result(endpoint, "GET", "FAIL", f"Exception: {str(e)}")
            return False
    
    def _extract_sample_objects(self, rule_data: Dict):
        """Extract sample object IDs from rule data for testing"""
        self.sample_objects = []
        
        # Extract network objects
        for net_type in ['sourceNetworks', 'destinationNetworks']:
            objects = rule_data.get(net_type, {}).get('objects', [])
            for obj in objects[:2]:  # Take up to 2 samples
                if obj.get('id') and obj.get('type'):
                    self.sample_objects.append({
                        'id': obj['id'],
                        'type': obj['type'],
                        'name': obj.get('name', 'unknown')
                    })
        
        # Extract port objects
        for port_type in ['sourcePorts', 'destinationPorts']:
            objects = rule_data.get(port_type, {}).get('objects', [])
            for obj in objects[:2]:
                if obj.get('id') and obj.get('type'):
                    self.sample_objects.append({
                        'id': obj['id'],
                        'type': obj['type'],
                        'name': obj.get('name', 'unknown')
                    })
    
    def test_object_endpoints(self) -> bool:
        """Test object detail endpoints"""
        print("\n" + "="*80)
        print("TESTING OBJECT ENDPOINTS")
        print("="*80)
        
        if not hasattr(self, 'sample_objects') or not self.sample_objects:
            # Test with common object types even if no samples found
            type_mapping = {
                'Host': 'object/hosts',
                'Network': 'object/networks',
                'Range': 'object/ranges',
                'FQDN': 'object/fqdns',
                'NetworkGroup': 'object/networkgroups',
                'ProtocolPortObject': 'object/protocolportobjects',
                'PortObjectGroup': 'object/portobjectgroups',
                'SecurityZone': 'object/securityzones'
            }
            
            print("\n[i] No sample objects found from rules, testing object list endpoints...")
            
            for obj_type, endpoint_path in type_mapping.items():
                endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/{endpoint_path}"
                url = f"https://{self.fmc_host}{endpoint}"
                
                try:
                    params = {'limit': 1, 'offset': 0}
                    response = requests.get(
                        url,
                        headers=self.headers,
                        params=params,
                        verify=False,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        count = data.get('paging', {}).get('count', 0)
                        self.log_result(endpoint, "GET", "PASS", 
                                      f"{obj_type}: {count} object(s) exist")
                    elif response.status_code == 404:
                        self.log_result(endpoint, "GET", "WARN", 
                                      f"{obj_type}: Endpoint may not be available")
                    else:
                        self.log_result(endpoint, "GET", "FAIL", 
                                      f"{obj_type}: Status {response.status_code}")
                        
                    time.sleep(0.2)  # Rate limiting
                    
                except Exception as e:
                    self.log_result(endpoint, "GET", "FAIL", 
                                  f"{obj_type}: Exception: {str(e)}")
            
            return True
        
        # Test actual object retrieval
        all_passed = True
        type_mapping = {
            'Host': 'object/hosts',
            'Network': 'object/networks',
            'Range': 'object/ranges',
            'FQDN': 'object/fqdns',
            'NetworkGroup': 'object/networkgroups',
            'ProtocolPortObject': 'object/protocolportobjects',
            'PortObjectGroup': 'object/portobjectgroups',
            'SecurityZone': 'object/securityzones',
            'URL': 'object/urls',
            'URLGroup': 'object/urlgroups',
            'Application': 'object/applications'
        }
        
        tested_types = set()
        
        for sample in self.sample_objects[:5]:  # Test up to 5 objects
            obj_type = sample['type']
            obj_id = sample['id']
            obj_name = sample['name']
            
            if obj_type in tested_types:
                continue  # Skip already tested types
            
            tested_types.add(obj_type)
            
            endpoint_path = type_mapping.get(obj_type)
            if not endpoint_path:
                self.log_result(f"object/{obj_type}", "GET", "SKIP", 
                              f"Unknown object type: {obj_type}")
                continue
            
            endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/{endpoint_path}/{obj_id}"
            url = f"https://{self.fmc_host}{endpoint}"
            
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    verify=False,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    value = data.get('value', 'N/A')
                    self.log_result(endpoint, "GET", "PASS", 
                                  f"{obj_type} '{obj_name}': value={value}")
                else:
                    self.log_result(endpoint, "GET", "FAIL", 
                                  f"{obj_type} '{obj_name}': Status {response.status_code}")
                    all_passed = False
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                self.log_result(endpoint, "GET", "FAIL", 
                              f"{obj_type} '{obj_name}': Exception: {str(e)}")
                all_passed = False
        
        return all_passed
    
    def test_pagination(self) -> bool:
        """Test pagination functionality"""
        print("\n" + "="*80)
        print("TESTING PAGINATION")
        print("="*80)
        
        endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies"
        url = f"https://{self.fmc_host}{endpoint}"
        
        try:
            # Test with different offsets and limits
            test_cases = [
                {'offset': 0, 'limit': 1},
                {'offset': 0, 'limit': 25},
                {'offset': 1, 'limit': 1}
            ]
            
            for params in test_cases:
                params['expanded'] = 'true'
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    verify=False,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    paging = data.get('paging', {})
                    items = data.get('items', [])
                    
                    self.log_result(endpoint, "GET", "PASS", 
                                  f"Pagination offset={params['offset']}, limit={params['limit']}: "
                                  f"returned {len(items)} items")
                else:
                    self.log_result(endpoint, "GET", "FAIL", 
                                  f"Pagination test failed: Status {response.status_code}")
                    return False
                
                time.sleep(0.2)
            
            return True
            
        except Exception as e:
            self.log_result(endpoint, "GET", "FAIL", f"Pagination test exception: {str(e)}")
            return False
    
    def test_expanded_parameter(self) -> bool:
        """Test expanded=true parameter"""
        print("\n" + "="*80)
        print("TESTING EXPANDED PARAMETER")
        print("="*80)
        
        endpoint = f"/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies"
        url = f"https://{self.fmc_host}{endpoint}"
        
        try:
            # Test without expanded
            params_basic = {'limit': 1, 'offset': 0}
            response_basic = requests.get(
                url,
                headers=self.headers,
                params=params_basic,
                verify=False,
                timeout=30
            )
            
            # Test with expanded
            params_expanded = {'limit': 1, 'offset': 0, 'expanded': 'true'}
            response_expanded = requests.get(
                url,
                headers=self.headers,
                params=params_expanded,
                verify=False,
                timeout=30
            )
            
            if response_basic.status_code == 200 and response_expanded.status_code == 200:
                basic_size = len(response_basic.text)
                expanded_size = len(response_expanded.text)
                
                if expanded_size >= basic_size:
                    self.log_result(endpoint, "GET", "PASS", 
                                  f"Expanded parameter working: basic={basic_size}B, expanded={expanded_size}B")
                    return True
                else:
                    self.log_result(endpoint, "GET", "WARN", 
                                  f"Expanded parameter may not be working as expected")
                    return True
            else:
                self.log_result(endpoint, "GET", "FAIL", "Could not test expanded parameter")
                return False
                
        except Exception as e:
            self.log_result(endpoint, "GET", "FAIL", f"Expanded test exception: {str(e)}")
            return False
    
    def generate_report(self):
        """Generate validation report"""
        print("\n" + "="*80)
        print("VALIDATION REPORT")
        print("="*80)
        
        total = len(self.results)
        passed = len([r for r in self.results if r['status'] == 'PASS'])
        failed = len([r for r in self.results if r['status'] == 'FAIL'])
        warnings = len([r for r in self.results if r['status'] == 'WARN'])
        skipped = len([r for r in self.results if r['status'] == 'SKIP'])
        
        print(f"\nTotal Tests: {total}")
        print(f"Passed: {passed} ✓")
        print(f"Failed: {failed} ✗")
        print(f"Warnings: {warnings} ⚠")
        print(f"Skipped: {skipped}")
        
        if failed > 0:
            print("\n" + "="*80)
            print("FAILED TESTS")
            print("="*80)
            for result in self.results:
                if result['status'] == 'FAIL':
                    print(f"\n[✗] {result['method']} {result['endpoint']}")
                    print(f"    {result['details']}")
        
        # Save detailed report to file
        report_file = 'api_validation_report.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[i] Detailed report saved to: {report_file}")
        print("="*80)
        
        return failed == 0
    
    def run_all_tests(self) -> bool:
        """Run all validation tests"""
        print("\n" + "="*80)
        print("FMC API ENDPOINT VALIDATION")
        print(f"Target: {self.fmc_host}")
        print("="*80)
        
        # Test authentication (required for all other tests)
        if not self.test_authentication():
            print("\n[✗] Authentication failed. Cannot proceed with other tests.")
            return False
        
        # Run all other tests
        self.test_domain_info()
        self.test_policy_endpoints()
        self.test_access_rule_endpoints()
        self.test_object_endpoints()
        self.test_pagination()
        self.test_expanded_parameter()
        
        # Generate report
        return self.generate_report()


def main():
    """Main execution function"""
    print("="*80)
    print("FMC API ENDPOINT VALIDATOR")
    print("Validates all API endpoints used in fmc_get_config.py")
    print("="*80)
    
    # Get FMC connection details
    print("\n[*] Enter FMC connection details:")
    fmc_host = input("FMC IP Address or Hostname: ").strip()
    username = input("API Username: ").strip()
    password = getpass.getpass("API Password: ")
    
    # Run validation
    validator = FMCAPIValidator(fmc_host, username, password)
    success = validator.run_all_tests()
    
    if success:
        print("\n[✓] All API endpoint validations passed!")
        sys.exit(0)
    else:
        print("\n[✗] Some API endpoint validations failed. Check report for details.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Validation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

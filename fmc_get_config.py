#!/usr/bin/env python3
"""
FMC Access Control Policy Export Tool
Extracts access control policies from Cisco Firepower Management Center via REST API
and converts them to CSV format.

Supports FMC API version 10.0
"""

import requests
import json
import csv
import sys
import getpass
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Optional, Any
import time

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class FMCAuthenticator:
    """Handles authentication and session management with FMC"""
    
    def __init__(self, fmc_host: str, username: str, password: str):
        """
        Initialize FMC authenticator
        
        Args:
            fmc_host: FMC hostname or IP address (without https://)
            username: API username
            password: API password
        """
        self.fmc_host = fmc_host.rstrip('/')
        self.username = username
        self.password = password
        self.base_url = f"https://{self.fmc_host}/api/fmc_platform/v1"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.domain_uuid = None
        self.auth_token = None
        self.refresh_token = None
        self.available_domains = []
        
    def authenticate(self) -> bool:
        """
        Authenticate with FMC and obtain access tokens
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        auth_url = f"https://{self.fmc_host}/api/fmc_platform/v1/auth/generatetoken"
        
        try:
            print(f"\n[*] Authenticating to FMC: {self.fmc_host}")
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 204:
                # Extract tokens and domain UUID from response headers
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.domain_uuid = response.headers.get('DOMAIN_UUID')
                
                # Update headers with authentication token
                self.headers['X-auth-access-token'] = self.auth_token
                
                print(f"[✓] Authentication successful")
                print(f"[✓] Default Domain UUID: {self.domain_uuid}")
                
                # Fetch available domains
                self._fetch_domains()
                
                return True
            else:
                print(f"[✗] Authentication failed: {response.status_code}")
                print(f"[✗] Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[✗] Connection error: {e}")
            return False
    
    def _fetch_domains(self) -> None:
        """Fetch available domains from FMC"""
        try:
            domains_url = f"https://{self.fmc_host}/api/fmc_platform/v1/info/domain"
            response = requests.get(
                domains_url,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                self.available_domains = data.get('items', [])
                print(f"[✓] Found {len(self.available_domains)} domain(s)")
            else:
                print(f"[!] Could not fetch domains: {response.status_code}")
                # Fallback to default domain from auth
                self.available_domains = [{'uuid': self.domain_uuid, 'name': 'Global', 'type': 'DOMAIN'}]
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching domains: {e}")
            # Fallback to default domain from auth
            self.available_domains = [{'uuid': self.domain_uuid, 'name': 'Global', 'type': 'DOMAIN'}]
    
    def get_domains(self) -> List[Dict]:
        """Get list of available domains"""
        return self.available_domains
    
    def select_domain(self, domain_uuid: str) -> None:
        """
        Select a specific domain
        
        Args:
            domain_uuid: UUID of the domain to select
        """
        self.domain_uuid = domain_uuid
        print(f"[✓] Selected domain UUID: {domain_uuid}")
    
    def get_headers(self) -> Dict[str, str]:
        """Return headers with authentication token"""
        return self.headers.copy()


class FMCPolicyExtractor:
    """Extracts various policy types from FMC"""
    
    # Policy type constants
    POLICY_TYPES = {
        'access': {'name': 'Access Control Policies', 'endpoint': 'policy/accesspolicies'},
        'nat': {'name': 'NAT Policies', 'endpoint': 'policy/ftdnatpolicies'},
        'prefilter': {'name': 'Prefilter Policies', 'endpoint': 'policy/prefilterpolicies'},
        'ssl': {'name': 'SSL Policies', 'endpoint': 'policy/sslpolicies'},
        'dns': {'name': 'DNS Policies', 'endpoint': 'policy/dnspolicies'}
    }
    
    def __init__(self, authenticator: FMCAuthenticator):
        """
        Initialize policy extractor
        
        Args:
            authenticator: Authenticated FMCAuthenticator instance
        """
        self.auth = authenticator
        # Use fmc_config for policy/object endpoints (not fmc_platform)
        self.base_url = f"https://{authenticator.fmc_host}/api/fmc_config/v1"
        # Cache for object details to avoid repeated API calls
        self.object_cache = {}
        
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make authenticated API request to FMC
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            
        Returns:
            Response JSON or None if error
        """
        url = f"{self.base_url}/domain/{self.auth.domain_uuid}/{endpoint}"
        
        try:
            response = requests.get(
                url,
                headers=self.auth.get_headers(),
                params=params,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                # Rate limiting - wait and retry
                print(f"[!] Rate limited, waiting 60 seconds...")
                time.sleep(60)
                return self._make_request(endpoint, params)
            else:
                print(f"[✗] API request failed: {response.status_code}")
                print(f"[✗] URL: {url}")
                print(f"[✗] Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[✗] Request error: {e}")
            return None
    
    def _paginate_results(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        """
        Handle pagination for API responses
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            
        Returns:
            List of all items across all pages
        """
        all_items = []
        offset = 0
        limit = 100  # FMC default limit
        
        if params is None:
            params = {}
        
        while True:
            params['offset'] = offset
            params['limit'] = limit
            params['expanded'] = 'true'  # Get expanded details
            
            response = self._make_request(endpoint, params)
            
            if not response or 'items' not in response:
                break
            
            items = response.get('items', [])
            all_items.extend(items)
            
            # Check pagination
            paging = response.get('paging', {})
            total = paging.get('count', 0)
            
            print(f"[*] Retrieved {len(all_items)} of {total} items")
            
            if len(all_items) >= total:
                break
            
            offset += limit
        
        return all_items
    
    def get_policies(self, policy_type: str = 'access') -> List[Dict]:
        """
        Get all policies of specified type
        
        Args:
            policy_type: Type of policy ('access', 'nat', 'prefilter', 'ssl', 'dns')
            
        Returns:
            List of policy objects
        """
        if policy_type not in self.POLICY_TYPES:
            print(f"[✗] Unknown policy type: {policy_type}")
            return []
        
        endpoint = self.POLICY_TYPES[policy_type]['endpoint']
        policy_name = self.POLICY_TYPES[policy_type]['name']
        
        print(f"\n[*] Fetching {policy_name}...")
        policies = self._paginate_results(endpoint)
        print(f"[✓] Found {len(policies)} {policy_name.lower()}")
        return policies
    
    def get_access_policies(self) -> List[Dict]:
        """Legacy method - Get all access control policies"""
        return self.get_policies('access')
    
    def get_access_rules(self, policy_id: str) -> List[Dict]:
        """
        Get all access control rules for a specific policy
        
        Args:
            policy_id: UUID of the access control policy
            
        Returns:
            List of access rule objects with full details
        """
        print(f"\n[*] Fetching access control rules for policy ID: {policy_id}")
        endpoint = f'policy/accesspolicies/{policy_id}/accessrules'
        rules = self._paginate_results(endpoint)
        print(f"[✓] Found {len(rules)} access control rules")
        
        # Fetch detailed information for each rule
        detailed_rules = []
        for idx, rule in enumerate(rules, 1):
            rule_id = rule.get('id')
            print(f"[*] Fetching details for rule {idx}/{len(rules)}: {rule.get('name', 'unnamed')}")
            
            # Get full rule details
            detail_endpoint = f'policy/accesspolicies/{policy_id}/accessrules/{rule_id}'
            detailed_rule = self._make_request(detail_endpoint)
            
            if detailed_rule:
                detailed_rules.append(detailed_rule)
            else:
                # Fallback to basic rule info if detail fetch fails
                detailed_rules.append(rule)
            
            # Small delay to avoid overwhelming the API
            time.sleep(0.5)
        
        return detailed_rules
    
    def get_nat_rules(self, policy_id: str) -> List[Dict]:
        """
        Get all NAT rules for a specific policy
        
        Args:
            policy_id: UUID of the NAT policy
            
        Returns:
            List of NAT rule objects with full details
        """
        print(f"\n[*] Fetching NAT rules for policy ID: {policy_id}")
        endpoint = f'policy/ftdnatpolicies/{policy_id}/natrules'
        rules = self._paginate_results(endpoint)
        print(f"[✓] Found {len(rules)} NAT rules")
        return rules
    
    def get_prefilter_rules(self, policy_id: str) -> List[Dict]:
        """
        Get all prefilter rules for a specific policy
        
        Args:
            policy_id: UUID of the prefilter policy
            
        Returns:
            List of prefilter rule objects
        """
        print(f"\n[*] Fetching prefilter rules for policy ID: {policy_id}")
        endpoint = f'policy/prefilterpolicies/{policy_id}/prefilterrules'
        rules = self._paginate_results(endpoint)
        print(f"[✓] Found {len(rules)} prefilter rules")
        return rules
    
    def get_ssl_rules(self, policy_id: str) -> List[Dict]:
        """
        Get all SSL rules for a specific policy
        
        Args:
            policy_id: UUID of the SSL policy
            
        Returns:
            List of SSL rule objects
        """
        print(f"\n[*] Fetching SSL rules for policy ID: {policy_id}")
        endpoint = f'policy/sslpolicies/{policy_id}/sslrules'
        rules = self._paginate_results(endpoint)
        print(f"[✓] Found {len(rules)} SSL rules")
        return rules
    
    def get_dns_rules(self, policy_id: str) -> List[Dict]:
        """
        Get all DNS rules for a specific policy
        
        Args:
            policy_id: UUID of the DNS policy
            
        Returns:
            List of DNS rule objects
        """
        print(f"\n[*] Fetching DNS rules for policy ID: {policy_id}")
        endpoint = f'policy/dnspolicies/{policy_id}/dnsrules'
        rules = self._paginate_results(endpoint)
        print(f"[✓] Found {len(rules)} DNS rules")
        return rules
    
    def get_object_details(self, object_ref: Dict) -> Optional[Dict]:
        """
        Fetch detailed information for an object reference
        
        Args:
            object_ref: Object reference dictionary with 'id' and 'type'
            
        Returns:
            Detailed object information or None if fetch fails
        """
        obj_id = object_ref.get('id')
        obj_type = object_ref.get('type')
        
        if not obj_id or not obj_type:
            return None
        
        # Check cache first
        cache_key = f"{obj_type}:{obj_id}"
        if cache_key in self.object_cache:
            return self.object_cache[cache_key]
        
        # Map object types to API endpoints
        type_mapping = {
            'Host': 'object/hosts',
            'Network': 'object/networks',
            'Range': 'object/ranges',
            'FQDN': 'object/fqdns',
            'NetworkGroup': 'object/networkgroups',
            'ProtocolPortObject': 'object/protocolportobjects',
            'PortObjectGroup': 'object/portobjectgroups',
            'ICMPv4Object': 'object/icmpv4objects',
            'ICMPv6Object': 'object/icmpv6objects',
            'SecurityZone': 'object/securityzones',
            'URL': 'object/urls',
            'URLGroup': 'object/urlgroups',
            'ApplicationFilter': 'object/applicationfilters',
            'Application': 'object/applications',
            'VlanTag': 'object/vlantags',
            'VlanGroupTag': 'object/vlangrouptags'
        }
        
        endpoint_base = type_mapping.get(obj_type)
        if not endpoint_base:
            return None
        
        # Fetch object details
        endpoint = f"{endpoint_base}/{obj_id}"
        details = self._make_request(endpoint)
        
        # Cache the result
        if details:
            self.object_cache[cache_key] = details
        
        return details
    
    def resolve_object_values(self, objects: List[Dict], literals: Optional[List[Dict]] = None) -> str:
        """
        Resolve object references to their actual values (IPs, ports, etc.)
        
        Args:
            objects: List of object references
            literals: Optional list of literal values
            
        Returns:
            Comma-separated string of resolved values
        """
        if not objects and not literals:
            return 'any'
        
        values = []
        
        # Process object references
        for obj in objects:
            details = self.get_object_details(obj)
            if details:
                obj_type = details.get('type')
                
                # Extract value based on object type
                if obj_type == 'Host':
                    values.append(details.get('value', 'unknown'))
                elif obj_type == 'Network':
                    values.append(details.get('value', 'unknown'))
                elif obj_type == 'Range':
                    values.append(details.get('value', 'unknown'))
                elif obj_type == 'FQDN':
                    values.append(details.get('value', 'unknown'))
                elif obj_type == 'NetworkGroup':
                    # Recursively resolve group members
                    group_objects = details.get('objects', [])
                    group_literals = details.get('literals', [])
                    group_values = self.resolve_object_values(group_objects, group_literals)
                    values.append(f"[{details.get('name')}={group_values}]")
                elif obj_type == 'ProtocolPortObject':
                    protocol = details.get('protocol', '')
                    port = details.get('port', '')
                    values.append(f"{protocol}/{port}" if protocol and port else details.get('name', 'unknown'))
                elif obj_type == 'PortObjectGroup':
                    # Recursively resolve group members
                    group_objects = details.get('objects', [])
                    group_values = self.resolve_object_values(group_objects)
                    values.append(f"[{details.get('name')}={group_values}]")
                elif obj_type == 'SecurityZone':
                    values.append(details.get('name', 'unknown'))
                else:
                    # For other types, use name
                    values.append(details.get('name', obj.get('name', 'unknown')))
            else:
                # Fallback to name if details fetch fails
                values.append(obj.get('name', 'unknown'))
            
            # Small delay to avoid API rate limiting
            time.sleep(0.1)
        
        # Process literals
        if literals:
            for lit in literals:
                lit_value = lit.get('value', '')
                if lit_value:
                    values.append(lit_value)
        
        return ', '.join(values) if values else 'any'
    
    @staticmethod
    def resolve_object_names(objects: List[Dict]) -> str:
        """
        Extract names from object references
        
        Args:
            objects: List of object dictionaries with 'name' keys
            
        Returns:
            Comma-separated string of object names
        """
        if not objects:
            return 'any'
        
        names = [obj.get('name', 'unknown') for obj in objects]
        return ', '.join(names)
    
    @staticmethod
    def resolve_port_objects(ports: List[Dict]) -> str:
        """
        Extract port information from port objects
        
        Args:
            ports: List of port object dictionaries
            
        Returns:
            Comma-separated string of port specifications
        """
        if not ports:
            return 'any'
        
        port_specs = []
        for port in ports:
            name = port.get('name', '')
            port_type = port.get('type', '')
            
            if port_type == 'ProtocolPortObject':
                protocol = port.get('protocol', '')
                port_val = port.get('port', '')
                if protocol and port_val:
                    port_specs.append(f"{protocol}/{port_val}")
                else:
                    port_specs.append(name)
            else:
                port_specs.append(name)
        
        return ', '.join(port_specs) if port_specs else 'any'


class CSVExporter:
    """Converts FMC access control policy data to CSV format"""
    
    def __init__(self, output_file: str):
        """
        Initialize CSV exporter
        
        Args:
            output_file: Path to output CSV file
        """
        self.output_file = output_file
        
    def export_access_rules(self, policy_name: str, rules: List[Dict], extractor: Optional['FMCPolicyExtractor'] = None) -> None:
        """
        Export access control rules to CSV
        
        Args:
            policy_name: Name of the access control policy
            rules: List of detailed access rule objects
            extractor: FMCPolicyExtractor instance for resolving object values
        """
        print(f"\n[*] Exporting {len(rules)} rules to CSV: {self.output_file}")
        if extractor:
            print(f"[*] Object value resolution enabled - this may take a few minutes...")
        
        # Define CSV columns matching typical FMC access rule export
        fieldnames = [
            'Policy',
            'Rule ID',
            'Rule Name',
            'Enabled',
            'Action',
            'Source Zones',
            'Source Zones (Values)',
            'Source Networks',
            'Source Networks (Values)',
            'Source Ports',
            'Source Ports (Values)',
            'Destination Zones',
            'Destination Zones (Values)',
            'Destination Networks',
            'Destination Networks (Values)',
            'Destination Ports',
            'Destination Ports (Values)',
            'Protocol',
            'Protocol (Values)',
            'Applications',
            'Applications (Values)',
            'URLs',
            'URLs (Values)',
            'Users',
            'IPS Policy',
            'File Policy',
            'Variable Set',
            'Logging',
            'Send Events To',
            'Log Files',
            'Log Connections',
            'Comment',
            'Section',
            'Category'
        ]
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for idx, rule in enumerate(rules, 1):
                    if extractor and idx % 5 == 0:  # Progress update every 5 rules
                        print(f"[*] Processing rule {idx}/{len(rules)} for CSV export...")
                    row = self._extract_rule_data(policy_name, rule, extractor)
                    writer.writerow(row)
            
            print(f"[✓] CSV export complete: {self.output_file}")
            
        except IOError as e:
            print(f"[✗] Error writing CSV file: {e}")
    
    def _extract_rule_data(self, policy_name: str, rule: Dict, extractor: Optional['FMCPolicyExtractor'] = None) -> Dict[str, str]:
        """
        Extract relevant data from rule object for CSV row
        
        Args:
            policy_name: Name of the policy
            rule: Rule object dictionary
            extractor: FMCPolicyExtractor instance for resolving object values
            
        Returns:
            Dictionary mapping CSV columns to values
        """
        # Source zones
        source_zones = rule.get('sourceZones', {}).get('objects', [])
        source_zone_names = FMCPolicyExtractor.resolve_object_names(source_zones)
        source_zone_values = extractor.resolve_object_values(source_zones) if extractor else ''
        
        # Destination zones
        dest_zones = rule.get('destinationZones', {}).get('objects', [])
        dest_zone_names = FMCPolicyExtractor.resolve_object_names(dest_zones)
        dest_zone_values = extractor.resolve_object_values(dest_zones) if extractor else ''
        
        # Source networks
        source_networks = rule.get('sourceNetworks', {}).get('objects', [])
        source_literals = rule.get('sourceNetworks', {}).get('literals', [])
        source_network_names = FMCPolicyExtractor.resolve_object_names(source_networks)
        if source_literals:
            literal_ips = [lit.get('value', '') for lit in source_literals]
            source_network_names += (', ' if source_network_names != 'any' else '') + ', '.join(literal_ips)
        source_network_values = extractor.resolve_object_values(source_networks, source_literals) if extractor else ''
        
        # Destination networks
        dest_networks = rule.get('destinationNetworks', {}).get('objects', [])
        dest_literals = rule.get('destinationNetworks', {}).get('literals', [])
        dest_network_names = FMCPolicyExtractor.resolve_object_names(dest_networks)
        if dest_literals:
            literal_ips = [lit.get('value', '') for lit in dest_literals]
            dest_network_names += (', ' if dest_network_names != 'any' else '') + ', '.join(literal_ips)
        dest_network_values = extractor.resolve_object_values(dest_networks, dest_literals) if extractor else ''
        
        # Source ports
        source_ports = rule.get('sourcePorts', {}).get('objects', [])
        source_port_names = FMCPolicyExtractor.resolve_port_objects(source_ports)
        source_port_values = extractor.resolve_object_values(source_ports) if extractor else ''
        
        # Destination ports
        dest_ports = rule.get('destinationPorts', {}).get('objects', [])
        dest_port_names = FMCPolicyExtractor.resolve_port_objects(dest_ports)
        dest_port_values = extractor.resolve_object_values(dest_ports) if extractor else ''
        
        # Protocols
        protocols = rule.get('protocols', {}).get('objects', [])
        protocol_names = FMCPolicyExtractor.resolve_object_names(protocols)
        protocol_values = extractor.resolve_object_values(protocols) if extractor else ''
        
        # Applications
        applications = rule.get('applications', {}).get('objects', [])
        app_names = FMCPolicyExtractor.resolve_object_names(applications)
        app_values = extractor.resolve_object_values(applications) if extractor else ''
        
        # URLs
        urls = rule.get('urls', {}).get('objects', [])
        url_names = FMCPolicyExtractor.resolve_object_names(urls)
        url_values = extractor.resolve_object_values(urls) if extractor else ''
        
        # Users
        users = rule.get('users', {}).get('objects', [])
        user_names = FMCPolicyExtractor.resolve_object_names(users)
        
        # IPS Policy
        ips_policy = rule.get('ipsPolicy', {})
        ips_policy_name = ips_policy.get('name', '') if ips_policy else ''
        
        # File Policy
        file_policy = rule.get('filePolicy', {})
        file_policy_name = file_policy.get('name', '') if file_policy else ''
        
        # Variable Set
        variable_set = rule.get('variableSet', {})
        variable_set_name = variable_set.get('name', '') if variable_set else ''
        
        # Logging
        log_begin = rule.get('logBegin', False)
        log_end = rule.get('logEnd', False)
        log_files = rule.get('logFiles', False)
        
        logging_config = []
        if log_begin:
            logging_config.append('At Beginning')
        if log_end:
            logging_config.append('At End')
        logging_str = ', '.join(logging_config) if logging_config else 'Disabled'
        
        # Send events to
        send_events_to = rule.get('sendEventsToFMC', False)
        events_str = 'FMC' if send_events_to else ''
        
        # Section/Category
        section = rule.get('section', '')
        category = rule.get('category', '')
        
        return {
            'Policy': policy_name,
            'Rule ID': rule.get('metadata', {}).get('ruleIndex', ''),
            'Rule Name': rule.get('name', ''),
            'Enabled': 'Yes' if rule.get('enabled', True) else 'No',
            'Action': rule.get('action', '').upper(),
            'Source Zones': source_zone_names,
            'Source Zones (Values)': source_zone_values,
            'Source Networks': source_network_names,
            'Source Networks (Values)': source_network_values,
            'Source Ports': source_port_names,
            'Source Ports (Values)': source_port_values,
            'Destination Zones': dest_zone_names,
            'Destination Zones (Values)': dest_zone_values,
            'Destination Networks': dest_network_names,
            'Destination Networks (Values)': dest_network_values,
            'Destination Ports': dest_port_names,
            'Destination Ports (Values)': dest_port_values,
            'Protocol': protocol_names,
            'Protocol (Values)': protocol_values,
            'Applications': app_names,
            'Applications (Values)': app_values,
            'URLs': url_names,
            'URLs (Values)': url_values,
            'Users': user_names,
            'IPS Policy': ips_policy_name,
            'File Policy': file_policy_name,
            'Variable Set': variable_set_name,
            'Logging': logging_str,
            'Send Events To': events_str,
            'Log Files': 'Yes' if log_files else 'No',
            'Log Connections': logging_str,
            'Comment': rule.get('comments', ''),
            'Section': section,
            'Category': category
        }
    
    def export_nat_rules(self, policy_name: str, rules: List[Dict]) -> None:
        """Export NAT rules to CSV"""
        print(f"\n[*] Exporting {len(rules)} NAT rules to CSV: {self.output_file}")
        
        fieldnames = ['Policy', 'Rule ID', 'Rule Name', 'Enabled', 'NAT Type',
                     'Interface In', 'Interface Out', 'Original Source', 'Original Destination',
                     'Original Source Port', 'Original Destination Port', 'Translated Source',
                     'Translated Destination', 'Translated Source Port', 'Translated Destination Port',
                     'Comment']
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for rule in rules:
                    writer.writerow(self._extract_nat_rule_data(policy_name, rule))
            print(f"[✓] CSV export complete: {self.output_file}")
        except IOError as e:
            print(f"[✗] Error writing CSV file: {e}")
    
    def export_prefilter_rules(self, policy_name: str, rules: List[Dict]) -> None:
        """Export prefilter rules to CSV"""
        print(f"\n[*] Exporting {len(rules)} prefilter rules to CSV: {self.output_file}")
        
        fieldnames = ['Policy', 'Rule ID', 'Rule Name', 'Enabled', 'Action', 'Source Zones',
                     'Source Networks', 'Source Ports', 'Destination Zones', 'Destination Networks',
                     'Destination Ports', 'Protocol', 'VLAN Tags', 'Logging', 'Comment']
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for rule in rules:
                    writer.writerow(self._extract_prefilter_rule_data(policy_name, rule))
            print(f"[✓] CSV export complete: {self.output_file}")
        except IOError as e:
            print(f"[✗] Error writing CSV file: {e}")
    
    def export_ssl_rules(self, policy_name: str, rules: List[Dict]) -> None:
        """Export SSL rules to CSV"""
        print(f"\n[*] Exporting {len(rules)} SSL rules to CSV: {self.output_file}")
        
        fieldnames = ['Policy', 'Rule ID', 'Rule Name', 'Enabled', 'Action', 'Source Zones',
                     'Source Networks', 'Destination Zones', 'Destination Networks',
                     'Destination Ports', 'Certificate', 'URL Categories', 'URLs', 'Logging', 'Comment']
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for rule in rules:
                    writer.writerow(self._extract_ssl_rule_data(policy_name, rule))
            print(f"[✓] CSV export complete: {self.output_file}")
        except IOError as e:
            print(f"[✗] Error writing CSV file: {e}")
    
    def export_dns_rules(self, policy_name: str, rules: List[Dict]) -> None:
        """Export DNS rules to CSV"""
        print(f"\n[*] Exporting {len(rules)} DNS rules to CSV: {self.output_file}")
        
        fieldnames = ['Policy', 'Rule ID', 'Rule Name', 'Enabled', 'Action', 'Source Zones',
                     'Source Networks', 'DNS Lists', 'URL Categories', 'Logging', 'Sinkhole', 'Comment']
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for rule in rules:
                    writer.writerow(self._extract_dns_rule_data(policy_name, rule))
            print(f"[✓] CSV export complete: {self.output_file}")
        except IOError as e:
            print(f"[✗] Error writing CSV file: {e}")
    
    def _extract_nat_rule_data(self, policy_name: str, rule: Dict) -> Dict[str, str]:
        """Extract NAT rule data for CSV"""
        orig_src = FMCPolicyExtractor.resolve_object_names(rule.get('originalSource', {}).get('objects', []))
        orig_dst = FMCPolicyExtractor.resolve_object_names(rule.get('originalDestination', {}).get('objects', []))
        trans_src = FMCPolicyExtractor.resolve_object_names(rule.get('translatedSource', {}).get('objects', []))
        trans_dst = FMCPolicyExtractor.resolve_object_names(rule.get('translatedDestination', {}).get('objects', []))
        
        return {
            'Policy': policy_name,
            'Rule ID': rule.get('metadata', {}).get('index', ''),
            'Rule Name': rule.get('name', ''),
            'Enabled': 'Yes' if rule.get('enabled', True) else 'No',
            'NAT Type': rule.get('natType', ''),
            'Interface In': FMCPolicyExtractor.resolve_object_names([rule.get('interfaceInTranslatedNetwork', {})]),
            'Interface Out': FMCPolicyExtractor.resolve_object_names([rule.get('interfaceOutTranslatedNetwork', {})]),
            'Original Source': orig_src,
            'Original Destination': orig_dst,
            'Original Source Port': rule.get('originalSourcePort', {}).get('port', ''),
            'Original Destination Port': rule.get('originalDestinationPort', {}).get('port', ''),
            'Translated Source': trans_src,
            'Translated Destination': trans_dst,
            'Translated Source Port': rule.get('translatedSourcePort', {}).get('port', ''),
            'Translated Destination Port': rule.get('translatedDestinationPort', {}).get('port', ''),
            'Comment': rule.get('description', '')
        }
    
    def _extract_prefilter_rule_data(self, policy_name: str, rule: Dict) -> Dict[str, str]:
        """Extract prefilter rule data for CSV"""
        log_begin = rule.get('logBegin', False)
        log_end = rule.get('logEnd', False)
        logging_str = ', '.join([x for x in ['At Beginning' if log_begin else '', 'At End' if log_end else ''] if x]) or 'Disabled'
        
        return {
            'Policy': policy_name,
            'Rule ID': rule.get('metadata', {}).get('ruleIndex', ''),
            'Rule Name': rule.get('name', ''),
            'Enabled': 'Yes' if rule.get('enabled', True) else 'No',
            'Action': rule.get('action', '').upper(),
            'Source Zones': FMCPolicyExtractor.resolve_object_names(rule.get('sourceZones', {}).get('objects', [])),
            'Source Networks': FMCPolicyExtractor.resolve_object_names(rule.get('sourceNetworks', {}).get('objects', [])),
            'Source Ports': FMCPolicyExtractor.resolve_port_objects(rule.get('sourcePorts', {}).get('objects', [])),
            'Destination Zones': FMCPolicyExtractor.resolve_object_names(rule.get('destinationZones', {}).get('objects', [])),
            'Destination Networks': FMCPolicyExtractor.resolve_object_names(rule.get('destinationNetworks', {}).get('objects', [])),
            'Destination Ports': FMCPolicyExtractor.resolve_port_objects(rule.get('destinationPorts', {}).get('objects', [])),
            'Protocol': FMCPolicyExtractor.resolve_object_names(rule.get('protocols', {}).get('objects', [])),
            'VLAN Tags': FMCPolicyExtractor.resolve_object_names(rule.get('vlanTags', {}).get('objects', [])),
            'Logging': logging_str,
            'Comment': rule.get('comments', '')
        }
    
    def _extract_ssl_rule_data(self, policy_name: str, rule: Dict) -> Dict[str, str]:
        """Extract SSL rule data for CSV"""
        log_begin = rule.get('logBegin', False)
        log_end = rule.get('logEnd', False)
        logging_str = ', '.join([x for x in ['At Beginning' if log_begin else '', 'At End' if log_end else ''] if x]) or 'Disabled'
        
        return {
            'Policy': policy_name,
            'Rule ID': rule.get('metadata', {}).get('ruleIndex', ''),
            'Rule Name': rule.get('name', ''),
            'Enabled': 'Yes' if rule.get('enabled', True) else 'No',
            'Action': rule.get('action', '').upper(),
            'Source Zones': FMCPolicyExtractor.resolve_object_names(rule.get('sourceZones', {}).get('objects', [])),
            'Source Networks': FMCPolicyExtractor.resolve_object_names(rule.get('sourceNetworks', {}).get('objects', [])),
            'Destination Zones': FMCPolicyExtractor.resolve_object_names(rule.get('destinationZones', {}).get('objects', [])),
            'Destination Networks': FMCPolicyExtractor.resolve_object_names(rule.get('destinationNetworks', {}).get('objects', [])),
            'Destination Ports': FMCPolicyExtractor.resolve_port_objects(rule.get('destinationPorts', {}).get('objects', [])),
            'Certificate': rule.get('certificate', {}).get('name', ''),
            'URL Categories': FMCPolicyExtractor.resolve_object_names(rule.get('urlCategories', {}).get('objects', [])),
            'URLs': FMCPolicyExtractor.resolve_object_names(rule.get('urls', {}).get('objects', [])),
            'Logging': logging_str,
            'Comment': rule.get('comments', '')
        }
    
    def _extract_dns_rule_data(self, policy_name: str, rule: Dict) -> Dict[str, str]:
        """Extract DNS rule data for CSV"""
        log_begin = rule.get('logBegin', False)
        log_end = rule.get('logEnd', False)
        logging_str = ', '.join([x for x in ['At Beginning' if log_begin else '', 'At End' if log_end else ''] if x]) or 'Disabled'
        
        return {
            'Policy': policy_name,
            'Rule ID': rule.get('metadata', {}).get('ruleIndex', ''),
            'Rule Name': rule.get('name', ''),
            'Enabled': 'Yes' if rule.get('enabled', True) else 'No',
            'Action': rule.get('action', '').upper(),
            'Source Zones': FMCPolicyExtractor.resolve_object_names(rule.get('sourceZones', {}).get('objects', [])),
            'Source Networks': FMCPolicyExtractor.resolve_object_names(rule.get('sourceNetworks', {}).get('objects', [])),
            'DNS Lists': FMCPolicyExtractor.resolve_object_names(rule.get('dnsLists', {}).get('objects', [])),
            'URL Categories': FMCPolicyExtractor.resolve_object_names(rule.get('urlCategories', {}).get('objects', [])),
            'Logging': logging_str,
            'Sinkhole': rule.get('sinkhole', {}).get('name', ''),
            'Comment': rule.get('comments', '')
        }


def main():
    """Main execution function"""
    print("=" * 80)
    print("FMC POLICY EXPORT TOOL")
    print("Cisco Firepower Management Center API v10.0")
    print("=" * 80)
    
    # Get FMC connection details from user
    print("\n[*] Enter FMC connection details:")
    fmc_host = input("FMC IP Address or Hostname: ").strip()
    username = input("API Username: ").strip()
    password = getpass.getpass("API Password: ")
    
    # Authenticate
    authenticator = FMCAuthenticator(fmc_host, username, password)
    if not authenticator.authenticate():
        print("\n[✗] Authentication failed. Exiting.")
        sys.exit(1)
    
    # Domain selection
    domains = authenticator.get_domains()
    
    if len(domains) == 0:
        print("\n[✗] No domains available. Exiting.")
        sys.exit(1)
    elif len(domains) == 1:
        # Auto-select single domain
        domain = domains[0]
        print(f"\n[✓] Auto-selected domain: {domain.get('name', 'Unknown')} (UUID: {domain.get('uuid')})")
        authenticator.select_domain(domain.get('uuid'))
    else:
        # Multiple domains - let user choose
        print("\n" + "=" * 80)
        print("DOMAIN SELECTION")
        print("=" * 80)
        for idx, domain in enumerate(domains, 1):
            domain_name = domain.get('name', 'Unknown')
            domain_type = domain.get('type', 'DOMAIN')
            print(f"{idx}. {domain_name} ({domain_type})")
        
        print("\n[*] Select domain (enter number):")
        try:
            domain_selection = int(input("Domain: ").strip())
            if 1 <= domain_selection <= len(domains):
                selected_domain = domains[domain_selection - 1]
                authenticator.select_domain(selected_domain.get('uuid'))
                print(f"[✓] Selected domain: {selected_domain.get('name', 'Unknown')}")
            else:
                print("[✗] Invalid selection. Exiting.")
                sys.exit(1)
        except ValueError:
            print("[✗] Invalid input. Exiting.")
            sys.exit(1)
    
    # Create policy extractor
    extractor = FMCPolicyExtractor(authenticator)
    
    # Select policy type
    print("\n" + "=" * 80)
    print("POLICY TYPE SELECTION")
    print("=" * 80)
    print("1. Access Control Policies")
    print("2. NAT Policies")
    print("3. Prefilter Policies")
    print("4. SSL Policies")
    print("5. DNS Policies")
    
    print("\n[*] Select policy type (enter number):") 
    try:
        type_selection = int(input("Policy type: ").strip())
        policy_type_map = {1: 'access', 2: 'nat', 3: 'prefilter', 4: 'ssl', 5: 'dns'}
        if type_selection not in policy_type_map:
            print("[✗] Invalid selection. Exiting.")
            sys.exit(1)
        policy_type = policy_type_map[type_selection]
    except ValueError:
        print("[✗] Invalid input. Exiting.")
        sys.exit(1)
    
    # Get all policies of selected type
    policies = extractor.get_policies(policy_type)
    
    if not policies:
        print(f"\n[✗] No {extractor.POLICY_TYPES[policy_type]['name'].lower()} found. Exiting.")
        sys.exit(1)
    
    # Display policies and let user choose
    print("\n" + "=" * 80)
    print(f"AVAILABLE {extractor.POLICY_TYPES[policy_type]['name'].upper()}")
    print("=" * 80)
    for idx, policy in enumerate(policies, 1):
        print(f"{idx}. {policy.get('name', 'unnamed')} (ID: {policy.get('id', 'unknown')})")
    
    # Get user selection
    print("\n[*] Select policy to export (enter number):")
    try:
        selection = int(input("Policy number: ").strip())
        if 1 <= selection <= len(policies):
            selected_policy = policies[selection - 1]
        else:
            print("[✗] Invalid selection. Exiting.")
            sys.exit(1)
    except ValueError:
        print("[✗] Invalid input. Exiting.")
        sys.exit(1)
    
    # Extract rules for selected policy
    policy_id = selected_policy.get('id')
    policy_name = selected_policy.get('name', 'unknown')
    
    print(f"\n[*] Selected policy: {policy_name}")
    
    # Get rules based on policy type
    if policy_type == 'access':
        rules = extractor.get_access_rules(policy_id)
    elif policy_type == 'nat':
        rules = extractor.get_nat_rules(policy_id)
    elif policy_type == 'prefilter':
        rules = extractor.get_prefilter_rules(policy_id)
    elif policy_type == 'ssl':
        rules = extractor.get_ssl_rules(policy_id)
    elif policy_type == 'dns':
        rules = extractor.get_dns_rules(policy_id)
    else:
        print(f"[✗] Unsupported policy type: {policy_type}")
        sys.exit(1)
    
    if not rules:
        print(f"\n[!] No rules found in policy '{policy_name}'")
        sys.exit(0)
    
    # Export to CSV
    policy_type_name = policy_type.replace('_', '-')
    output_file = f"fmc_{policy_type_name}_policy_{policy_name.replace(' ', '_')}.csv"
    exporter = CSVExporter(output_file)
    
    # Export based on policy type
    if policy_type == 'access':
        exporter.export_access_rules(policy_name, rules, extractor)
    elif policy_type == 'nat':
        exporter.export_nat_rules(policy_name, rules)
    elif policy_type == 'prefilter':
        exporter.export_prefilter_rules(policy_name, rules)
    elif policy_type == 'ssl':
        exporter.export_ssl_rules(policy_name, rules)
    elif policy_type == 'dns':
        exporter.export_dns_rules(policy_name, rules)
    
    print("\n" + "=" * 80)
    print("EXPORT COMPLETE")
    print("=" * 80)
    print(f"Policy Type: {extractor.POLICY_TYPES[policy_type]['name']}")
    print(f"Policy Name: {policy_name}")
    print(f"Rules exported: {len(rules)}")
    print(f"Output file: {output_file}")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

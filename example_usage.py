#!/usr/bin/env python3
"""
Example usage of FMC API client for testing/development
Demonstrates authentication and basic API operations
"""

from fmc_get_config import FMCAuthenticator, FMCPolicyExtractor, CSVExporter

def example_usage():
    """Example demonstrating programmatic usage of FMC API client"""
    
    # Example 1: Authentication
    print("=" * 80)
    print("EXAMPLE 1: Authentication")
    print("=" * 80)
    
    # Initialize authenticator
    fmc_host = "10.0.0.100"  # Replace with your FMC IP
    username = "admin"
    password = "your_password"
    
    auth = FMCAuthenticator(fmc_host, username, password)
    
    # Authenticate
    if auth.authenticate():
        print(f"Successfully authenticated with domain: {auth.domain_uuid}")
    else:
        print("Authentication failed")
        return
    
    # Example 2: Domain Selection
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Domain Selection")
    print("=" * 80)
    
    domains = auth.get_domains()
    print(f"Available domains: {len(domains)}")
    for domain in domains:
        print(f"  - {domain.get('name')} (UUID: {domain.get('uuid')})")
    
    # Select first domain (or you can choose by index)
    if domains:
        auth.select_domain(domains[0].get('uuid'))
    
    # Example 3: List all policies
    print("\n" + "=" * 80)
    print("EXAMPLE 3: List Access Control Policies")
    print("=" * 80)
    
    extractor = FMCPolicyExtractor(auth)
    policies = extractor.get_access_policies()
    
    for policy in policies:
        print(f"Policy: {policy.get('name')}")
        print(f"  ID: {policy.get('id')}")
        print(f"  Default Action: {policy.get('defaultAction', {}).get('action')}")
        print()
    
    # Example 4: Get rules for first policy
    if policies:
        print("=" * 80)
        print("EXAMPLE 4: Extract Rules from First Policy")
        print("=" * 80)
        
        first_policy = policies[0]
        policy_id = first_policy.get('id')
        policy_name = first_policy.get('name')
        
        print(f"Extracting rules from: {policy_name}")
        rules = extractor.get_access_rules(policy_id)
        
        # Display first 3 rules
        for idx, rule in enumerate(rules[:3], 1):
            print(f"\nRule {idx}: {rule.get('name')}")
            print(f"  Action: {rule.get('action')}")
            print(f"  Enabled: {rule.get('enabled')}")
            
            # Source networks
            src_nets = rule.get('sourceNetworks', {}).get('objects', [])
            if src_nets:
                src_names = [n.get('name') for n in src_nets]
                print(f"  Source Networks: {', '.join(src_names)}")
            
            # Destination networks
            dst_nets = rule.get('destinationNetworks', {}).get('objects', [])
            if dst_nets:
                dst_names = [n.get('name') for n in dst_nets]
                print(f"  Destination Networks: {', '.join(dst_names)}")
        
        # Example 5: Export to CSV
        print("\n" + "=" * 80)
        print("EXAMPLE 5: Export to CSV")
        print("=" * 80)
        
        output_file = f"example_export_{policy_name.replace(' ', '_')}.csv"
        exporter = CSVExporter(output_file)
        exporter.export_access_rules(policy_name, rules)
        print(f"Exported {len(rules)} rules to {output_file}")


def example_custom_extraction():
    """Example showing custom data extraction from rules"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE: Custom Rule Analysis")
    print("=" * 80)
    
    # Authenticate (reuse code from above)
    fmc_host = "10.0.0.100"
    username = "admin"
    password = "your_password"
    
    auth = FMCAuthenticator(fmc_host, username, password)
    if not auth.authenticate():
        return
    
    extractor = FMCPolicyExtractor(auth)
    policies = extractor.get_access_policies()
    
    if not policies:
        return
    
    # Get rules from first policy
    policy_id = policies[0].get('id')
    rules = extractor.get_access_rules(policy_id)
    
    # Custom analysis: Find rules with IPS policy
    ips_rules = [r for r in rules if r.get('ipsPolicy')]
    print(f"Rules with IPS policy: {len(ips_rules)}")
    
    # Find BLOCK rules
    block_rules = [r for r in rules if r.get('action') == 'BLOCK']
    print(f"BLOCK rules: {len(block_rules)}")
    
    # Find disabled rules
    disabled_rules = [r for r in rules if not r.get('enabled', True)]
    print(f"Disabled rules: {len(disabled_rules)}")
    
    # Find rules with specific applications
    app_rules = [r for r in rules if r.get('applications', {}).get('objects')]
    print(f"Rules with application filters: {len(app_rules)}")
    
    # Print rule distribution by action
    print("\nRule distribution by action:")
    actions = {}
    for rule in rules:
        action = rule.get('action', 'UNKNOWN')
        actions[action] = actions.get(action, 0) + 1
    
    for action, count in sorted(actions.items()):
        print(f"  {action}: {count}")


if __name__ == "__main__":
    print("""
    FMC API Client Examples
    =======================
    
    This script demonstrates programmatic usage of the FMC API client.
    
    IMPORTANT: Update the following variables before running:
    - fmc_host: Your FMC IP address or hostname
    - username: Your API username
    - password: Your API password
    
    Uncomment the example you want to run below.
    """)
    
    # Uncomment to run examples:
    # example_usage()
    # example_custom_extraction()
    
    print("\nTo run examples, edit this file and uncomment the example calls.")

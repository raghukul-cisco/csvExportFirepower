# FMC Policy Export - Testing Checklist

## Pre-Testing Setup

- [ ] Python 3.7+ installed (`python3 --version`)
- [ ] Dependencies installed (`pip3 install -r requirements.txt`)
- [ ] FMC accessible on network (ping test)
- [ ] API credentials available (username/password)
- [ ] User has API access enabled in FMC
- [ ] User has read permissions for access control policies

## Basic Functionality Tests

### Authentication Tests

- [ ] **Test 1: Valid Credentials**
  - Run: `python3 fmc_get_config.py`
  - Input valid credentials
  - Expected: "Authentication successful" message
  - Expected: Domain UUID displayed

- [ ] **Test 2: Invalid Credentials**
  - Run with wrong password
  - Expected: "Authentication failed" error
  - Expected: HTTP 401 or 403 status

- [ ] **Test 3: Invalid FMC Host**
  - Run with non-existent IP
  - Expected: Connection error message
  - Expected: Timeout or connection refused

- [ ] **Test 4: Token Retrieval**
  - Verify X-auth-access-token in headers
  - Verify domain UUID extracted
  - Check token is not empty

### Policy Discovery Tests

- [ ] **Test 5: List All Policies**
  - Authenticate successfully
  - Expected: List of all access control policies
  - Verify policy names and IDs displayed
  - Count matches FMC GUI count

- [ ] **Test 6: Empty Policy List**
  - Use account with no policy access
  - Expected: "No access control policies found"
  - Script exits gracefully

- [ ] **Test 7: Policy Selection**
  - Select valid policy number
  - Expected: Policy selected, moves to rule extraction
  - Try invalid number: Expected error

### Rule Extraction Tests

- [ ] **Test 8: Small Policy (<10 rules)**
  - Extract rules from policy with few rules
  - Expected: All rules retrieved
  - Verify rule count matches FMC
  - Check extraction time (<30 seconds)

- [ ] **Test 9: Medium Policy (10-100 rules)**
  - Extract rules from medium policy
  - Expected: Pagination handled correctly
  - Verify all rules retrieved
  - Check for "Retrieved X of Y items" messages

- [ ] **Test 10: Large Policy (>100 rules)**
  - Extract rules from large policy
  - Expected: Multiple pagination requests
  - All rules retrieved without loss
  - Check total time (estimate ~0.5s per rule)

- [ ] **Test 11: Empty Policy (0 rules)**
  - Select policy with no rules
  - Expected: "No rules found" message
  - Script exits gracefully

### Rule Detail Extraction Tests

- [ ] **Test 12: Rule with Source Zones**
  - Find rule with source zones configured
  - Verify zone names in CSV
  - Check "any" if no zones

- [ ] **Test 13: Rule with Network Objects**
  - Find rule with network objects
  - Verify object names in source/dest columns
  - Check literal IPs included

- [ ] **Test 14: Rule with Port Objects**
  - Find rule with specific ports
  - Verify port specifications (tcp/443, etc.)
  - Check "any" for no port restrictions

- [ ] **Test 15: Rule with Applications**
  - Find rule with app filters
  - Verify application names in CSV
  - Check multiple apps comma-separated

- [ ] **Test 16: Rule with IPS Policy**
  - Find rule with IPS policy attached
  - Verify IPS policy name in CSV
  - Check empty if no IPS policy

- [ ] **Test 17: Rule with File Policy**
  - Find rule with file policy
  - Verify file policy name in CSV
  - Check empty if no file policy

- [ ] **Test 18: Rule with Logging**
  - Find rule with logging enabled
  - Check "At Beginning" or "At End"
  - Verify log files and events columns

- [ ] **Test 19: Disabled Rule**
  - Find disabled rule
  - Verify "Enabled" column shows "No"
  - Check rule still exported

- [ ] **Test 20: Rule with Comments**
  - Find rule with comments
  - Verify comment text in CSV
  - Check special characters handled

### CSV Export Tests

- [ ] **Test 21: File Creation**
  - Run full export
  - Verify CSV file created
  - Check filename format: `fmc_access_policy_<NAME>.csv`

- [ ] **Test 22: CSV Structure**
  - Open CSV in Excel/LibreOffice
  - Verify 24 columns present
  - Check header row correct

- [ ] **Test 23: CSV Content**
  - Verify all rules present
  - Check row count = rule count + 1 (header)
  - Spot check random rules match FMC

- [ ] **Test 24: Special Characters**
  - Check rules with special chars (quotes, commas)
  - Verify CSV escaping works
  - Open in Excel - no broken columns

- [ ] **Test 25: Empty Values**
  - Check rules with missing fields
  - Verify empty cells or "any" as appropriate
  - No "None" or "null" in CSV

### Error Handling Tests

- [ ] **Test 26: Rate Limiting**
  - Run against busy FMC (if possible)
  - Verify HTTP 429 detected
  - Check automatic 60-second wait
  - Verify retry succeeds

- [ ] **Test 27: Network Interruption**
  - Disconnect network mid-extraction
  - Expected: Request error message
  - Script handles gracefully

- [ ] **Test 28: Invalid Policy ID**
  - Manually trigger with bad policy ID
  - Expected: HTTP 404 or error message
  - Script doesn't crash

- [ ] **Test 29: File Write Permissions**
  - Run in read-only directory
  - Expected: File write error
  - Clear error message displayed

- [ ] **Test 30: Keyboard Interrupt**
  - Press Ctrl+C during execution
  - Expected: "Operation cancelled by user"
  - Clean exit

## Advanced Tests

### Performance Tests

- [ ] **Test 31: Memory Usage**
  - Monitor memory during large policy export
  - Expected: No memory leaks
  - Memory released after completion

- [ ] **Test 32: Response Time**
  - Time full export process
  - Expected: ~0.5 seconds per rule
  - No excessive delays

### Integration Tests

- [ ] **Test 33: Multiple Policy Export**
  - Run script multiple times
  - Export different policies
  - Verify no conflicts

- [ ] **Test 34: Programmatic Usage**
  - Run `example_usage.py` (uncommented)
  - Verify classes can be imported
  - Check programmatic access works

- [ ] **Test 35: Quickstart Script**
  - Run `./quickstart.sh`
  - Verify all checks pass
  - Dependencies installed correctly

### Data Validation Tests

- [ ] **Test 36: Compare with FMC Export**
  - Export policy manually from FMC GUI
  - Export same policy with script
  - Compare rule counts and key fields
  - Verify no missing rules

- [ ] **Test 37: Object Name Resolution**
  - Find rule with nested object groups
  - Verify top-level names shown
  - Check member objects not expanded

- [ ] **Test 38: Multiple Objects Per Field**
  - Find rule with 5+ source networks
  - Verify comma-separated list
  - Check all objects included

### Compatibility Tests

- [ ] **Test 39: Python Version**
  - Test with Python 3.7
  - Test with Python 3.8+
  - Test with Python 3.11+

- [ ] **Test 40: FMC Version**
  - Document tested FMC version
  - Test API v1 endpoints
  - Verify domain UUID extraction

## Security Tests

- [ ] **Test 41: Password Security**
  - Verify password not echoed
  - Check not in process list
  - Confirm not logged

- [ ] **Test 42: SSL/TLS**
  - Verify HTTPS used
  - Check cert verification disabled (lab)
  - Test with valid cert (optional)

- [ ] **Test 43: Token Handling**
  - Verify token not printed
  - Check token cleared on exit
  - Confirm not written to disk

## Documentation Tests

- [ ] **Test 44: README Accuracy**
  - Follow README instructions
  - Verify all examples work
  - Check troubleshooting steps

- [ ] **Test 45: Error Messages**
  - Verify all errors have clear messages
  - Check no technical jargon
  - Suggest corrective actions

## Production Readiness Checklist

- [ ] All basic functionality tests passed
- [ ] Tested with production FMC (read-only)
- [ ] Verified no performance impact on FMC
- [ ] Documentation complete and accurate
- [ ] Error handling comprehensive
- [ ] Security measures in place
- [ ] Backup/recovery tested
- [ ] User training completed

## Test Results Template

```
Test Date: ___________
Tester: ___________
FMC Version: ___________
Python Version: ___________

Test Results:
- Total Tests: _____ 
- Passed: _____
- Failed: _____
- Skipped: _____

Failed Tests:
1. Test #__: Reason: ______________
2. Test #__: Reason: ______________

Notes:
_______________________________________
_______________________________________

Sign-off:
- Developer: ___________
- QA: ___________
- Date: ___________
```

## Regression Testing

After any code changes, run:
1. Authentication tests (1-4)
2. Policy discovery tests (5-7)
3. Rule extraction tests (8-11)
4. CSV export tests (21-25)
5. Error handling tests (26-30)

## Continuous Testing

For CI/CD pipeline:
```bash
# Unit tests
python3 -m pytest tests/

# Integration tests (requires FMC lab)
python3 tests/integration_tests.py --fmc-host 10.0.0.100

# Linting
pylint fmc_get_config.py
flake8 fmc_get_config.py

# Type checking
mypy fmc_get_config.py
```

## Bug Report Template

```
Bug ID: ___________
Severity: [ ] Critical [ ] High [ ] Medium [ ] Low
Date Found: ___________

Description:
_______________________________________

Steps to Reproduce:
1. _______________________________________
2. _______________________________________
3. _______________________________________

Expected Behavior:
_______________________________________

Actual Behavior:
_______________________________________

Environment:
- Python Version: ___________
- FMC Version: ___________
- OS: ___________

Logs/Screenshots:
_______________________________________

Workaround (if any):
_______________________________________
```

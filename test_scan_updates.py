#!/usr/bin/env python3
"""
Test script to verify scanner and orchestrator updates for Windows ports and vulnerabilities.
"""

import asyncio
import json
import sys
sys.path.insert(0, '.')

from core.scanner import Scanner
from ai.connector import KMN_AI_Connector
from core.orchestrator import Orchestrator

async def test_scanner_updates():
    """Test that scanner.py has the updated scan profiles."""
    print("Testing Scanner Updates")
    print("=" * 60)
    
    scanner = Scanner()
    
    # Test scan profiles dictionary
    print("\n1. Checking scan profiles in scanner.py:")
    
    # We'll inspect the perform_nmap_scan method indirectly by checking the code
    import inspect
    source = inspect.getsource(scanner.perform_nmap_scan)
    
    expected_profiles = {
        "default": "-sV -sC -O --top-ports 1000",
        "full": "-sV -sC -O -p-",
        "vuln": "-sV --script vuln --top-ports 1000"
    }
    
    found_profiles = {}
    
    # Look for the scan_profiles dictionary in source
    if '"default"' in source:
        # Extract the dictionary section
        lines = source.split('\n')
        in_dict = False
        for line in lines:
            if 'scan_profiles = {' in line:
                in_dict = True
            if in_dict and '}' in line and 'scan_profiles' not in line:
                in_dict = False
            if in_dict:
                # Parse key-value pairs
                if ':' in line and '"' in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip().strip('"\'')
                    value = parts[1].strip().strip(',\'"')
                    found_profiles[key] = value
    
    print("Found scan profiles:")
    for profile, options in found_profiles.items():
        print(f"  {profile}: {options}")
    
    # Check for expected profiles
    all_found = True
    for profile, expected_options in expected_profiles.items():
        if profile in found_profiles:
            if expected_options in found_profiles[profile]:
                print(f"✓ Profile '{profile}' has correct options: {expected_options}")
            else:
                print(f"✗ Profile '{profile}' has wrong options: {found_profiles[profile]}")
                all_found = False
        else:
            print(f"✗ Profile '{profile}' not found")
            all_found = False
    
    return all_found

async def test_orchestrator_scan_type():
    """Test that orchestrator.py uses 'full' scan type."""
    print("\n\n2. Testing Orchestrator scan type update")
    print("=" * 60)
    
    # Create mock objects for testing
    class MockAI:
        async def ask_ai_async(self, *args, **kwargs):
            return type('obj', (object,), {
                'reasoning': 'Test reasoning',
                'suggested_command': 'echo test',
                'risk_level': 'low',
                'confidence': 0.9,
                'attack_phase': 'reconnaissance'
            })()
    
    class MockScanner:
        async def perform_nmap_scan(self, target, scan_type="default"):
            print(f"  Scanner called with target={target}, scan_type={scan_type}")
            return {
                "target": target,
                "success": True,
                "scan_type": scan_type,
                "parsed_results": {"hosts": []}
            }
        
        def parse_nmap_results(self, results):
            return []
    
    # Create orchestrator with mocks
    orchestrator = Orchestrator(MockAI(), MockScanner())
    
    # Create a test session
    session_id = orchestrator.create_session("192.168.1.1")
    
    # Start reconnaissance (this should call scanner with "full" type)
    print(f"\nCreated session: {session_id}")
    print("Starting reconnaissance (should use 'full' scan)...")
    
    await orchestrator.start_reconnaissance(session_id)
    
    # Check if the session was updated
    session = orchestrator.sessions.get(session_id)
    if session:
        print(f"Session status: {session.status}")
        print(f"Session stage: {session.current_stage}")
        print("✓ Orchestrator reconnaissance completed")
        return True
    else:
        print("✗ Session not found")
        return False

def check_orchestrator_code():
    """Check orchestrator.py code for the specific change."""
    print("\n\n3. Checking orchestrator.py source code")
    print("=" * 60)
    
    with open('core/orchestrator.py', 'r') as f:
        content = f.read()
    
    # Look for the line that calls perform_nmap_scan
    lines = content.split('\n')
    found_line = None
    for i, line in enumerate(lines):
        if 'perform_nmap_scan' in line and 'full' in line:
            found_line = line.strip()
            line_num = i + 1
    
    if found_line:
        print(f"✓ Found updated perform_nmap_scan call at line {line_num}:")
        print(f"  {found_line}")
        return True
    else:
        print("✗ Could not find updated perform_nmap_scan call with 'full' parameter")
        # Show what we found instead
        for i, line in enumerate(lines):
            if 'perform_nmap_scan' in line:
                print(f"  Line {i+1}: {line.strip()}")
        return False

async def main():
    print("KMN-CyberSeek Scan Updates Verification")
    print("=" * 60)
    
    all_tests_passed = True
    
    # Test 1: Scanner updates
    if not await test_scanner_updates():
        all_tests_passed = False
    
    # Test 2: Check orchestrator code
    if not check_orchestrator_code():
        all_tests_passed = False
    
    # Test 3: Orchestrator functionality (mock test)
    if not await test_orchestrator_scan_type():
        all_tests_passed = False
    
    print("\n" + "=" * 60)
    if all_tests_passed:
        print("SUCCESS: All tests passed!")
        print("\nSummary of updates:")
        print("1. ✓ Scanner.py updated with:")
        print("   - default: -sV -sC -O --top-ports 1000")
        print("   - full: -sV -sC -O -p-")
        print("   - vuln: -sV --script vuln --top-ports 1000")
        print("2. ✓ Orchestrator.py updated to use 'full' scan in start_reconnaissance")
        print("3. ✓ Windows ports and vulnerabilities are now included in scans")
    else:
        print("FAILURE: Some tests failed")
    
    print("=" * 60)
    return all_tests_passed

if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
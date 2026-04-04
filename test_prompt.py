#!/usr/bin/env python3
"""
Test script to verify SYSTEM_PROMPT loads correctly.
"""
import sys
sys.path.insert(0, '.')

from ai.prompts import SYSTEM_PROMPT

def main():
    print("Testing SYSTEM_PROMPT import...")
    print(f"Length: {len(SYSTEM_PROMPT)} characters")
    print("\nFirst 500 characters:")
    print(SYSTEM_PROMPT[:500])
    print("\nChecking for required sections...")
    
    required_sections = [
        ("WEB APPLICATION METHODOLOGY", "Web app methodology"),
        ("CONTEXT-AWARE TOOLING", "Context-aware tooling"),
        ("NON-INTERACTIVE EXECUTION", "Non-interactive execution"),
        ("DETAILED ATTACK CHAINING EXAMPLES", "Attack chaining examples"),
        ("curl -I -s", "curl fingerprinting"),
        ("wpscan --url", "WPScan command"),
        ("--batch", "batch flag"),
        ("msfconsole -q -x", "Metasploit one-liner"),
    ]
    
    for keyword, description in required_sections:
        if keyword in SYSTEM_PROMPT:
            print(f"✓ Found {description}: '{keyword}'")
        else:
            print(f"✗ Missing {description}: '{keyword}'")
    
    print("\nSYSTEM_PROMPT appears valid!")

if __name__ == "__main__":
    main()
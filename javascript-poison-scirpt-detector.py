# -*- coding: utf-8 -*-
"""
Created on Sat Feb 15 20:39:25 2024

@author: IAN CARTER KULANI

"""

import re

def detect_js_poison_script(js_code):
    """
    Detects potential JavaScript Poison Script Injection patterns.
    """
    # Common malicious patterns
    patterns = [
        r"<script.*?>.*?</script>",  # Embedded script tags
        r"document\.cookie",  # Accessing cookies
        r"eval\(.*?\)",  # Use of eval (dangerous execution)
        r"setTimeout\(.*?\)",  # Potential delay attack
        r"setInterval\(.*?\)",  # Repeated execution
        r"window\.location",  # Redirect-based attack
        r"XMLHttpRequest",  # Potential AJAX-based attack
        r"fetch\(",  # Fetch API misuse
        r"onerror\s*=\s*",  # Exploiting error handling
        r"unescape\(",  # Decoding obfuscated payloads
    ]
    
    # Check for malicious patterns
    for pattern in patterns:
        if re.search(pattern, js_code, re.IGNORECASE):
            return f"[ALERT] Potential JavaScript Poison Script detected: {pattern}"
    
    return "[SAFE] No malicious script detected."

if __name__ == "__main__":
    print("Cyber Security Tool: JavaScript Poison Script Detector")
    user_js_code = input("Enter JavaScript code for analysis:")
    result = detect_js_poison_script(user_js_code)
    print(result)

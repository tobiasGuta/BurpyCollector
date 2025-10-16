# BurpyCollector
BurpyCollector is a Jython Burp Suite extension that automatically collects and deduplicates unique HTTP endpoints from Proxy traffic. It respects Burp’s Target scope (or a custom host list), normalizes queries, and saves the results in JSON Lines format for easy parsing and recon use.
# Installation
https://github.com/user-attachments/assets/7d8366fd-7ec5-4cec-8725-e2ab8b005f6a

# regex

```bash
printf '\n\n' && jq -r '
  .[]
  | select(.method=="POST")
  | "URL: \(.full_url)\nBODY:\(.post_body)\nTOOL:\(.tool)\n--------------------------------------------------"
' /user/tools/endpoint_saver/burp_endpoints_pretty.json | awk '/^--------------------------------------------------$/ { print; for(i=0;i<5;i++) print ""; next
 } { print }
```

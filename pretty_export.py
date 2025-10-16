# pretty_export.py
import json

infile = r"D:\users\tools\endpoint_saver\burp_endpoints.jsonl" # change me
outfile = r"D:\users\tools\endpoint_saver\burp_endpoints_pretty.json" # change me

objs = []
with open(infile, "r", encoding="utf-8") as fh:
    for line in fh:
        s = line.strip()
        if not s:
            continue
        objs.append(json.loads(s))

with open(outfile, "w", encoding="utf-8") as fh:
    json.dump(objs, fh, ensure_ascii=False, indent=2)

print("Wrote", outfile)

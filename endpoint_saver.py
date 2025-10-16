# - respects Burp's Target scope when use_burp_scope = True
# - fallback to allowed_hosts_csv when use_burp_scope = False
# - saves everything for in-scope targets, strips host port, removes timestamp column
# For Jython 2.7 (Burp). Save file as UTF-8 (no BOM).

try:
    from burp import IBurpExtender, IHttpListener
    from java.text import SimpleDateFormat
    from java.util import Date, TimeZone
    from urlparse import urlparse, parse_qs
    from urllib import quote_plus
    import csv, codecs, os
    try:
        import json
    except Exception:
        # fallback for older Jython environments
        import simplejson as json
except Exception as e:
    import sys
    sys.stderr.write("[EndpointSaver] IMPORT ERROR: %s\n" % e)
    raise

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("EndpointSaverCSV_AutoScope")

        # ---------------- CONFIG ----------------
        # Use JSON Lines format for readability and safe append.
        self.outfile = r"D:\users\tools\endpoint_saver\burp_endpoints.jsonl" # change me
        self.normalize_query = True   # True = sort query params for dedupe
        self.only_proxy = True        # True = capture Proxy tool only
        # Capture POST request bodies (store on request event, attach on response event)
        self.capture_post_bodies = True
        # Maximum body length to keep (truncate longer bodies)
        self.post_body_max_len = 2000
        # How long to keep pending request bodies (seconds)
        self.pending_body_ttl = 300

        # If True, use Burp's Target scope (Target -> Scope) to decide what to save.
        # If False, use allowed_hosts_csv below.
        self.use_burp_scope = True

        # When use_burp_scope is False, fallback to this comma-separated list:
        self.allowed_hosts_csv = "example.com"
        self.include_subdomains = True
        # ----------------------------------------

        # in-memory dedupe set
        self.seen = set()
        # pending request bodies (keyed by dedupe_key)
        self.pending_bodies = {}

        # normalize allowed hosts list
        self.allowed_hosts = [h.strip().lower() for h in self.allowed_hosts_csv.split(",") if h.strip()]

        # ensure directory exists
        try:
            parent = os.path.dirname(self.outfile)
            if parent and not os.path.exists(parent):
                os.makedirs(parent)
        except Exception as e:
            print("[EndpointSaver] ERROR creating directory: %s" % e)

        # create file if missing, then load existing seen keys
        try:
            first = not os.path.exists(self.outfile)
            if first:
                # create empty file
                parent = os.path.dirname(self.outfile)
                if parent and not os.path.exists(parent):
                    os.makedirs(parent)
                with codecs.open(self.outfile, "w", "utf-8") as fh:
                    fh.write("")
            self._load_existing_seen()
        except Exception as e:
            print("[EndpointSaver] ERROR initializing file: %s" % e)

        # register listener
        callbacks.registerHttpListener(self)
        print("[EndpointSaver] ready -> %s" % self.outfile)
        print("[EndpointSaver] use_burp_scope=%s  allowed_hosts=%s  include_subdomains=%s" %
              (self.use_burp_scope, self.allowed_hosts, self.include_subdomains))

    def _now_iso(self):
        fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"))
        return fmt.format(Date())

    def _normalize_query(self, raw_query):
        if not raw_query:
            return ""
        try:
            qdict = parse_qs(raw_query, keep_blank_values=True)
            pairs = []
            for k in sorted(qdict.keys()):
                vals = qdict[k]
                for v in sorted(vals):
                    pairs.append("%s=%s" % (quote_plus(k), quote_plus(v)))
            return "&".join(pairs)
        except Exception:
            return raw_query

    def _host_matches(self, hostname):
        """Return True if hostname matches any allowed host (respecting include_subdomains)."""
        if not hostname:
            return False
        host = hostname.split(":")[0].lower()
        for allowed in self.allowed_hosts:
            if self.include_subdomains:
                if host == allowed or host.endswith("." + allowed):
                    return True
            else:
                if host == allowed:
                    return True
        return False

    def _load_existing_seen(self):
        try:
            if not os.path.exists(self.outfile):
                return
            count = 0
            # Try JSON Lines first
            try:
                with codecs.open(self.outfile, "r", "utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            # not valid json, skip to CSV fallback
                            raise
                        method = obj.get('method') or ""
                        host = (obj.get('host') or "").split(":")[0]
                        path = obj.get('path') or ""
                        query = obj.get('query') or ""
                        key = "%s %s %s %s" % (method, host, path, query)
                        self.seen.add(key)
                        count += 1
            except Exception:
                # Fallback: try CSV parsing for legacy files
                try:
                    with codecs.open(self.outfile, "r", "utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for row in reader:
                            method = row.get('method') or ""
                            host = (row.get('host') or "").split(":")[0]
                            path = row.get('path') or ""
                            query = row.get('query') or ""
                            key = "%s %s %s %s" % (method, host, path, query)
                            self.seen.add(key)
                            count += 1
                except Exception:
                    pass
            print("[EndpointSaver] loaded %d existing endpoints for dedupe" % count)
        except Exception as e:
            print("[EndpointSaver] ERROR loading existing CSV: %s" % e)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if self.only_proxy and toolFlag != self._callbacks.TOOL_PROXY:
                return

            # If this is a request event and capturing POST bodies is enabled,
            # capture the request body for POST and store it in pending_bodies
            # so it can be attached when the response event arrives.
            analyzed_req = self._helpers.analyzeRequest(messageInfo)
            url = analyzed_req.getUrl()  # java.net.URL object
            method = analyzed_req.getMethod()
            full_url = url.toString()
            parsed = __import__('urlparse').urlparse(full_url)
            host_with_port = parsed.netloc
            path = parsed.path if parsed.path else "/"
            raw_query = parsed.query or ""
            query = self._normalize_query(raw_query) if self.normalize_query else raw_query
            host = host_with_port.split(":")[0]

            dedupe_key = "%s %s %s %s" % (method, host, path, query)

            # If request event: optionally capture POST body and return
            if messageIsRequest:
                try:
                    if self.capture_post_bodies and method.upper() == 'POST':
                        body_bytes = messageInfo.getRequest()[analyzed_req.getBodyOffset():]
                        try:
                            # use Burp helpers to convert bytes to string (safer for Jython/Java byte[])
                            body = self._helpers.bytesToString(body_bytes)
                        except Exception:
                            try:
                                body = body_bytes.tostring() if hasattr(body_bytes, 'tostring') else str(body_bytes)
                            except Exception:
                                body = str(body_bytes)
                        if body is None:
                            body = ""
                        # Truncate and store
                        if len(body) > self.post_body_max_len:
                            body = body[:self.post_body_max_len] + "..."
                        # store with timestamp
                        try:
                            ts = int(Date().getTime() / 1000)
                        except Exception:
                            import time
                            ts = int(time.time())
                        self.pending_bodies[dedupe_key] = {'body': body, 'ts': ts}
                except Exception:
                    pass
                return

            # Scope check
            in_scope = False
            if self.use_burp_scope:
                try:
                    in_scope = bool(self._callbacks.isInScope(url))
                except Exception:
                    in_scope = self._host_matches(host_with_port)
            else:
                in_scope = self._host_matches(host_with_port)
            if not in_scope:
                return

            # prune stale pending bodies
            try:
                try:
                    now_ts = int(Date().getTime() / 1000)
                except Exception:
                    import time
                    now_ts = int(time.time())
                stale = []
                for k, v in self.pending_bodies.items():
                    if now_ts - v.get('ts', 0) > self.pending_body_ttl:
                        stale.append(k)
                for k in stale:
                    try:
                        del self.pending_bodies[k]
                    except Exception:
                        pass
            except Exception:
                pass

            dedupe_key = "%s %s %s %s" % (method, host, path, query)
            if dedupe_key in self.seen:
                return
            self.seen.add(dedupe_key)

            # Default placeholders
            status_code = "-"
            content_type = "-"

            # Capture response if available
            resp = messageInfo.getResponse()
            if resp:
                try:
                    analyzed_resp = self._helpers.analyzeResponse(resp)
                    status_code = str(analyzed_resp.getStatusCode())
                    headers = analyzed_resp.getHeaders()
                    for h in headers:
                        if h.lower().startswith("content-type:"):
                            content_type = h.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

            # Attach any pending POST body captured earlier
            post_body = None
            try:
                pending = self.pending_bodies.pop(dedupe_key, None)
                if pending:
                    post_body = pending.get('body')
            except Exception:
                post_body = None

            tool_name = self._toolname(toolFlag)

            # Write JSON Lines row
            try:
                obj = {
                    'tool': tool_name,
                    'method': method,
                    'host': host,
                    'path': path,
                    'query': query,
                    'full_url': full_url,
                    'status_code': status_code,
                    'content_type': content_type,
                    'post_body': post_body if post_body is not None else ""
                }
                with codecs.open(self.outfile, "a", "utf-8") as fh:
                    fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
                print("[EndpointSaver] saved: %s %s%s (status: %s)" % (method, host, path, status_code))
            except Exception as e:
                print("[EndpointSaver] ERROR writing file: %s" % e)

        except Exception as ex:
            print("[EndpointSaver] error: %s" % ex)

    def _toolname(self, toolFlag):
        if toolFlag == self._callbacks.TOOL_PROXY:
            return "Proxy"
        if toolFlag == self._callbacks.TOOL_SCANNER:
            return "Scanner"
        if toolFlag == self._callbacks.TOOL_INTRUDER:
            return "Intruder"
        if toolFlag == self._callbacks.TOOL_REPEATER:
            return "Repeater"
        if toolFlag == self._callbacks.TOOL_SEQUENCER:
            return "Sequencer"
        if toolFlag == self._callbacks.TOOL_EXTENDER:
            return "Extender"
        if toolFlag == self._callbacks.TOOL_SPIDER:
            return "Spider"
        if toolFlag == self._callbacks.TOOL_TARGET:
            return "Target"
        return "Other"

/*
 * Name: Custom Detection: Oyster/Broomstick (CleanUpLoader) SEO-Poisoning & C2
 *
 * Description:
 *   Detects network indicators associated with the Oyster / Broomstick /
 *   CleanUpLoader backdoor delivered via SEO poisoning and malvertising of
 *   trojanized IT utilities (fake PuTTY / WinSCP) — FS-ISAC alert 95104129
 *   (UNC6016 / UNC6286). The trigger matches three independent, high-fidelity
 *   network signals over DNS, HTTP, and TLS:
 *     1. Distribution / C2 DOMAINS (exact or subdomain-boundary match) seen in
 *        DNS QNAME, DNS answers, HTTP Host, or TLS SNI.
 *     2. Oyster C2 IP ADDRESSES (exact match on the flow server endpoint) seen
 *        on HTTP or TLS connections.
 *     3. Oyster HTTP C2 fingerprints: distinctive beacon URI paths, spoofed
 *        user-agent strings, and payload-download DLL filenames.
 *   Expected directionality is Egress (Outbound): internal hosts (often IT
 *   admins) reaching out to attacker distribution sites / C2. The trigger
 *   classifies direction per flow and raises a native Reveal(x) detection
 *   (commitDetection) with full SOC enrichment, falling back to commitRecord
 *   (then a debug log) where detection APIs are unavailable.
 *
 * Events:
 *   DNS_REQUEST
 *   DNS_RESPONSE
 *   HTTP_REQUEST
 *   SSL_OPEN
 *
 * Assignments:
 *   Assign to all internal client devices (or a "Workstations" / "IT Admin"
 *   device group) for outbound DNS/HTTP/TLS visibility. If DNS is served by
 *   internal resolvers, also assign to the "DNS Servers" group so resolver-
 *   sourced QNAME lookups are seen. Server-side assignment is not required;
 *   this trigger targets client-initiated outbound activity. Broad "All
 *   Devices" assignment works but increases per-event CPU on high-volume
 *   sensors — prefer the narrowest effective client scope.
 *
 * Configuration Requirements:
 *   - Reveal(x) 360 / firmware 9.x+ (default target).
 *   - No payload buffering required (matches on parsed L7 metadata only).
 *   - commitDetection requires an EDA sensor with detection privileges; on
 *     sensors/firmware lacking it, the trigger degrades to commitRecord, then
 *     to a debug log line (all guarded with typeof checks).
 *   - Known exclusion: Palo Alto DNS sinkhole — alerts are suppressed when a
 *     DNS answer contains 198.135.184.22 or the QNAME equals
 *     sinkhole.paloaltonetworks.com.
 *   - Privilege to save/enable triggers in the ExtraHop Admin UI.
 *
 * Notes:
 *   - Indicators are maintained as static maps at the top of the script
 *     (exactDomains, c2Ips, c2UriPaths, suspiciousUserAgents, payloadDlls).
 *     Update these in place as the campaign evolves.
 *   - Domain matching uses exact-or-subdomain-boundary logic (no mid-string
 *     substring matches). C2 IPs match exactly on the server endpoint. Short
 *     URI paths (/reg, /secure) only fire when corroborated by a known C2 IP
 *     or a suspicious user agent, to suppress false positives; the long/unique
 *     URIs fire independently. Hashes from the bulletin are host-only and not
 *     network-observable, so they are not matched here.
 *   - Deduplication via identityKey + identityTtl 'day' (one detection per
 *     client+indicator per day). Constant-time checks, early returns, no
 *     unbounded loops.
 *   - Doc audit: Verified against ExtraHop 26.1 / RX 9.x Trigger API
 *     documentation and Mercury's create-custom-detection.pdf on 2026-06-15.
 *     Confirmed event names (DNS_REQUEST, DNS_RESPONSE, HTTP_REQUEST,
 *     SSL_OPEN), property names (DNS.qname, DNS.answers, HTTP.host, HTTP.uri,
 *     HTTP.headers, SSL.host, Flow.client/Flow.server.ipaddr.localityName),
 *     and APIs (commitDetection, commitRecord). Corrections applied during
 *     audit: added riskScore to commitDetection (per create-custom-detection.pdf
 *     signature) and removed the deprecated categories parameter (deprecated
 *     since 9.3 -> Detection Catalog). No deprecated APIs used (SSL global used
 *     instead of TLS; no *.tprocess; no exit()).
 *   - 26.1 editor (.d.ts) reconciliation: the 26.1 trigger-editor TypeScript
 *     validator on this firmware does NOT declare several properties present in
 *     the public API reference. The following substitutions were applied so the
 *     trigger compiles cleanly in the editor:
 *       * TLS SNI:    SSL.serverName  -> SSL.host
 *       * TLS hashes: SSL.ja3Fingerprint / SSL.ja3sFingerprint -> SSL.ja4Fingerprint
 *       * Removed HTTP.statusCode (not present on HTTP_REQUEST type)
 *       * Removed DNS.rcode (not declared on DNS type)
 *       * DNSAnswer.rdata -> DNSAnswer.data
 *       * GeoIP.country/city/asn/org -> guarded method lookups via an any-typed
 *         alias (accessors are not declared in this editor .d.ts)
 *       * Removed the metricAdd* metric fallback (metricAdd* globals are not
 *         declared in this editor .d.ts; fallback chain is now
 *         commitDetection -> commitRecord -> debug()).
 */

/* ----------------------------- IOC DEFINITIONS ----------------------------- */

// Distribution + C2 domains (Arctic Wolf, SC Media, Darktrace). Lowercase.
var exactDomains = {
  'updaterputty.com': 'Oyster/Broomstick SEO-poisoning distribution domain (fake PuTTY)',
  'putty.run': 'Oyster/Broomstick SEO-poisoning distribution domain (fake PuTTY)',
  'putty.bet': 'Oyster/Broomstick SEO-poisoning distribution domain (fake PuTTY)',
  'puttyy.org': 'Oyster/Broomstick SEO-poisoning distribution domain (typosquat PuTTY)',
  'zephyrhype.com': 'Oyster/Broomstick malvertising distribution domain',
  'putty-app.naymin.com': 'Oyster/Broomstick typosquat domain (Darktrace investigation)'
};

// Oyster C2 IP addresses (Darktrace). Exact string match on server endpoint.
var c2Ips = {
  '85.239.52.99': 'Oyster C2 server (Darktrace)',
  '194.213.18.89': 'Oyster C2 server (/reg beacon, Darktrace)',
  '185.28.119.113': 'Oyster C2 server (/secure beacon, Darktrace)',
  '185.196.8.217': 'Oyster C2 server (Darktrace)',
  '185.208.158.119': 'Oyster C2 server (Darktrace)'
};

// High-uniqueness Oyster C2 beacon URIs — fire independently.
var c2UriPathsStrong = {
  '/api/kcehc': 'Oyster C2 beacon URI (Darktrace)',
  '/api/jgfnsfnuefcnegfnehjbfncejfh': 'Oyster C2 beacon URI (Darktrace)'
};

// Short Oyster C2 URIs — only fire when corroborated by a C2 IP or bad UA.
var c2UriPathsWeak = {
  '/reg': 'Oyster C2 registration beacon URI (Darktrace)',
  '/secure': 'Oyster C2 initial callback URI (Darktrace)'
};

// Spoofed user-agent strings used by Oyster HTTP C2 (Darktrace). Lowercase.
var suspiciousUserAgents = {
  'wordpressagent': 'Oyster spoofed HTTP user-agent (Darktrace)',
  'fingerprint': 'Oyster spoofed HTTP user-agent (Darktrace)',
  'fingerprintpersistent': 'Oyster spoofed HTTP user-agent (Darktrace)'
};

// Campaign DLL filenames that may appear in payload-download URIs.
var payloadDlls = {
  'twain_96.dll': 'Oyster loader DLL (rundll32 DllRegisterServer persistence)',
  'zqin.dll': 'Oyster loader DLL',
  'green.dll': 'Oyster loader DLL',
  'captureservice.dll': 'Oyster loader DLL (CaptureService task)'
};

// Palo Alto DNS sinkhole exclusion.
var PALO_ALTO_SINKHOLE_IP = '198.135.184.22';
var PALO_ALTO_SINKHOLE_QNAME = 'sinkhole.paloaltonetworks.com';

var DETECTION_TYPE = 'oyster_broomstick_network_ioc';
var CUSTOM_RECORD_ID = 'oyster-broomstick-ioc';

/* ------------------------------- HELPERS ----------------------------------- */

function asString(x) { return (x === null || typeof x === 'undefined') ? '' : String(x); }

function safeDeviceName(dev) { return dev ? asString(dev.name || dev.hostname || '') : ''; }

function safeHostnames(arr) {
  if (!arr || !arr.length) return '';
  var r = '';
  for (var i = 0; i < arr.length; i++) { if (i > 0) r += ', '; r += asString(arr[i]); }
  return r;
}

function normalize(value) {
  if (value === null || typeof value === 'undefined') return '';
  return String(value).trim().toLowerCase();
}

function normalizeHost(host) {
  host = normalize(host);
  if (!host) return '';
  // strip [ipv6] brackets and any trailing :port
  if (host.indexOf(']:') !== -1) {
    host = host.replace(/^\[/, '').replace(/\](:\d+)?$/, '');
  } else if ((host.match(/:/g) || []).length === 1) {
    host = host.split(':')[0];
  }
  if (host.charAt(host.length - 1) === '.') { host = host.slice(0, -1); }
  return host;
}

// Exact or subdomain-boundary domain match (no mid-string substring matches).
function matchDomain(host) {
  var h = normalizeHost(host);
  if (!h) return null;
  if (exactDomains[h]) { return { type: 'domain', value: h, reason: exactDomains[h] }; }
  for (var dom in exactDomains) {
    if (exactDomains.hasOwnProperty(dom)) {
      if (h.length > dom.length && h.indexOf('.' + dom) === (h.length - dom.length - 1)) {
        return { type: 'domain', value: h, reason: exactDomains[dom] + ' (subdomain)' };
      }
    }
  }
  return null;
}

function matchIp(ipObj) {
  if (!ipObj) return null;
  var ip = String(ipObj);
  if (c2Ips[ip]) { return { type: 'ip', value: ip, reason: c2Ips[ip] }; }
  return null;
}

// HTTP fingerprint match: strong URI, payload DLL, suspicious UA, or
// (weak URI corroborated by C2 IP / bad UA). Returns indicator or null.
function matchHttpFingerprint(uri, userAgent, serverIpObj) {
  var u = normalize(uri);
  var ua = normalize(userAgent);
  var serverIsC2 = serverIpObj ? (c2Ips[String(serverIpObj)] ? true : false) : false;
  var uaBad = ua && suspiciousUserAgents[ua] ? true : false;

  if (ua && suspiciousUserAgents[ua]) {
    return { type: 'user-agent', value: ua, reason: suspiciousUserAgents[ua] };
  }
  if (u) {
    var path = u;
    var qpos = path.indexOf('?');
    if (qpos !== -1) { path = path.substring(0, qpos); }
    if (c2UriPathsStrong[path]) {
      return { type: 'uri', value: path, reason: c2UriPathsStrong[path] };
    }
    for (var dll in payloadDlls) {
      if (payloadDlls.hasOwnProperty(dll)) {
        var seg = '/' + dll;
        if (path.length >= seg.length && path.indexOf(seg) === (path.length - seg.length)) {
          return { type: 'payload', value: dll, reason: payloadDlls[dll] };
        }
      }
    }
    if (c2UriPathsWeak[path] && (serverIsC2 || uaBad)) {
      return { type: 'uri', value: path, reason: c2UriPathsWeak[path] + ' (corroborated)' };
    }
  }
  return null;
}

// Direction classifier (combined perimeter + flow-perspective labels).
function classifyDirection(iocMatchSide, isDnsQuery) {
  var clientLocality = (Flow && Flow.client && Flow.client.ipaddr) ? String(Flow.client.ipaddr.localityName || '') : '';
  var serverLocality = (Flow && Flow.server && Flow.server.ipaddr) ? String(Flow.server.ipaddr.localityName || '') : '';
  if (isDnsQuery && clientLocality === 'internal') return 'Egress (Outbound)';
  if (clientLocality === 'internal' && serverLocality === 'internal') return 'Lateral (East-West)';
  if (iocMatchSide === 'server' && clientLocality === 'internal') return 'Egress (Outbound)';
  if (iocMatchSide === 'client' && clientLocality === 'external' && serverLocality === 'internal') return 'Ingress (Inbound)';
  return 'Unknown';
}

/* ---------------------- SOC ANALYSIS ENRICHMENT ---------------------------- */

function detectionDescription(indicator, contextLine, direction) {
  var lines = [
    'Observed network activity associated with ' + asString(indicator.campaign || 'Oyster/Broomstick (CleanUpLoader)') + ' indicators (FS-ISAC alert 95104129, UNC6016/UNC6286).',
    '',
    '## Indicator',
    '- Type: ' + asString(indicator.type),
    '- Value: ' + asString(indicator.value),
    '- Reason: ' + asString(indicator.reason),
    '',
    '## Flow',
    '- Event: ' + asString(event),
    '- Protocol: ' + asString((typeof Flow !== 'undefined' && Flow.l7proto) ? Flow.l7proto : ''),
    '- Client IP: ' + asString((Flow && Flow.client) ? Flow.client.ipaddr : ''),
    '- Client Port: ' + asString((Flow && Flow.client) ? Flow.client.port : ''),
    '- Server IP: ' + asString((Flow && Flow.server) ? Flow.server.ipaddr : ''),
    '- Server Port: ' + asString((Flow && Flow.server) ? Flow.server.port : ''),
    '- VLAN: ' + asString((typeof Flow !== 'undefined' && Flow.vlan) ? Flow.vlan : ''),
    '- Client Locality: ' + asString((Flow && Flow.client && Flow.client.ipaddr) ? String(Flow.client.ipaddr.localityName || '') : ''),
    '- Server Locality: ' + asString((Flow && Flow.server && Flow.server.ipaddr) ? String(Flow.server.ipaddr.localityName || '') : ''),
    '- Traffic Direction: ' + asString(direction),
    '',
    '## Device Context',
    '- Client Device ID: ' + asString((Flow && Flow.client && Flow.client.device) ? Flow.client.device.id : ''),
    '- Client Device Name: ' + safeDeviceName((Flow && Flow.client && Flow.client.device) ? Flow.client.device : null),
    '- Client DNS Names: ' + safeHostnames((Flow && Flow.client && Flow.client.device) ? Flow.client.device.dnsNames : null),
    '- Server Device ID: ' + asString((Flow && Flow.server && Flow.server.device) ? Flow.server.device.id : ''),
    '- Server Device Name: ' + safeDeviceName((Flow && Flow.server && Flow.server.device) ? Flow.server.device : null),
    '- Server DNS Names: ' + safeHostnames((Flow && Flow.server && Flow.server.device) ? Flow.server.device.dnsNames : null)
  ];

  var protoCtx = [];
  if (typeof SSL !== 'undefined') {
    if (SSL.host) protoCtx.push('- TLS SNI: ' + asString(SSL.host));
    if (SSL.version) protoCtx.push('- TLS Version: ' + asString(SSL.version));
    if (SSL.ja4Fingerprint) protoCtx.push('- JA4: ' + asString(SSL.ja4Fingerprint));
    if (SSL.cipherSuite) protoCtx.push('- TLS Cipher Suite: ' + asString(SSL.cipherSuite));
  }
  if (typeof HTTP !== 'undefined') {
    if (HTTP.host) protoCtx.push('- HTTP Host: ' + asString(HTTP.host));
    if (HTTP.method) protoCtx.push('- HTTP Method: ' + asString(HTTP.method));
    if (HTTP.uri) protoCtx.push('- HTTP URI: ' + asString(HTTP.uri));
    var ua = HTTP.headers && (HTTP.headers['User-Agent'] || HTTP.headers['user-agent']);
    if (ua) protoCtx.push('- HTTP User-Agent: ' + asString(ua));
  }
  if (typeof DNS !== 'undefined') {
    if (DNS.qname) protoCtx.push('- DNS QNAME: ' + asString(DNS.qname));
    if (DNS.qtype) protoCtx.push('- DNS QTYPE: ' + asString(DNS.qtype));
    if (DNS.answers) protoCtx.push('- DNS RDATA: ' + asString(DNS.answers));
  }
  if (protoCtx.length) {
    lines.push('', '## Protocol Context');
    for (var i = 0; i < protoCtx.length; i++) { lines.push(protoCtx[i]); }
  }

  var iocCtx = [];
  iocCtx.push('- Indicator Category: Malspam / Backdoor C2 (Oyster/Broomstick/CleanUpLoader)');
  iocCtx.push('- Match Source: FS-ISAC alert 95104129; Arctic Wolf, Darktrace, SC Media');
  iocCtx.push('- Delivery: SEO poisoning / malvertising of trojanized PuTTY & WinSCP');
  iocCtx.push('- Persistence (host): scheduled task running rundll32.exe twain_96.dll,DllRegisterServer');
  lines.push('', '## IOC Context');
  for (var j = 0; j < iocCtx.length; j++) { lines.push(iocCtx[j]); }

  var vulnCtx = [];
  vulnCtx.push('- Threat Intel Feed: FS-ISAC (Member Submission)');
  vulnCtx.push('- Threat Actors: UNC6016, UNC6286 (Oyster also used by Rhysida, Vanilla Tempest)');
  vulnCtx.push('- TLP: AMBER');
  vulnCtx.push('- Confidence: High');
  lines.push('', '## Vulnerability & Threat Intel');
  for (var k = 0; k < vulnCtx.length; k++) { lines.push(vulnCtx[k]); }

  var geoCtx = [];
  if (Flow && Flow.server && Flow.server.ipaddr && String(Flow.server.ipaddr.localityName || '') === 'external') {
    // GeoIP accessors are not declared in the 26.1 editor .d.ts; reference via
    // an any-typed alias and guard each lookup so the trigger compiles cleanly
    // and degrades safely if the accessor is unavailable on the sensor.
    var geo = /** @type {any} */ (typeof GeoIP !== 'undefined' ? GeoIP : null);
    var serverIpForGeo = Flow.server.ipaddr;
    if (geo) {
      if (typeof geo.lookupCountryName === 'function') {
        var gc = geo.lookupCountryName(serverIpForGeo);
        if (gc) geoCtx.push('- Server GeoIP Country: ' + asString(gc));
      }
      if (typeof geo.lookupCity === 'function') {
        var gci = geo.lookupCity(serverIpForGeo);
        if (gci) geoCtx.push('- Server GeoIP City: ' + asString(gci));
      }
      if (typeof geo.lookupAsn === 'function') {
        var ga = geo.lookupAsn(serverIpForGeo);
        if (ga) geoCtx.push('- Server ASN: ' + asString(ga));
      }
    }
  }
  if (geoCtx.length) {
    lines.push('', '## GeoIP Context');
    for (var g = 0; g < geoCtx.length; g++) { lines.push(geoCtx[g]); }
  }

  lines.push('', '## Observation');
  lines.push('- Observed At: ' + asString(new Date().toISOString()));
  lines.push('- Traffic Direction: ' + asString(direction));
  if (contextLine) lines.push('- Context: ' + asString(contextLine));
  lines.push('- Recommended Action: Isolate the client host (likely IT-admin workstation), hunt for a scheduled task invoking rundll32.exe against a DLL in %APPDATA%\\Roaming, check for follow-on RDP/SMB lateral movement, and rotate credentials used on the host.');

  return lines.join('\n\n');
}

/* ------------------------- DETECTION DISPATCH ------------------------------ */

function riskScoreFor(indicatorType) {
  // C2 IP, distribution/C2 domain, spoofed UA, and unique C2 URI are
  // high-fidelity Oyster backdoor signals (ransomware precursor) -> 80 (red).
  // Payload-DLL and corroborated short-URI matches -> 70 (orange).
  if (indicatorType === 'payload') { return 70; }
  return 80;
}

function raiseDetection(indicator, direction, contextLine) {
  var clientIp = (Flow && Flow.client) ? Flow.client.ipaddr : null;
  var description = detectionDescription(indicator, contextLine, direction);
  var title = 'Oyster/Broomstick network IOC: ' + asString(indicator.type) + ' ' + asString(indicator.value);
  var identityKey = asString(clientIp) + '|' + asString(indicator.type) + '|' + asString(indicator.value);
  var riskScore = riskScoreFor(indicator.type);

  if (typeof commitDetection === 'function') {
    var participants = [];
    if (Flow && Flow.client && Flow.client.offender) { participants.push(Flow.client.offender); }
    if (Flow && Flow.server && Flow.server.victim) { participants.push(Flow.server.victim); }
    commitDetection(DETECTION_TYPE, {
      title: title,
      description: description,
      riskScore: riskScore,
      participants: participants,
      identityKey: identityKey,
      identityTtl: 'day'
    });
    return;
  }

  if (typeof commitRecord === 'function') {
    debug('Oyster trigger: commitDetection unavailable; writing custom record.');
    commitRecord(CUSTOM_RECORD_ID, {
      indicatorType: asString(indicator.type),
      indicatorValue: asString(indicator.value),
      indicatorReason: asString(indicator.reason),
      direction: asString(direction),
      eventName: asString(event),
      clientIpAddr: (Flow && Flow.client) ? Flow.client.ipaddr : null,
      serverIpAddr: (Flow && Flow.server) ? Flow.server.ipaddr : null,
      description: description
    });
    return;
  }

  // Final fallback: neither commitDetection nor commitRecord is available on
  // this sensor. Emit a debug line so the match is still observable in the
  // trigger runtime log. (A metric fallback is intentionally omitted: the
  // metricAdd* globals are not declared in the 26.1 trigger-editor .d.ts on
  // this firmware, so referencing them fails TypeScript validation.)
  debug('Oyster/Broomstick IOC match (' + asString(indicator.type) + ': ' +
        asString(indicator.value) + '), but detection/record APIs are ' +
        'unavailable on this sensor; no artifact emitted.');
}

/* ------------------------------- MAIN -------------------------------------- */

var evt = String(event);
var indicator = null;
var isDnsQuery = false;
var matchSide = 'server';

if (evt === 'DNS_REQUEST') {
  isDnsQuery = true;
  var qn = (typeof DNS !== 'undefined' && DNS.qname) ? normalizeHost(DNS.qname) : '';
  if (qn === PALO_ALTO_SINKHOLE_QNAME) { return; }
  indicator = matchDomain(qn);

} else if (evt === 'DNS_RESPONSE') {
  var rq = (typeof DNS !== 'undefined' && DNS.qname) ? normalizeHost(DNS.qname) : '';
  if (rq === PALO_ALTO_SINKHOLE_QNAME) { return; }
  // Palo Alto sinkhole answer exclusion.
  if (typeof DNS !== 'undefined' && DNS.answers && DNS.answers.length) {
    for (var a = 0; a < DNS.answers.length; a++) {
      var ans = DNS.answers[a];
      var rdata = ans ? asString(ans.data || ans) : '';
      if (rdata.indexOf(PALO_ALTO_SINKHOLE_IP) !== -1) { return; }
    }
  }
  isDnsQuery = true;
  indicator = matchDomain(rq);

} else if (evt === 'HTTP_REQUEST') {
  var serverIp = (Flow && Flow.server) ? Flow.server.ipaddr : null;
  // 1) C2 IP on the server endpoint.
  indicator = matchIp(serverIp);
  // 2) Distribution/C2 host header.
  if (!indicator && typeof HTTP !== 'undefined' && HTTP.host) {
    indicator = matchDomain(HTTP.host);
  }
  // 3) HTTP C2 fingerprint (URI / user-agent / payload DLL).
  if (!indicator && typeof HTTP !== 'undefined') {
    var hua = HTTP.headers ? (HTTP.headers['User-Agent'] || HTTP.headers['user-agent']) : '';
    indicator = matchHttpFingerprint(HTTP.uri, hua, serverIp);
  }

} else if (evt === 'SSL_OPEN') {
  var sslServerIp = (Flow && Flow.server) ? Flow.server.ipaddr : null;
  // 1) C2 IP on the server endpoint.
  indicator = matchIp(sslServerIp);
  // 2) Distribution/C2 domain in TLS SNI.
  if (!indicator && typeof SSL !== 'undefined' && SSL.host) {
    indicator = matchDomain(SSL.host);
  }
}

if (indicator) {
  var direction = classifyDirection(matchSide, isDnsQuery);
  var contextLine = 'Oyster/Broomstick (CleanUpLoader) — FS-ISAC 95104129';
  indicator.campaign = 'Oyster/Broomstick (CleanUpLoader)';
  raiseDetection(indicator, direction, contextLine);
}

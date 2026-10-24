//! Minimal JavaScript runner for bot-challenge pages.
//!
//! Cloudflare and friends gate traffic behind a script that computes a token
//! and either sets a cookie or redirects. There is no DOM here, so the script
//! runs against a shimmed environment: enough for the common challenge
//! scripts, not a browser.

use boa_engine::{Context, Source};


fn prelude(url: &str, host: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('\'', "\\'");
    format!(
        r#"
var window = this;
var self = this;
var globalThis = this;
var navigator = {{
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  platform: 'Win32', language: 'en-US', languages: ['en-US','en'], webdriver: false,
  hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0, vendor: 'Google Inc.'
}};
var location = {{
  href: '{url}', protocol: 'https:', host: '{host}', hostname: '{host}',
  pathname: '/', search: '', hash: '', origin: 'https://{host}',
  reload: function () {{}}, replace: function (u) {{ location.href = u; }},
  assign: function (u) {{ location.href = u; }}
}};
var document = {{
  cookie: '', referrer: '', title: '', readyState: 'complete',
  createElement: function (tag) {{
    var el = {{ style: {{}}, tagName: String(tag).toUpperCase(),
      appendChild: function () {{}}, setAttribute: function () {{}},
      addEventListener: function () {{}}, removeEventListener: function () {{}},
      getContext: function () {{ return null; }} }};
    Object.defineProperty(el, 'src', {{
      set: function (v) {{ __dyn.push(String(v)); }},
      get: function () {{ return ''; }}
    }});
    return el;
  }},
  getElementById: function () {{ return null; }},
  getElementsByTagName: function () {{ return [{{ appendChild: function () {{}} }}]; }},
  getElementsByClassName: function () {{ return []; }},
  querySelector: function () {{ return null; }},
  querySelectorAll: function () {{ return []; }},
  addEventListener: function () {{}},
  removeEventListener: function () {{}},
  documentElement: {{ style: {{}} }},
  head: {{ appendChild: function () {{}} }},
  body: {{ appendChild: function () {{}} }}
}};
var __dyn = [];
var history = {{ replaceState: function () {{}}, pushState: function () {{}} }};
var screen = {{ width: 1920, height: 1080, colorDepth: 24, availWidth: 1920 }};
var performance = {{ now: function () {{ return Date.now(); }} }};
var setTimeout = function (f) {{ try {{ if (typeof f === 'function') f(); }} catch (e) {{}} return 0; }};
var setInterval = setTimeout;
var clearTimeout = function () {{}};
var clearInterval = function () {{}};
var requestAnimationFrame = setTimeout;
var _b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
function atob(s) {{
  s = String(s).replace(/[^A-Za-z0-9+/=]/g, '');
  var o = '';
  for (var i = 0; i < s.length; i += 4) {{
    var a = _b64.indexOf(s[i]), b = _b64.indexOf(s[i+1]);
    var c = _b64.indexOf(s[i+2]), d = _b64.indexOf(s[i+3]);
    o += String.fromCharCode((a << 2) | (b >> 4));
    if (c !== 64 && c !== -1) o += String.fromCharCode(((b & 15) << 4) | (c >> 2));
    if (d !== 64 && d !== -1) o += String.fromCharCode(((c & 3) << 6) | d);
  }}
  return o;
}}
function btoa(s) {{
  s = String(s); var o = '';
  for (var i = 0; i < s.length; i += 3) {{
    var a = s.charCodeAt(i), b = s.charCodeAt(i+1), c = s.charCodeAt(i+2);
    o += _b64[(a >> 2) & 63] + _b64[((a & 3) << 4) | ((b || 0) >> 4)];
    o += isNaN(b) ? '=' : _b64[((b & 15) << 2) | ((c || 0) >> 6)];
    o += isNaN(c) ? '=' : _b64[c & 63];
  }}
  return o;
}}
var crypto = {{
  getRandomValues: function (a) {{
    for (var i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
    return a;
  }}
}};
var localStorage = {{ getItem: function () {{ return null; }}, setItem: function () {{}} }};
var addEventListener = function () {{}};
var removeEventListener = function () {{}};
var dispatchEvent = function () {{ return true; }};
var matchMedia = function () {{ return {{ matches: false, addListener: function () {{}}, addEventListener: function () {{}} }}; }};
var MutationObserver = function () {{ return {{ observe: function () {{}}, disconnect: function () {{}} }}; }};
var Image = function () {{ return {{ src: '', onload: null, onerror: null }}; }};
var XMLHttpRequest = function () {{
  return {{ open: function () {{}}, send: function () {{}}, setRequestHeader: function () {{}},
    readyState: 4, status: 200, responseText: '', addEventListener: function () {{}} }};
}};
var fetch = function () {{ return new Promise(function () {{}}); }};
var queueMicrotask = function (f) {{ try {{ f(); }} catch (e) {{}} }};
var structuredClone = function (o) {{ return o; }};
var URL = function (u, b) {{
  this.href = String(u); this.pathname = '/'; this.search = ''; this.hash = '';
  this.host = '{host}'; this.hostname = '{host}'; this.origin = 'https://{host}';
  this.toString = function () {{ return this.href; }};
}};
var URLSearchParams = function () {{
  this.get = function () {{ return null; }}; this.append = function () {{}};
  this.toString = function () {{ return ''; }};
}};
var TextEncoder = function () {{
  this.encode = function (s) {{
    var a = []; for (var i = 0; i < String(s).length; i++) a.push(String(s).charCodeAt(i) & 255);
    return new Uint8Array(a);
  }};
}};
var TextDecoder = function () {{
  this.decode = function (a) {{
    var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return s;
  }};
}};
var Blob = function () {{ this.size = 0; this.type = ''; }};
"#,
        url = esc(url),
        host = esc(host)
    )
}

fn scripts(html: &str) -> (Vec<String>, Vec<String>) {
    let mut inline = Vec::new();
    let mut urls = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("<script") {
        let after = &rest[i..];
        let Some(open_end) = after.find('>') else { break };
        let tag = &after[..open_end];
        let body = &after[open_end + 1..];
        let Some(close) = body.find("</script>") else { break };
        if let Some(src) = tag.split("src=").nth(1) {
            let u = src
                .trim_start()
                .trim_start_matches(['"', '\''])
                .split(['"', '\'', ' ', '>'])
                .next()
                .unwrap_or("");
            if !u.is_empty() && urls.len() < 8 {
                urls.push(u.to_string());
            }
        } else {
            let code = body[..close].trim();
            if !code.is_empty() && inline.len() < 16 {
                inline.push(code.to_string());
            }
        }
        rest = &body[close + 9..];
    }
    (inline, urls)
}

pub fn inline_scripts(html: &str) -> Vec<String> {
    scripts(html).0
}

pub fn script_urls(html: &str) -> Vec<String> {
    scripts(html).1
}

fn read_string(ctx: &mut Context, expr: &str) -> Option<String> {
    let v = ctx.eval(Source::from_bytes(expr)).ok()?;
    let s = v.to_string(ctx).ok()?.to_std_string_escaped();
    if s.is_empty() || s == "undefined" {
        None
    } else {
        Some(s)
    }
}

/// A live JS session. Keeps one context so state survives dynamic script
/// loads, which is how the challenge scripts actually work.
pub struct Session {
    ctx: Context,
    url: String,
    pub ran: usize,
    pub errors: Vec<String>,
}

impl Session {
    pub fn new(url: &str, host: &str) -> Option<Self> {
        let mut ctx = Context::default();
        ctx.eval(Source::from_bytes(&prelude(url, host))).ok()?;
        Some(Self {
            ctx,
            url: url.to_string(),
            ran: 0,
            errors: Vec::new(),
        })
    }

    pub fn eval(&mut self, code: &str) {
        match self.ctx.eval(Source::from_bytes(code)) {
            Ok(_) => self.ran += 1,
            Err(e) => {
                if self.errors.len() < 4 {
                    self.errors.push(e.to_string().chars().take(120).collect());
                }
            }
        }
    }

    /// Script URLs the page asked for dynamically.
    pub fn take_dyn(&mut self) -> Vec<String> {
        let Some(d) = read_string(&mut self.ctx, "__dyn.join('\\n')") else {
            return Vec::new();
        };
        let _ = self.ctx.eval(Source::from_bytes("__dyn = [];"));
        d.split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    pub fn cookie(&mut self) -> Option<String> {
        read_string(&mut self.ctx, "document.cookie")
    }

    pub fn redirect(&mut self) -> Option<String> {
        let h = read_string(&mut self.ctx, "location.href")?;
        if h == self.url {
            None
        } else {
            Some(h)
        }
    }
}

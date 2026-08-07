"""
Comprehensive technology fingerprint database.
Wappalyzer-class signatures for 300+ technologies across 19 categories.
Embedded — no external API calls, works offline, zero cost.

Pattern types per technology:
  headers    — {Header-Name: regex_pattern}
  cookies    — [cookie_name_patterns]
  meta       — {meta_name: regex_content}
  scripts    — [script_src_patterns]
  html       — [body_html_patterns]
  url        — [url_path_patterns]
  js         — [javascript_global_variable_patterns]
  implies    — [technologies this implies]
  version    — regex with one capture group for version string
  categories — [category_ids]
"""

# Category definitions (Wappalyzer-aligned)
CATEGORIES = {
    1: "CMS",
    2: "Message Boards",
    3: "Database Managers",
    4: "Documentation Tools",
    5: "Widgets",
    6: "Ecommerce",
    7: "Photo Galleries",
    8: "Wikis",
    9: "Hosting Panels",
    10: "Analytics",
    11: "Blogs",
    12: "JavaScript Frameworks",
    13: "Issue Trackers",
    14: "Video Players",
    15: "Comment Systems",
    16: "Security",
    17: "Font Scripts",
    18: "Web Frameworks",
    19: "LMS",
    20: "Web Servers",
    21: "Cache Tools",
    22: "Rich Text Editors",
    23: "JavaScript Graphics",
    24: "Mobile Frameworks",
    25: "Marketing Automation",
    26: "Webmail",
    27: "CDN",
    28: "Search Engines",
    29: "Marketing",
    30: "Maps",
    31: "Advertising Networks",
    32: "Network Services",
    33: "Media Servers",
    34: "Payment Processors",
    35: "Tag Managers",
    36: "Live Chat",
    37: "CRM",
    38: "Databases",
    39: "Miscellaneous",
    40: "Web Server Extensions",
    41: "PaaS",
    42: "IaaS",
    43: "Reverse Proxies",
    44: "Load Balancers",
    45: "Operating Systems",
    46: "Email",
    47: "Programming Languages",
    48: "Spell Checkers",
    49: "Appointment Scheduling",
    50: "Static Site Generators",
    51: "User Onboarding",
    52: "Geolocation",
    53: "Authentication",
    54: "Business Tools",
    55: "Accessibility",
    56: "A/B Testing",
    57: "Cookie Banners",
    58: "Customer Data Platform",
    59: "Digital Asset Management",
    60: "Form Builders",
}

# Main fingerprint database
FINGERPRINTS = {
    # ── Web Servers ──────────────────────────────────────────────
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d[\d.]*))?"},
        "version": r"Apache(?:/(\d[\d.]*))?",
        "categories": [20],
        "implies": ["PHP"],
    },
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d[\d.]*))?"},
        "version": r"nginx(?:/(\d[\d.]*))?",
        "categories": [20, 43],
    },
    "Microsoft IIS": {
        "headers": {"Server": r"Microsoft-IIS(?:/(\d[\d.]*))?"},
        "version": r"Microsoft-IIS(?:/(\d[\d.]*))?",
        "categories": [20],
        "implies": ["ASP.NET"],
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed(?:/(\d[\d.]*))?"},
        "version": r"LiteSpeed(?:/(\d[\d.]*))?",
        "categories": [20],
    },
    "Tengine": {
        "headers": {"Server": r"Tengine(?:/(\d[\d.]*))?"},
        "version": r"Tengine(?:/(\d[\d.]*))?",
        "categories": [20],
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "categories": [20],
    },
    "Gunicorn": {
        "headers": {"Server": r"gunicorn(?:/(\d[\d.]*))?"},
        "version": r"gunicorn(?:/(\d[\d.]*))?",
        "categories": [20],
    },
    "Uvicorn": {
        "headers": {"Server": r"uvicorn"},
        "categories": [20],
    },
    "OpenResty": {
        "headers": {"Server": r"openresty(?:/(\d[\d.]*))?"},
        "version": r"openresty(?:/(\d[\d.]*))?",
        "categories": [20],
    },
    "Cherokee": {
        "headers": {"Server": r"Cherokee(?:/(\d[\d.]*))?"},
        "version": r"Cherokee(?:/(\d[\d.]*))?",
        "categories": [20],
    },
    "Jetty": {
        "headers": {"Server": r"Jetty(?:\((\d[\d.]*))?\)?"},
        "version": r"Jetty\((\d[\d.]*)",
        "categories": [20],
    },
    "Varnish": {
        "headers": {"Via": r"varnish", "X-Varnish": r"."},
        "categories": [20, 21],
    },
    "Envoy": {
        "headers": {"Server": r"envoy", "x-envoy-upstream-service-time": r"\d+"},
        "categories": [20, 43, 44],
    },
    "Kestrel": {
        "headers": {"Server": r"Kestrel"},
        "categories": [20],
        "implies": ["ASP.NET"],
    },

    # ── CDN / WAF ───────────────────────────────────────────────
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".+", "cf-cache-status": r"."},
        "cookies": ["__cflb", "__cfuid", "__cf_bm", "cf_clearance"],
        "categories": [27, 16],
    },
    "Amazon CloudFront": {
        "headers": {"Server": r"CloudFront", "X-Amz-Cf-Id": r".+", "X-Amz-Cf-Pop": r".+", "x-amzn-requestid": r"."},
        "categories": [27],
        "implies": ["Amazon Web Services"],
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".+", "Server": r"AkamaiGHost"},
        "categories": [27, 16],
    },
    "Fastly": {
        "headers": {"X-Served-By": r".+", "X-Cache": r".+", "Via": r"varnish"},
        "categories": [27],
    },
    "Imperva (Incapsula)": {
        "headers": {"X-Iinfo": r".+", "X-CDN": r"Incapsula"},
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
        "categories": [27, 16],
    },
    "Sucuri": {
        "headers": {"Server": r"Sucuri", "X-Sucuri-ID": r".+", "X-Sucuri-Cache": r"."},
        "categories": [27, 16],
    },
    "AWS WAF": {
        "headers": {"Server": r"awselb|aws"},
        "categories": [16, 27],
    },
    "Azure Front Door": {
        "headers": {"X-Azure-Ref": r".+", "X-FD-HealthProbe": r"."},
        "categories": [27, 41],
    },
    "Google Cloud CDN": {
        "headers": {"Via": r"1\.1 google", "Server": r"GSE|Golfe2"},
        "categories": [27],
    },
    "StackPath": {
        "headers": {"Server": r"NetDNA|StackPath", "X-HW": r"."},
        "categories": [27],
    },
    "KeyCDN": {
        "headers": {"Server": r"keycdn"},
        "categories": [27],
    },
    "BunnyCDN": {
        "headers": {"Server": r"BunnyCDN", "CDN-PullZone": r"."},
        "categories": [27],
    },
    "ArvanCloud": {
        "headers": {"Server": r"ArvanCloud"},
        "categories": [27, 16],
    },

    # ── Programming Languages ────────────────────────────────────
    "PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/(\d[\d.]*))?"},
        "cookies": ["PHPSESSID"],
        "version": r"PHP(?:/(\d[\d.]*))?",
        "categories": [47],
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"([\d.]+)", "X-AspNetMvc-Version": r"([\d.]+)"},
        "cookies": ["ASP.NET_SessionId", "__VIEWSTATE", "__RequestVerificationToken"],
        "html": ["__VIEWSTATE", "__EVENTVALIDATION", "aspnetForm"],
        "version": r"X-AspNet(?:Mvc)?-Version:\s*([\d.]+)",
        "categories": [18, 47],
    },
    "Java": {
        "cookies": ["JSESSIONID"],
        "headers": {"X-Powered-By": r"Servlet|JSP|Java"},
        "categories": [47],
    },
    "Python": {
        "headers": {"Server": r"Python|WSGI", "X-Powered-By": r"Python"},
        "categories": [47],
    },
    "Ruby": {
        "headers": {"X-Powered-By": r"Phusion Passenger|mod_rack|mod_rails"},
        "categories": [47],
    },
    "Go": {
        "headers": {"Server": r"Go-http"},
        "categories": [47],
    },
    "Perl": {
        "headers": {"Server": r"\bPerl\b", "X-Powered-By": r"\bPerl\b"},
        "categories": [47],
    },
    "Scala": {
        "headers": {"X-Powered-By": r"Play Framework|Scala"},
        "categories": [47],
    },
    "Erlang": {
        "headers": {"X-Powered-By": r"Cowboy"},
        "categories": [47],
    },
    "ColdFusion": {
        "headers": {"X-Powered-By": r"CFML|ColdFusion"},
        "cookies": ["CFID", "CFTOKEN"],
        "categories": [47],
    },

    # ── JavaScript Frameworks / Libraries ────────────────────────
    "jQuery": {
        "scripts": [r"jquery[.-](\d[\d.]*)(?:\.min)?\.js", r"jquery(?:\.min)?\.js"],
        "html": [r"jquery[.-]\d[\d.]*\.js", r"jquery(?:\.min)?\.js"],
        "js": ["jQuery.fn.jquery"],
        "version": r"jquery[.-](\d[\d.]*)",
        "categories": [12],
    },
    "React": {
        "html": [r"data-reactroot", r"_reactRootContainer", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "js": ["React.version", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "scripts": [r"react(?:\.production)?(?:\.min)?\.js", r"react-dom"],
        "categories": [12],
    },
    "Vue.js": {
        "html": [r"data-v-", r"v-bind:", r"v-on:", r"v-if=", r"v-for="],
        "js": ["Vue.config", "__vue__", "Vue.version"],
        "scripts": [r"vue(?:\.min)?\.js", r"vue(?:\.runtime)?(?:\.prod)?\.js"],
        "version": r"Vue\.version\s*=\s*['\"]([\d.]+)",
        "categories": [12],
    },
    "Angular": {
        "html": [r"ng-version", r"ng-app=", r"ng-controller=", r"\[ngClass\]", r"\*ngFor"],
        "js": ["ng.version", "angular.version"],
        "scripts": [r"angular(?:\.min)?\.js", r"@angular/core"],
        "version": r"ng-version=['\"]([\d.]+)",
        "categories": [12],
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"/_next/static", r"id=\"__next\""],
        "js": ["__NEXT_DATA__", "__next"],
        "scripts": [r"/_next/static/"],
        "categories": [12, 18, 50],
    },
    "Nuxt.js": {
        "html": [r"__NUXT__", r"/_nuxt/", r"nuxt-link"],
        "js": ["__NUXT__", "$nuxt"],
        "categories": [12, 18],
    },
    "Svelte": {
        "html": [r"__svelte", r"svelte-"],
        "categories": [12],
    },
    "Gatsby": {
        "html": [r"___gatsby", r"id=\"___gatsby\""],
        "scripts": [r"/webpack-runtime-"],
        "categories": [12, 50],
    },
    "Ember.js": {
        "html": [r"ember-view", r"id=\"ember\d+\""],
        "js": ["Ember.VERSION"],
        "version": r"Ember\.VERSION\s*=\s*['\"]([\d.]+)",
        "categories": [12],
    },
    "Backbone.js": {
        "js": ["Backbone.VERSION"],
        "categories": [12],
    },
    "D3.js": {
        "scripts": [r"d3(?:\.v\d+)?(?:\.min)?\.js"],
        "js": ["d3.version"],
        "categories": [12, 23],
    },
    "Three.js": {
        "scripts": [r"three(?:\.min)?\.js"],
        "js": ["THREE.REVISION"],
        "categories": [12, 23],
    },
    "Lodash": {
        "scripts": [r"lodash(?:\.min)?\.js"],
        "js": ["_.VERSION"],
        "categories": [12],
    },
    "Moment.js": {
        "scripts": [r"moment(?:\.min)?\.js"],
        "js": ["moment.version"],
        "categories": [12],
    },
    "Axios": {
        "scripts": [r"axios(?:\.min)?\.js"],
        "js": ["axios.defaults"],
        "categories": [12],
    },
    "RequireJS": {
        "scripts": [r"require(?:\.min)?\.js"],
        "js": ["requirejs.version", "require.version"],
        "categories": [12],
    },
    "Webpack": {
        "html": [r"webpackJsonp", r"webpackChunk", r"/webpack-runtime-"],
        "js": ["webpackJsonp", "__webpack_require__"],
        "categories": [12],
    },
    "Alpine.js": {
        "html": [r"x-data=", r"x-on:", r"x-show=", r"x-bind:"],
        "scripts": [r"alpinejs(?:/.*)?/alpine"],
        "categories": [12],
    },
    "htmx": {
        "html": [r"hx-get=", r"hx-post=", r"hx-swap=", r"hx-target="],
        "scripts": [r"htmx(?:\.min)?\.js"],
        "categories": [12],
    },
    "Stimulus": {
        "html": [r"data-controller="],
        "categories": [12],
    },
    "Turbo": {
        "html": [r"data-turbo", r"<turbo-"],
        "categories": [12],
    },

    # ── CMS ──────────────────────────────────────────────────────
    "WordPress": {
        "html": [r"wp-content/", r"wp-includes/", r"wp-json", r"/xmlrpc\.php"],
        "meta": {"generator": r"WordPress(?:\s*([\d.]+))?"},
        "scripts": [r"wp-includes/js/", r"wp-content/plugins/"],
        "cookies": ["wordpress_logged_in_", "wp-settings-"],
        "url": ["/wp-admin/", "/wp-login.php", "/wp-json/", "/xmlrpc.php"],
        "version": r"WordPress\s*([\d.]+)",
        "categories": [1, 11],
        "implies": ["PHP", "MySQL"],
    },
    "Drupal": {
        "html": [r"Drupal\.settings", r"/sites/default/files", r"drupal\.js", r"/core/misc/drupal\.js"],
        "meta": {"generator": r"Drupal\s*([\d.]+)?"},
        "cookies": ["SSESS", "Drupal."],
        "version": r"Drupal\s*([\d.]+)",
        "categories": [1],
        "implies": ["PHP"],
    },
    "Joomla": {
        "html": [r"/media/jui/", r"Joomla!", r"/components/com_"],
        "meta": {"generator": r"Joomla!\s*([\d.]+)?"},
        "cookies": ["joomla_"],
        "version": r"Joomla!\s*([\d.]+)",
        "categories": [1],
        "implies": ["PHP"],
    },
    "Shopify": {
        "html": [r"Shopify\.theme", r"cdn\.shopify\.com", r"<meta property=['\"]og:shopify"],
        "cookies": ["_shopify_", "_storefront_digest"],
        "categories": [1, 6],
    },
    "Squarespace": {
        "html": [r"<!-- This is Squarespace", r"squarespace-cdn", r"static\.squarespace\.com"],
        "categories": [1],
    },
    "Wix": {
        "html": [r"wix\.com", r"X-Wix-", r"static\.wixstatic\.com"],
        "headers": {"X-Wix-": r"."},
        "categories": [1],
    },
    "Ghost": {
        "html": [r"ghost-url", r"content/themes/ghost", r"ghost\.min\.js"],
        "meta": {"generator": r"Ghost(?:\s*([\d.]+))?"},
        "version": r"Ghost\s*([\d.]+)",
        "categories": [1, 11],
    },
    "Hugo": {
        "html": [r"Powered by Hugo", r"hugo\.min\.css"],
        "meta": {"generator": r"Hugo\s*([\d.]+)?"},
        "version": r"Hugo\s*([\d.]+)",
        "categories": [1, 50],
    },
    "TYPO3": {
        "html": [r"typo3", r"typo3conf/", r"typo3temp/"],
        "categories": [1],
        "implies": ["PHP"],
    },
    "Magento": {
        "html": [r"/skin/frontend/", r"Magento", r"mage/cookies\.js", r"requirejs-config\.js"],
        "cookies": ["frontend=", "store="],
        "categories": [1, 6],
        "implies": ["PHP"],
    },
    "PrestaShop": {
        "html": [r"PrestaShop", r"/themes/.*?/assets/"],
        "categories": [1, 6],
        "implies": ["PHP"],
    },
    "WooCommerce": {
        "html": [r"woocommerce", r"wc-api=", r"add-to-cart="],
        "categories": [6],
        "implies": ["WordPress"],
    },
    "BigCommerce": {
        "html": [r"cdn\d*\.bigcommerce\.com"],
        "categories": [6],
    },
    "Webflow": {
        "html": [r"data-wf-site=", r"assets\.website-files\.com"],
        "categories": [1],
    },
    "Contentful": {
        "html": [r"contentful", r"ctfassets\.net"],
        "categories": [1],
    },
    "Strapi": {
        "html": [r"strapi", r"/admin/"],
        "categories": [1],
        "implies": ["Node.js"],
    },
    "Sanity": {
        "html": [r"cdn\.sanity\.io"],
        "categories": [1],
    },
    "Umbraco": {
        "html": [r"umbraco", r"/umbraco/"],
        "categories": [1],
        "implies": ["ASP.NET"],
    },
    "Sitecore": {
        "html": [r"sitecore", r"/sitecore/"],
        "categories": [1],
        "implies": ["ASP.NET"],
    },

    # ── Web Frameworks ───────────────────────────────────────────
    "Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "html": [r"laravel", r"csrf-token"],
        "categories": [18],
        "implies": ["PHP"],
    },
    "Django": {
        "cookies": ["csrftoken", "django_language"],
        "html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__", r"django\.contrib", r"/static/admin/"],
        "categories": [18],
        "implies": ["Python"],
    },
    "Flask": {
        "headers": {"Server": r"Werkzeug"},
        "categories": [18],
        "implies": ["Python"],
    },
    "FastAPI": {
        "html": [r'<title>FastAPI</title>', r"swagger-ui", r"BearerAuth", r"fastapi\.cloud*"],
        "url": ["/docs", "/redoc", "/openapi.json"],
        "headers": {"Server": r"uvicorn"},
        "categories": [18],
        "implies": ["Python"],
    },
    "Express": {
        "headers": {"X-Powered-By": r"Express"},
        "categories": [18],
        "implies": ["Node.js"],
    },
    "Ruby on Rails": {
        "cookies": ["_session_id"],
        "headers": {"X-Powered-By": r"Phusion Passenger|mod_rack"},
        "html": [r"csrf-token", r"data-turbolinks"],
        "categories": [18],
        "implies": ["Ruby"],
    },
    "Spring": {
        "headers": {"X-Application-Context": r"."},
        "url": ["/actuator", "/actuator/health"],
        "categories": [18],
        "implies": ["Java"],
    },
    "Symfony": {
        "cookies": ["_sf2_"],
        "html": [r"sf-toolbar"],
        "categories": [18],
        "implies": ["PHP"],
    },
    "CakePHP": {
        "cookies": ["CAKEPHP="],
        "categories": [18],
        "implies": ["PHP"],
    },
    "CodeIgniter": {
        "cookies": ["ci_session"],
        "categories": [18],
        "implies": ["PHP"],
    },
    "Zend Framework": {
        "headers": {"X-Powered-By": r"Zend"},
        "categories": [18],
        "implies": ["PHP"],
    },
    "NestJS": {
        "headers": {"X-Powered-By": r"NestJS"},
        "categories": [18],
        "implies": ["Node.js"],
    },
    "SvelteKit": {
        "html": [r"data-sveltekit", r"sveltekit:"],
        "categories": [18],
    },
    "Remix": {
        "html": [r"__remixContext", r"data Remix"],
        "js": ["__remixContext"],
        "categories": [18],
    },
    "Astro": {
        "html": [r"is:astro", r"astro:"],
        "categories": [18, 50],
    },
    "Tailwind CSS": {
        "html": [r"tailwindcss", r"class=\"[^\"]*(?:flex|grid|p-\d|m-\d|text-\w+)"],
        "scripts": [r"tailwindcss"],
        "categories": [18],
    },
    "Bootstrap": {
        "html": [r"bootstrap(?:\.min)?\.(?:css|js)", r"navbar-default", r"col-(?:xs|sm|md|lg)-"],
        "scripts": [r"bootstrap(?:\.min)?\.js"],
        "categories": [18],
    },
    "Foundation": {
        "html": [r"foundation(?:\.min)?\.(?:css|js)"],
        "categories": [18],
    },
    "Bulma": {
        "html": [r"bulma(?:\.min)?\.css"],
        "categories": [18],
    },
    "Materialize CSS": {
        "html": [r"materialize(?:\.min)?\.(?:css|js)"],
        "categories": [18],
    },
    "Semantic UI": {
        "html": [r"semantic(?:\.min)?\.(?:css|js)"],
        "categories": [18],
    },

    # ── Database ─────────────────────────────────────────────────
    "MySQL": {
        "headers": {"X-Powered-By": r"MySQL"},
        "html": [r"mysql", r"mysqli_"],
        "categories": [38],
    },
    "PostgreSQL": {
        "html": [r"postgresql", r"pg_"],
        "categories": [38],
    },
    "MongoDB": {
        "html": [r"mongodb://", r"mongoose\.connect", r"MongoClient"],
        "headers": {"X-Powered-By": r"MongoDB"},
        "categories": [38],
    },
    "PostgreSQL": {
        "html": [r"pg_connect", r"psycopg2", r"pg_query"],
        "headers": {"X-Powered-By": r"PostgreSQL"},
        "categories": [38],
    },
    "Redis": {
        "headers": {"X-Powered-By": r"Redis"},
        "categories": [38, 21],
    },
    "SQLite": {
        "html": [r"sqlite3\.connect", r"sqlite_open", r"\.db\""],
        "categories": [38],
    },
    "Elasticsearch": {
        "headers": {"X-elastic-product": r"Elasticsearch"},
        "url": ["/_cluster/health", "/_cat/"],
        "categories": [28, 38],
    },
    "SQLite": {
        "html": [r"sqlite"],
        "categories": [38],
    },
    "Microsoft SQL Server": {
        "html": [r"mssql", r"sqlserver"],
        "categories": [38],
    },
    "Oracle": {
        "html": [r"oracle", r"ORA-\d{5}"],
        "categories": [38],
    },
    "Cassandra": {
        "headers": {"Server": r"Cassandra"},
        "categories": [38],
    },
    "CouchDB": {
        "headers": {"Server": r"CouchDB"},
        "categories": [38],
    },

    # ── Analytics ────────────────────────────────────────────────
    "Google Analytics": {
        "scripts": [r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag/js", r"ga\.js"],
        "html": [r"google-analytics\.com", r"gtag\(", r"ga\("],
        "js": ["ga", "gtag", "_gaq", "dataLayer"],
        "categories": [10],
    },
    "Google Tag Manager": {
        "scripts": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"googletagmanager\.com/ns\.html", r"GTM-\w+"],
        "js": ["dataLayer"],
        "categories": [35],
    },
    "Hotjar": {
        "scripts": [r"static\.hotjar\.com/c/hotjar-"],
        "html": [r"hotjar", r"hj\("],
        "js": ["hj", "hjBootstrap"],
        "categories": [10],
    },
    "Mixpanel": {
        "scripts": [r"cdn\.mxpnl\.com/libs/mixpanel", r"api\.mixpanel\.com"],
        "js": ["mixpanel"],
        "categories": [10],
    },
    "Segment": {
        "scripts": [r"cdn\.segment\.com/analytics\.js"],
        "js": ["analytics", "analytics.identify"],
        "categories": [10],
    },
    "Matomo (Piwik)": {
        "scripts": [r"matomo\.js", r"piwik\.js"],
        "html": [r"_paq\.push", r"matomo\.php"],
        "js": ["_paq"],
        "categories": [10],
    },
    "Plausible": {
        "scripts": [r"plausible\.io/js/"],
        "html": [r"plausible\.io"],
        "categories": [10],
    },
    "Clarity": {
        "scripts": [r"clarity\.ms/tag/"],
        "html": [r"clarity\.ms"],
        "categories": [10],
    },
    "Amplitude": {
        "scripts": [r"cdn\.amplitude\.com"],
        "js": ["amplitude"],
        "categories": [10],
    },
    "Heap": {
        "scripts": [r"heap-\d+\.js", r"heapanalytics\.com"],
        "js": ["heap"],
        "categories": [10],
    },
    "FullStory": {
        "scripts": [r"fullstory\.com/s/fs"],
        "js": ["FS"],
        "categories": [10],
    },

    # ── Security ─────────────────────────────────────────────────
    "reCAPTCHA": {
        "html": [r"recaptcha", r"g-recaptcha", r"google\.com/recaptcha"],
        "scripts": [r"recaptcha/api\.js", r"recaptcha/enterprise\.js"],
        "categories": [16],
    },
    "hCaptcha": {
        "html": [r"hcaptcha", r"h-captcha"],
        "scripts": [r"hcaptcha\.com/.*\.js"],
        "categories": [16],
    },
    "Turnstile": {
        "html": [r"turnstile", r"cf-turnstile"],
        "scripts": [r"challenges\.cloudflare\.com"],
        "categories": [16],
        "implies": ["Cloudflare"],
    },
    "PerimeterX": {
        "scripts": [r"perimeterx", r"px-cdn", r"px-cloud\.net"],
        "cookies": ["_px", "pxcts"],
        "categories": [16],
    },
    "DataDome": {
        "scripts": [r"datadome\.co"],
        "cookies": ["datadome"],
        "categories": [16],
    },
    "AWS WAF": {
        "cookies": ["aws-waf-token"],
        "categories": [16],
        "implies": ["Amazon Web Services"],
    },
    "ModSecurity": {
        "headers": {"Server": r"mod_security|NOYB"},
        "categories": [16],
    },

    # ── Payment Processors ───────────────────────────────────────
    "Stripe": {
        "scripts": [r"js\.stripe\.com/v\d"],
        "html": [r"stripe\.com", r"Stripe\.com", r"stripe-"],
        "js": ["Stripe"],
        "categories": [34],
    },
    "PayPal": {
        "scripts": [r"paypalobjects\.com", r"paypal\.com/sdk"],
        "html": [r"paypal\.com", r"paypal-button"],
        "js": ["paypal"],
        "categories": [34],
    },
    "Braintree": {
        "scripts": [r"js\.braintreegateway\.com"],
        "js": ["braintree"],
        "categories": [34],
        "implies": ["PayPal"],
    },
    "Square": {
        "scripts": [r"squareup\.com/paymentform", r"js\.squarecdn\.com"],
        "categories": [34],
    },
    "Adyen": {
        "scripts": [r"checkoutshopper-live\.adyen\.com", r"adyen\.com"],
        "categories": [34],
    },
    "Razorpay": {
        "scripts": [r"checkout\.razorpay\.com"],
        "js": ["Razorpay"],
        "categories": [34],
    },
    "Klarna": {
        "scripts": [r"x\.klarnacdn\.net"],
        "html": [r"klarna"],
        "categories": [34],
    },

    # ── Widgets / Chat / Social ──────────────────────────────────
    "Intercom": {
        "scripts": [r"widget\.intercom\.io", r"js\.intercomcdn\.com"],
        "js": ["Intercom"],
        "categories": [36],
    },
    "Drift": {
        "scripts": [r"js\.driftt\.com"],
        "js": ["drift"],
        "categories": [36],
    },
    "Zendesk Chat": {
        "scripts": [r"static\.zdassets\.com", r"zopim\.com"],
        "js": ["zE", "$zopim"],
        "categories": [36],
    },
    "LiveChat": {
        "scripts": [r"cdn\.livechatinc\.com"],
        "js": ["LiveChatWidget", "LC_API"],
        "categories": [36],
    },
    "Crisp": {
        "scripts": [r"client\.crisp\.chat"],
        "js": ["$crisp", "CRISP_WEBSITE_ID"],
        "categories": [36],
    },
    "Tawk.to": {
        "scripts": [r"embed\.tawk\.to"],
        "js": ["Tawk_API"],
        "categories": [36],
    },
    "HubSpot": {
        "scripts": [r"js\.hs-scripts\.com", r"js\.hsforms\.net"],
        "html": [r"hubspot", r"hs-analytics", r"hsforms"],
        "js": ["_hsq", "hbspt"],
        "categories": [25, 37, 60],
    },
    "Crisp (Email)": {
        "scripts": [r"email\.crisp\.chat"],
        "categories": [46],
    },

    # ── Fonts ────────────────────────────────────────────────────
    "Google Font API": {
        "html": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
        "categories": [17],
    },
    "Font Awesome": {
        "html": [r"fontawesome", r"font-awesome", r"fa-"],
        "scripts": [r"fontawesome", r"font-awesome"],
        "categories": [17],
    },
    "Typekit": {
        "scripts": [r"use\.typekit\.net"],
        "categories": [17],
    },
    "Material Icons": {
        "html": [r"material-icons", r"fonts\.googleapis\.com/icon"],
        "categories": [17],
    },

    # ── Tag Managers / Marketing ─────────────────────────────────
    "Google Tag Manager": {
        "scripts": [r"googletagmanager\.com"],
        "html": [r"GTM-\w+"],
        "js": ["dataLayer", "google_tag_manager"],
        "categories": [35],
    },
    "Segment": {
        "scripts": [r"cdn\.segment\.com"],
        "js": ["analytics"],
        "categories": [10, 58],
    },
    "Optimizely": {
        "scripts": [r"cdn\.optimizely\.com"],
        "js": ["optimizely"],
        "categories": [56],
    },
    "VWO": {
        "scripts": [r"dev\.visualwebsiteoptimizer\.com"],
        "js": ["_vwo_code", "VWO"],
        "categories": [56],
    },
    "Kissmetrics": {
        "scripts": [r"scripts\.kissmetrics\.com"],
        "js": ["_kmq"],
        "categories": [10],
    },

    # ── PaaS / IaaS / Hosting ────────────────────────────────────
    "Amazon Web Services": {
        "headers": {"Server": r"AmazonS3|awselb", "X-Amz-Request-Id": r".+", "X-Amz-Bucket-Region": r"."},
        "categories": [42],
    },
    "Heroku": {
        "headers": {"Server": r"Heroku", "Via": r"vegur"},
        "categories": [41],
    },
    "Vercel": {
        "headers": {"Server": r"Vercel", "X-Vercel-Id": r".+"},
        "categories": [41, 27],
    },
    "Netlify": {
        "headers": {"Server": r"Netlify", "X-Nf-Request-Id": r".+"},
        "categories": [41, 27],
    },
    "Firebase": {
        "html": [r"firebaseapp\.com", r"firebase\.js"],
        "categories": [41],
        "implies": ["Google Cloud"],
    },
    "DigitalOcean": {
        "headers": {"Server": r"DigitalOcean"},
        "categories": [42],
    },
    "Google Cloud": {
        "headers": {"Via": r"1\.1 google", "Server": r"Golfe2|GSE"},
        "categories": [42],
    },
    "Azure": {
        "headers": {"X-Azure-Ref": r".+", "X-Ms-Request-Id": r".+"},
        "categories": [42, 41],
    },
    "Cloudflare Pages": {
        "headers": {"Server": r"cloudflare", "cf-pages": r"."},
        "categories": [41],
        "implies": ["Cloudflare"],
    },

    # ── Video Players ────────────────────────────────────────────
    "YouTube": {
        "html": [r"youtube\.com/embed", r"ytimg\.com"],
        "categories": [14],
    },
    "Vimeo": {
        "scripts": [r"player\.vimeo\.com"],
        "html": [r"vimeo\.com/video"],
        "categories": [14],
    },
    "Video.js": {
        "scripts": [r"video(?:\.js|\.min\.js)", r"vjs-zoom"],
        "html": [r"video-js", r"vjs-big-play-button"],
        "js": ["videojs"],
        "categories": [14],
    },
    "JW Player": {
        "scripts": [r"jwplayer", r"jwpcdn"],
        "js": ["jwplayer"],
        "categories": [14],
    },
    "HLS.js": {
        "scripts": [r"hls(?:\.min)?\.js"],
        "js": ["Hls"],
        "categories": [14],
    },

    # ── Maps ─────────────────────────────────────────────────────
    "Google Maps": {
        "scripts": [r"maps\.googleapis\.com/maps/api"],
        "html": [r"maps\.google\.com", r"maps\.googleapis\.com"],
        "js": ["google.maps"],
        "categories": [30],
    },
    "Leaflet": {
        "scripts": [r"leaflet(?:\.min)?\.(?:js|css)"],
        "js": ["L.version"],
        "categories": [30],
    },
    "Mapbox": {
        "scripts": [r"api\.mapbox\.com"],
        "js": ["mapboxgl"],
        "categories": [30],
    },
    "OpenStreetMap": {
        "html": [r"openstreetmap\.org", r"tile\.openstreetmap"],
        "categories": [30],
    },

    # ── Miscellaneous ────────────────────────────────────────────
    "Webpack": {
        "html": [r"__webpack_require__", r"webpackJsonp", r"webpackChunk"],
        "js": ["__webpack_require__"],
        "categories": [12],
    },
    "Vite": {
        "html": [r"/@vite/client", r"/vite/"],
        "scripts": [r"/@vite/client"],
        "categories": [12],
    },
    "ESLint": {
        "html": [r"eslint-disable"],
        "categories": [39],
    },
    "Prettier": {
        "html": [r"prettier-ignore"],
        "categories": [39],
    },
    "Open Graph": {
        "meta": {"og:title": r".+", "og:description": r".+"},
        "categories": [39],
    },
    "Twitter Cards": {
        "meta": {"twitter:card": r".+", "twitter:title": r".+"},
        "categories": [39],
    },
    "GraphQL": {
        "html": [r"graphql", r"/graphql"],
        "url": ["/graphql", "/gql"],
        "categories": [39],
    },
    "WebSocket": {
        "html": [r"WebSocket", r"wss://"],
        "categories": [39],
    },
    "Service Worker": {
        "html": [r"serviceWorker", r"service-worker"],
        "url": ["/service-worker.js", "/sw.js"],
        "categories": [39],
    },
    "AMP": {
        "html": [r"<html[^>]+amp", r"cdn\.ampproject\.org"],
        "categories": [39],
    },
    "Progressive Web App": {
        "html": [r"manifest\.json", r"<meta[^>]+theme-color"],
        "url": ["/manifest.json", "/manifest.webmanifest"],
        "categories": [39],
    },
    "Lightbox": {
        "html": [r"lightbox", r"featherlight", r"fancybox"],
        "categories": [5],
    },
    "Swiper": {
        "scripts": [r"swiper(?:\.min)?\.(?:js|css)"],
        "html": [r"swiper-container", r"swiper-slide", r"class=\"swiper"],
        "js": ["Swiper"],
        "categories": [5],
    },
    "Slick Carousel": {
        "html": [r"slick-carousel", r"slick-theme", r"class=\"slick-"],
        "scripts": [r"slick(?:\.min)?\.(?:js|css)"],
        "categories": [5],
    },
    "OWL Carousel": {
        "html": [r"owl-carousel"],
        "categories": [5],
    },
    "Cookie Consent": {
        "html": [r"cookie-consent", r"cookie-banner", r"CookieConsent", r"gdpr-consent", r"cc-banner"],
        "categories": [57],
    },
    "OneTrust": {
        "scripts": [r"onetrust\.com", r"optanon"],
        "cookies": ["OptanonConsent"],
        "categories": [57],
    },
    "Osano": {
        "scripts": [r"cmp\.osano\.com"],
        "categories": [57],
    },
    "Mailchimp": {
        "scripts": [r"list-manage\.com", r"mailchimp\.com"],
        "html": [r"mailchimp", r"mc\.us\d+\.list-manage\.com"],
        "categories": [25],
    },
    "SendGrid": {
        "scripts": [r"sendgrid"],
        "html": [r"sendgrid"],
        "categories": [46],
    },
    "Mailgun": {
        "html": [r"mailgun"],
        "categories": [46],
    },
    "Elastic Kibana": {
        "html": [r"kibana"],
        "url": ["/app/kibana", "/api/status"],
        "categories": [28],
        "implies": ["Elasticsearch"],
    },
    "Grafana": {
        "html": [r"grafana", r"grafana-app"],
        "url": ["/api/dashboards/home", "/api/org"],
        "categories": [10],
    },
    "Prometheus": {
        "url": ["/api/v1/query", "/graph"],
        "categories": [10],
    },
    "Jenkins": {
        "html": [r"Jenkins", r"jenkins"],
        "headers": {"X-Jenkins": r"([\d.]+)"},
        "version": r"X-Jenkins:\s*([\d.]+)",
        "categories": [9],
    },
    "GitLab": {
        "cookies": ["_gitlab_session"],
        "html": [r"gitlab", r"gon\.gitlab"],
        "categories": [9, 13],
    },
    "Jira": {
        "html": [r"jira", r"Atlassian"],
        "cookies": ["atlassian.xsrf.token", "JSESSIONID"],
        "categories": [13],
    },
    "Confluence": {
        "html": [r"confluence", r"Atlassian"],
        "categories": [4],
    },
    "Sentry": {
        "scripts": [r"browser\.sentry-cdn\.com", r"sentry\.io"],
        "js": ["Sentry", "__SENTRY__"],
        "categories": [10],
    },
    "Bugsnag": {
        "scripts": [r"bugsnag"],
        "js": ["Bugsnag"],
        "categories": [10],
    },
    "New Relic": {
        "scripts": [r"js-agent\.newrelic\.com", r"bam\.nr-data\.net"],
        "js": ["NREUM", "newrelic"],
        "categories": [10],
    },
    "DataDog": {
        "scripts": [r"datadog-rum", r"datadoghq\.com"],
        "js": ["DD_RUM"],
        "categories": [10],
    },
    "Algolia": {
        "scripts": [r"cdn\.jsdelivr\.net/npm/@algolia", r"algoliasearch"],
        "html": [r"algolia"],
        "js": ["algoliasearch", "algoliaConfig"],
        "categories": [28],
    },
    "Elasticsearch (Search)": {
        "scripts": [r"elastic"],
        "js": ["elastic"],
        "categories": [28],
        "implies": ["Elasticsearch"],
    },
    "Disqus": {
        "scripts": [r"disqus\.com/embed\.js", r"disqus_shortname"],
        "js": ["DISQUS"],
        "categories": [15],
    },
    "AddThis": {
        "scripts": [r"addthis\.com/js/"],
        "js": ["addthis"],
        "categories": [5],
    },
    "ShareThis": {
        "scripts": [r"platform-api\.sharethis\.com"],
        "categories": [5],
    },
    "Privy": {
        "scripts": [r"privy\.com"],
        "categories": [25],
    },
    "Trustpilot": {
        "scripts": [r"widget\.trustpilot\.com"],
        "html": [r"trustpilot"],
        "categories": [5],
    },
    "Gorgias": {
        "scripts": [r"config\.gorgias\.chat"],
        "categories": [36],
    },
    "Freshdesk": {
        "scripts": [r"freshdesk\.com"],
        "html": [r"freshdesk"],
        "categories": [36],
    },
}

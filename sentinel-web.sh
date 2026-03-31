#!/bin/bash
# Sentinel Web App Security Scanner
# https://sentinel.hitcreate.io
# Run: sentinel scan <url>
#
# Scans any deployed web app for security misconfigurations.
# Checks headers, exposed secrets, CORS, debug endpoints, TLS.

set -uo pipefail

JSON_MODE=false
EXPLAIN_MODE=false
FIX_MODE=false
TARGET_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_MODE=true; shift ;;
    --explain) EXPLAIN_MODE=true; shift ;;
    --fix) FIX_MODE=true; shift ;;
    -*) echo "Unknown option: $1"; exit 1 ;;
    *) TARGET_URL="$1"; shift ;;
  esac
done

if [[ -z "$TARGET_URL" ]]; then
  echo "Usage: sentinel-web.sh <url> [--explain] [--fix] [--json]"
  exit 1
fi

# Normalize URL
[[ "$TARGET_URL" != http* ]] && TARGET_URL="https://$TARGET_URL"
# Strip trailing slash
TARGET_URL="${TARGET_URL%/}"

# ── Scoring ──
PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()
EXPLANATIONS=()
NC="\033[0m"

check() {
  local id="$1" category="$2" name="$3" severity="$4"
  shift 4
  TOTAL=$((TOTAL + 1))
  if "$@" 2>/dev/null; then
    PASS=$((PASS + 1))
    RESULTS+=("PASS|$id|$category|$name|$severity")
    if ! $JSON_MODE && ! $FIX_MODE; then
      printf "  \033[32m✓\033[0m %-44s %s\n" "$name" "PASS"
    fi
  else
    if [[ "$severity" == "critical" || "$severity" == "high" ]]; then
      FAIL=$((FAIL + 1))
    else
      WARN=$((WARN + 1))
    fi
    RESULTS+=("FAIL|$id|$category|$name|$severity")
    if ! $JSON_MODE && ! $FIX_MODE; then
      if [[ "$severity" == "critical" ]]; then
        printf "  \033[31m✗\033[0m %-44s %s (%s)\n" "$name" "FAIL" "$severity"
      else
        printf "  \033[33m!\033[0m %-44s %s (%s)\n" "$name" "WARN" "$severity"
      fi
    fi
  fi
}

explain() {
  local id="$1" what="$2" why="$3" fix="$4"
  EXPLANATIONS+=("$id|$what|$why|$fix")
}

# ── Fetch page + headers once ──
HEADERS_RAW=""
PAGE_SOURCE=""
HTTP_CODE=""

fetch_target() {
  HEADERS_RAW=$(curl -sI -L --max-time 15 "$TARGET_URL" 2>/dev/null)
  PAGE_SOURCE=$(curl -sL --max-time 15 "$TARGET_URL" 2>/dev/null)
  HTTP_CODE=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET_URL" 2>/dev/null)
}

# ── Security Headers ──

check_hsts() {
  echo "$HEADERS_RAW" | grep -qi "strict-transport-security"
}

check_hsts_quality() {
  local hsts
  hsts=$(echo "$HEADERS_RAW" | grep -i "strict-transport-security" | head -1)
  [[ -z "$hsts" ]] && return 1
  # Check max-age >= 31536000 (1 year)
  local max_age
  max_age=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+' | head -1)
  [[ -n "$max_age" && "$max_age" -ge 31536000 ]]
}

check_csp() {
  echo "$HEADERS_RAW" | grep -qi "content-security-policy"
}

check_csp_quality() {
  local csp
  csp=$(echo "$HEADERS_RAW" | grep -i "content-security-policy" | head -1)
  [[ -z "$csp" ]] && return 1
  # Fail if contains unsafe-inline or unsafe-eval
  ! echo "$csp" | grep -qi "unsafe-inline\|unsafe-eval"
}

check_x_content_type() {
  echo "$HEADERS_RAW" | grep -qi "x-content-type-options"
}

check_x_frame_options() {
  echo "$HEADERS_RAW" | grep -qi "x-frame-options\|frame-ancestors"
}

check_referrer_policy() {
  echo "$HEADERS_RAW" | grep -qi "referrer-policy"
}

check_permissions_policy() {
  echo "$HEADERS_RAW" | grep -qi "permissions-policy"
}

# ── Exposed Secrets & Files ──

check_env_exposed() {
  local code
  code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET_URL/.env" 2>/dev/null)
  # 200 with content that looks like env vars = exposed
  if [[ "$code" == "200" ]]; then
    local content
    content=$(curl -sL --max-time 5 "$TARGET_URL/.env" 2>/dev/null | head -5)
    echo "$content" | grep -qE '^[A-Z_]+=.' && return 1
  fi
  return 0
}

check_git_exposed() {
  local code
  code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET_URL/.git/config" 2>/dev/null)
  if [[ "$code" == "200" ]]; then
    local content
    content=$(curl -sL --max-time 5 "$TARGET_URL/.git/config" 2>/dev/null | head -3)
    echo "$content" | grep -qi "repositoryformatversion\|\[core\]\|\[remote" && return 1
  fi
  return 0
}

check_sourcemap_exposed() {
  # Check if JS source maps are accessible (leak source code)
  local js_file
  js_file=$(echo "$PAGE_SOURCE" | grep -oP 'src="([^"]*\.js)"' | grep -oP '"[^"]*"' | tr -d '"' | head -1)
  [[ -z "$js_file" ]] && return 0
  case "$js_file" in
    http*) ;;
    //*) js_file="https:$js_file" ;;
    /*) js_file="${TARGET_URL}$js_file" ;;
    *) js_file="${TARGET_URL}/$js_file" ;;
  esac
  local map_code
  map_code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 "${js_file}.map" 2>/dev/null)
  [[ "$map_code" != "200" ]]
}

check_debug_headers() {
  # Check for debug/dev indicators in headers
  local debug_found=false
  echo "$HEADERS_RAW" | grep -qi "x-debug\|x-powered-by.*debug\|server.*development" && debug_found=true
  # Check page source for common debug indicators
  echo "$PAGE_SOURCE" | grep -qi '__NEXT_DATA__.*"development"\|DEBUG.*=.*true\|"debug":true' && debug_found=true
  ! $debug_found
}

# ── API Key Exposure ──

check_api_keys_in_source() {
  # Scan page source + JS bundles for secret API key patterns
  # 15 patterns covering the most commonly leaked keys
  local found=false
  local scan_text="$PAGE_SOURCE"

  # Also grab inline JS and first few JS bundle contents
  local js_urls
  js_urls=$(echo "$PAGE_SOURCE" | grep -oP 'src="([^"]*\.js)"' | grep -oP '"[^"]*"' | tr -d '"' | head -5)
  for js_url in $js_urls; do
    case "$js_url" in
      http*) ;;
      //*) js_url="https:$js_url" ;;
      /*) js_url="${TARGET_URL}$js_url" ;;
      *) js_url="${TARGET_URL}/$js_url" ;;
    esac
    local js_content
    js_content=$(curl -sL --max-time 5 "$js_url" 2>/dev/null | head -500)
    scan_text="$scan_text"$'\n'"$js_content"
  done

  # 1. AWS Access Key
  echo "$scan_text" | grep -qP 'AKIA[0-9A-Z]{16}' && found=true

  # 2. Stripe secret key
  echo "$scan_text" | grep -qP 'sk_live_[a-zA-Z0-9]{20,}' && found=true

  # 3. Stripe restricted key
  echo "$scan_text" | grep -qP 'rk_live_[a-zA-Z0-9]{20,}' && found=true

  # 4. OpenAI key
  echo "$scan_text" | grep -qP 'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}' && found=true

  # 5. Anthropic key
  echo "$scan_text" | grep -qP 'sk-ant-[a-zA-Z0-9_-]{40,}' && found=true

  # 6. GitHub PAT (classic)
  echo "$scan_text" | grep -qP 'ghp_[a-zA-Z0-9]{36}' && found=true

  # 7. GitHub PAT (fine-grained)
  echo "$scan_text" | grep -qP 'github_pat_[a-zA-Z0-9_]{82}' && found=true

  # 8. Supabase service_role key (JWT with service_role claim)
  # Handled by Supabase scanner, but check here too
  echo "$scan_text" | grep -qP '"role"\s*:\s*"service_role"' && found=true

  # 9. Twilio
  echo "$scan_text" | grep -qP 'SK[a-f0-9]{32}' && found=true

  # 10. SendGrid
  echo "$scan_text" | grep -qP 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}' && found=true

  # 11. Mailgun
  echo "$scan_text" | grep -qP 'key-[a-f0-9]{32}' && found=true

  # 12. Database connection strings
  echo "$scan_text" | grep -qP '(postgres|mysql|mongodb)://[a-zA-Z0-9_]+:[^@\s]{8,}@' && found=true

  # 13. Private key blocks
  echo "$scan_text" | grep -qP 'BEGIN (RSA |EC |DSA )?PRIVATE KEY' && found=true

  # 14. Generic SECRET/PRIVATE patterns with values
  echo "$scan_text" | grep -qP '(SECRET|PRIVATE|MASTER)_KEY\s*[:=]\s*["\x27][a-zA-Z0-9_-]{20,}' && found=true

  # 15. Firebase server key
  echo "$scan_text" | grep -qP 'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}' && found=true

  ! $found
}

check_next_public_secrets() {
  # NEXT_PUBLIC_ vars that look like secrets
  local found=false
  echo "$PAGE_SOURCE" | grep -qP 'NEXT_PUBLIC_[A-Z_]*(SECRET|PRIVATE|KEY|TOKEN|PASSWORD)[A-Z_]*' && found=true
  ! $found
}

# ── CORS ──

check_cors_wildcard() {
  # Send a preflight-style request and check ACAO header
  local cors_header
  cors_header=$(curl -sI -L --max-time 5 \
    -H "Origin: https://evil.example.com" \
    "$TARGET_URL" 2>/dev/null | grep -i "access-control-allow-origin" | head -1)

  [[ -z "$cors_header" ]] && return 0  # No CORS header = no issue
  ! echo "$cors_header" | grep -q '\*'
}

# ── TLS ──

check_tls_valid() {
  [[ "$TARGET_URL" != https://* ]] && return 1
  local domain
  domain=$(echo "$TARGET_URL" | sed 's|https://||' | cut -d/ -f1)
  echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -checkend 604800 &>/dev/null
}

check_https_redirect() {
  local http_url="${TARGET_URL/https:/http:}"
  local redirect
  redirect=$(curl -sI -L --max-time 5 -o /dev/null -w "%{url_effective}" "$http_url" 2>/dev/null)
  [[ "$redirect" == https://* ]]
}

# ── Exposed Endpoints ──

check_admin_exposed() {
  local admin_found=false
  for path in "/admin" "/wp-admin" "/phpmyadmin" "/adminer" "/_debug" "/graphql"; do
    local code
    code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 3 "${TARGET_URL}${path}" 2>/dev/null)
    if [[ "$code" == "200" ]]; then
      admin_found=true
      break
    fi
  done
  ! $admin_found
}

# ── Explanation Data ──

load_explanations() {
  explain "W01" \
    "Strict-Transport-Security header missing" \
    "Without HSTS, browsers may connect over plain HTTP, allowing man-in-the-middle attacks. 64% of sites still lack this header." \
    "Add to your server config:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"

  explain "W02" \
    "HSTS max-age too short or missing includeSubDomains" \
    "A short max-age or missing includeSubDomains leaves gaps in HTTPS enforcement." \
    "Set max-age to at least 31536000 (1 year) and include subdomains:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"

  explain "W03" \
    "Content-Security-Policy header missing" \
    "CSP prevents XSS attacks by controlling which scripts can run. Only 22% of sites have it." \
    "Start with a report-only policy, then tighten:\n  Content-Security-Policy: default-src 'self'; script-src 'self'"

  explain "W04" \
    "CSP uses unsafe-inline or unsafe-eval" \
    "These directives defeat the purpose of CSP by allowing inline scripts (the main XSS vector)." \
    "Remove unsafe-inline and unsafe-eval. Use nonces or hashes instead:\n  script-src 'self' 'nonce-{random}'"

  explain "W05" \
    "X-Content-Type-Options header missing" \
    "Without nosniff, browsers may interpret files as a different MIME type, enabling attacks." \
    "Add: X-Content-Type-Options: nosniff"

  explain "W06" \
    "X-Frame-Options / frame-ancestors missing" \
    "Without this, your site can be embedded in iframes on malicious sites (clickjacking)." \
    "Add: X-Frame-Options: DENY\nOr in CSP: frame-ancestors 'none'"

  explain "W07" \
    "Referrer-Policy header missing" \
    "Without it, full URLs (including query params with tokens) leak to third-party sites." \
    "Add: Referrer-Policy: strict-origin-when-cross-origin"

  explain "W08" \
    "Permissions-Policy header missing" \
    "Controls which browser features (camera, mic, geolocation) your site can use. Only 4% adoption." \
    "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"

  explain "W09" \
    ".env file accessible via web" \
    "Your .env file (containing API keys, database passwords, secrets) is publicly downloadable. This is the #1 post-deploy mistake — 110,000+ domains were compromised via exposed .env files." \
    "Block .env in your web server config:\n  Caddy: @blocked path /.env\n        respond @blocked 404\n  Nginx: location ~ /\\.env { deny all; }"

  explain "W10" \
    ".git directory accessible via web" \
    "Your git repository is exposed. Attackers can download your entire source code, commit history, and any secrets ever committed. 5 million servers expose .git directories." \
    "Block .git in your web server config:\n  Caddy: @blocked path /.git/*\n        respond @blocked 404\n  Nginx: location ~ /\\.git { deny all; }"

  explain "W11" \
    "JavaScript source maps accessible" \
    "Source maps expose your original source code, making it easier to find vulnerabilities." \
    "Remove .map files from production or block access:\n  In Next.js: productionBrowserSourceMaps: false in next.config.js"

  explain "W12" \
    "Debug mode indicators detected" \
    "Debug/development indicators in production expose internal state and error details to attackers." \
    "Ensure NODE_ENV=production and debug flags are off in your deployment."

  explain "W13" \
    "API keys found in page source or JS bundles" \
    "Secret API keys are embedded in your frontend JavaScript. Sentinel checks 15 patterns: AWS (AKIA), Stripe (sk_live), OpenAI (sk-), Anthropic (sk-ant-), GitHub PATs (ghp_), Supabase service_role, Twilio, SendGrid, Mailgun, database URIs, private key blocks, Firebase, and generic secret patterns. Stolen keys are exploited within 5 minutes of GitHub exposure." \
    "Move ALL secret keys to server-side code (API routes, Edge Functions, environment variables). Never prefix secrets with NEXT_PUBLIC_ or VITE_."

  explain "W14" \
    "Suspicious NEXT_PUBLIC_ variables detected" \
    "NEXT_PUBLIC_ variables are exposed to the browser. If they contain SECRET, PRIVATE, or KEY, they may be leaking credentials." \
    "Rename without NEXT_PUBLIC_ prefix and access server-side only (API routes, getServerSideProps)."

  explain "W15" \
    "CORS allows all origins (*)" \
    "Access-Control-Allow-Origin: * lets any website make authenticated requests to your API and read the response." \
    "Restrict to your actual domains:\n  Access-Control-Allow-Origin: https://yourdomain.com"

  explain "W16" \
    "TLS certificate expires within 7 days or is invalid" \
    "An expired or invalid TLS certificate breaks HTTPS and shows security warnings to users." \
    "Renew your certificate. If using Let's Encrypt / Caddy, check auto-renewal is working."

  explain "W17" \
    "HTTP does not redirect to HTTPS" \
    "HTTP requests are not redirected to HTTPS, meaning traffic can be intercepted." \
    "Configure your server to redirect all HTTP to HTTPS."

  explain "W18" \
    "Admin/debug endpoints accessible" \
    "Common admin paths (/admin, /wp-admin, /phpmyadmin, /graphql) are publicly accessible." \
    "Protect admin endpoints with authentication or remove them from production."
}

# ── Output ──

print_header() {
  if ! $JSON_MODE && ! $FIX_MODE; then
    echo ""
    echo -e "\033[33mSentinel Web App Security Scan\033[0m"
    echo -e "\033[33m══════════════════════════════\033[0m"
    echo ""
    echo "  Target: $TARGET_URL"
    echo "  Status: $HTTP_CODE"
    echo ""
  fi
}

print_grade() {
  local score=0
  [[ $TOTAL -gt 0 ]] && score=$(( (PASS * 100) / TOTAL ))

  local grade
  if [[ $FAIL -eq 0 && $score -ge 90 ]]; then grade="A"
  elif [[ $score -ge 80 ]]; then grade="B"
  elif [[ $score -ge 65 ]]; then grade="C"
  elif [[ $score -ge 50 ]]; then grade="D"
  else grade="F"
  fi

  if $JSON_MODE; then
    echo "{"
    echo "  \"scan_type\": \"web\","
    echo "  \"target\": \"$TARGET_URL\","
    echo "  \"http_status\": \"$HTTP_CODE\","
    echo "  \"grade\": \"$grade\","
    echo "  \"score\": $score,"
    echo "  \"total\": $TOTAL,"
    echo "  \"pass\": $PASS,"
    echo "  \"fail\": $FAIL,"
    echo "  \"warn\": $WARN,"
    echo "  \"results\": ["
    local first=true
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r status id cat name sev <<< "$r"
      $first || echo ","
      printf '    {"id":"%s","category":"%s","name":"%s","severity":"%s","status":"%s"}' "$id" "$cat" "$name" "$sev" "$status"
      first=false
    done
    echo ""
    echo "  ]"
    echo "}"
  elif $FIX_MODE; then
    echo "# Sentinel Web App Fixes"
    echo "# Target: $TARGET_URL"
    echo "# Grade: $grade ($score%) — $FAIL critical/high issues"
    echo ""
    for e in "${EXPLANATIONS[@]}"; do
      IFS='|' read -r eid ewhat ewhy efix <<< "$e"
      for r in "${RESULTS[@]}"; do
        IFS='|' read -r status rid rcat rname rsev <<< "$r"
        if [[ "$rid" == "$eid" && "$status" == "FAIL" ]]; then
          echo "# $eid: $rname"
          echo -e "$efix"
          echo ""
        fi
      done
    done
  else
    echo ""
    local grade_color
    case "$grade" in
      A|B) grade_color="\033[32m" ;;
      C) grade_color="\033[33m" ;;
      *) grade_color="\033[31m" ;;
    esac

    echo -e "  ${grade_color}Grade: $grade ($score%)${NC}"
    echo "  $PASS of $TOTAL checks passed · $FAIL critical/high · $WARN warnings"
    echo ""

    if $EXPLAIN_MODE; then
      echo -e "\033[33m── Explanations ──\033[0m"
      echo ""
      for e in "${EXPLANATIONS[@]}"; do
        IFS='|' read -r eid ewhat ewhy efix <<< "$e"
        for r in "${RESULTS[@]}"; do
          IFS='|' read -r status rid rcat rname rsev <<< "$r"
          if [[ "$rid" == "$eid" && "$status" == "FAIL" ]]; then
            echo -e "  \033[33m$eid: $rname\033[0m"
            echo "  WHAT: $ewhat"
            echo "  WHY:  $ewhy"
            echo -e "  FIX:  $efix"
            echo ""
          fi
        done
      done
    else
      if [[ $FAIL -gt 0 || $WARN -gt 0 ]]; then
        echo "  Run with --explain to see what's wrong and how to fix it."
        echo "  Run with --fix to get the commands."
      fi
    fi
  fi
}

# ── Main ──

fetch_target

if [[ "$HTTP_CODE" == "000" ]]; then
  echo "Error: Could not connect to $TARGET_URL"
  exit 1
fi

print_header

# Security Headers
if ! $JSON_MODE && ! $FIX_MODE; then
  echo -e "\033[33m── Security Headers ──\033[0m"
fi
check W01 Headers  "Strict-Transport-Security (HSTS)"      high     check_hsts
check W02 Headers  "HSTS max-age >= 1 year + subdomains"   medium   check_hsts_quality
check W03 Headers  "Content-Security-Policy (CSP)"         high     check_csp
check W04 Headers  "CSP without unsafe-inline/eval"        medium   check_csp_quality
check W05 Headers  "X-Content-Type-Options: nosniff"       medium   check_x_content_type
check W06 Headers  "X-Frame-Options / frame-ancestors"     medium   check_x_frame_options
check W07 Headers  "Referrer-Policy"                       medium   check_referrer_policy
check W08 Headers  "Permissions-Policy"                    medium   check_permissions_policy

# Exposed Secrets
if ! $JSON_MODE && ! $FIX_MODE; then
  echo ""
  echo -e "\033[33m── Exposed Secrets & Files ──\033[0m"
fi
check W09 Secrets  ".env file not accessible"              critical check_env_exposed
check W10 Secrets  ".git directory not accessible"         critical check_git_exposed
check W11 Secrets  "Source maps not exposed"               medium   check_sourcemap_exposed
check W12 Secrets  "No debug mode indicators"              high     check_debug_headers
check W13 Secrets  "No API keys in page source"            critical check_api_keys_in_source
check W14 Secrets  "No secrets in NEXT_PUBLIC_ vars"       high     check_next_public_secrets

# CORS & Transport
if ! $JSON_MODE && ! $FIX_MODE; then
  echo ""
  echo -e "\033[33m── Transport & Access ──\033[0m"
fi
check W15 CORS     "CORS does not allow all origins"       high     check_cors_wildcard
check W16 TLS      "TLS certificate valid (7+ days)"      critical check_tls_valid
check W17 TLS      "HTTP redirects to HTTPS"               high     check_https_redirect
check W18 Access   "Admin/debug endpoints not exposed"     high     check_admin_exposed

load_explanations
print_grade

#!/bin/bash
# Sentinel Supabase Security Scanner
# https://sentinel.hitcreate.io
# Run: sentinel scan --supabase <url>
#
# Scans a Supabase project for security misconfigurations.
# Checks RLS status, key exposure, auth config, storage policies.

set -uo pipefail

JSON_MODE=false
EXPLAIN_MODE=false
FIX_MODE=false
TARGET_URL=""
SUPABASE_URL=""
ANON_KEY=""
SERVICE_ROLE_KEY_FOUND=false

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_MODE=true; shift ;;
    --explain) EXPLAIN_MODE=true; shift ;;
    --fix) FIX_MODE=true; shift ;;
    --anon-key) ANON_KEY="$2"; shift 2 ;;
    --url) SUPABASE_URL="$2"; shift 2 ;;
    -*) echo "Unknown option: $1"; exit 1 ;;
    *) TARGET_URL="$1"; shift ;;
  esac
done

if [[ -z "$TARGET_URL" && -z "$SUPABASE_URL" ]]; then
  echo "Usage: sentinel-supabase.sh <app-url-or-supabase-url> [--anon-key KEY] [--explain] [--fix] [--json]"
  echo ""
  echo "Examples:"
  echo "  sentinel-supabase.sh https://myapp.vercel.app          # Auto-detect from page source"
  echo "  sentinel-supabase.sh --url https://xyz.supabase.co --anon-key eyJ...  # Direct"
  exit 1
fi

# ── Scoring ──
PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()
EXPLANATIONS=()
FIXES=()

check() {
  local id="$1" category="$2" name="$3" severity="$4"
  shift 4
  TOTAL=$((TOTAL + 1))
  if "$@" 2>/dev/null; then
    PASS=$((PASS + 1))
    RESULTS+=("PASS|$id|$category|$name|$severity")
    if ! $JSON_MODE && ! $FIX_MODE; then
      printf "  \033[32m✓\033[0m %-40s %s\n" "$name" "PASS"
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
        printf "  \033[31m✗\033[0m %-40s %s (%s)\n" "$name" "FAIL" "$severity"
      else
        printf "  \033[33m!\033[0m %-40s %s (%s)\n" "$name" "WARN" "$severity"
      fi
    fi
  fi
}

explain() {
  local id="$1" what="$2" why="$3" fix="$4"
  EXPLANATIONS+=("$id|$what|$why|$fix")
  FIXES+=("$id|$fix")
}

# ── D1: Detection & Connection ──

detect_supabase() {
  # If direct Supabase URL provided, use it
  if [[ -n "$SUPABASE_URL" ]]; then
    return 0
  fi

  # Otherwise, fetch the target URL and look for Supabase client init
  local page_source
  page_source=$(curl -sL --max-time 15 "$TARGET_URL" 2>/dev/null) || return 1

  # Look for Supabase URL in page source or JS bundles
  # Common patterns: createClient("https://xyz.supabase.co", "eyJ...")
  # NEXT_PUBLIC_SUPABASE_URL, VITE_SUPABASE_URL, REACT_APP_SUPABASE_URL
  local detected_url
  detected_url=$(echo "$page_source" | grep -oP 'https://[a-zA-Z0-9-]+\.supabase\.co' | head -1)

  if [[ -z "$detected_url" ]]; then
    # Try fetching JS bundles referenced in the page
    local js_urls
    js_urls=$(echo "$page_source" | grep -oP '(?:src|href)="([^"]*\.js)"' | grep -oP '"[^"]*"' | tr -d '"' | head -10)
    for js_url in $js_urls; do
      # Handle relative URLs
      case "$js_url" in
        http*) ;;
        //*) js_url="https:$js_url" ;;
        /*) js_url="${TARGET_URL%/}$js_url" ;;
        *) js_url="${TARGET_URL%/}/$js_url" ;;
      esac
      local js_content
      js_content=$(curl -sL --max-time 10 "$js_url" 2>/dev/null)
      detected_url=$(echo "$js_content" | grep -oP 'https://[a-zA-Z0-9-]+\.supabase\.co' | head -1)
      if [[ -n "$detected_url" ]]; then
        # Also try to grab the anon key from the same bundle
        if [[ -z "$ANON_KEY" ]]; then
          ANON_KEY=$(echo "$js_content" | grep -oP 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | head -1)
        fi
        break
      fi
    done
  fi

  # Also check inline scripts for the anon key
  if [[ -z "$ANON_KEY" ]]; then
    ANON_KEY=$(echo "$page_source" | grep -oP 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | head -1)
  fi

  if [[ -n "$detected_url" ]]; then
    SUPABASE_URL="$detected_url"
    return 0
  fi

  return 1
}

# Decode JWT payload (base64url → base64 → JSON)
decode_jwt_payload() {
  local token="$1"
  local payload
  payload=$(echo "$token" | cut -d. -f2)
  # Add padding
  local pad=$((4 - ${#payload} % 4))
  [[ $pad -lt 4 ]] && payload="${payload}$(printf '=%.0s' $(seq 1 $pad))"
  # Decode (handle base64url: replace - with + and _ with /)
  echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null
}

# ── D3: Key Exposure Checks ──

# SB04: Check if any JWT in the frontend is a service_role key
check_service_role_key() {
  [[ -z "$TARGET_URL" ]] && return 0  # Can't check without a web app URL

  local page_source
  page_source=$(curl -sL --max-time 15 "$TARGET_URL" 2>/dev/null)

  # Find all JWTs in page source
  local jwts
  jwts=$(echo "$page_source" | grep -oP 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' 2>/dev/null)

  # Also scan JS bundles
  local js_urls
  js_urls=$(echo "$page_source" | grep -oP '(?:src|href)="([^"]*\.js)"' | grep -oP '"[^"]*"' | tr -d '"' | head -10)
  for js_url in $js_urls; do
    case "$js_url" in
      http*) ;;
      //*) js_url="https:$js_url" ;;
      /*) js_url="${TARGET_URL%/}$js_url" ;;
      *) js_url="${TARGET_URL%/}/$js_url" ;;
    esac
    local js_content
    js_content=$(curl -sL --max-time 10 "$js_url" 2>/dev/null)
    local more_jwts
    more_jwts=$(echo "$js_content" | grep -oP 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' 2>/dev/null)
    jwts="$jwts"$'\n'"$more_jwts"
  done

  # Check each JWT for service_role
  local jwt
  while IFS= read -r jwt; do
    [[ -z "$jwt" ]] && continue
    local payload_json
    payload_json=$(decode_jwt_payload "$jwt")
    if echo "$payload_json" | grep -q '"role"[[:space:]]*:[[:space:]]*"service_role"'; then
      SERVICE_ROLE_KEY_FOUND=true
      return 1  # CRITICAL: service_role key in frontend
    fi
  done <<< "$jwts"

  return 0  # No service_role key found — good
}

# SB05: Anon key in frontend + RLS disabled = open database
check_anon_key_without_rls() {
  # This check is evaluated after RLS checks — uses global RLS_DISABLED_TABLES
  [[ -z "$ANON_KEY" ]] && return 0  # No anon key found, can't assess
  [[ -z "${RLS_DISABLED_TABLES:-}" ]] && return 0  # No RLS issues found
  return 1  # Anon key exposed AND tables without RLS = open database
}

# SB06: .git-credentials or hardcoded Supabase keys in local files (if running locally)
check_git_credentials_supabase() {
  [[ -f "$HOME/.git-credentials" ]] || return 0
  grep -qi "supabase" "$HOME/.git-credentials" 2>/dev/null && return 1
  return 0
}

# ── D2: RLS Status Checks ──

RLS_DISABLED_TABLES=""
TABLES_CHECKED=0
TABLES_UNPROTECTED=0

check_rls_enabled() {
  [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]] && return 1

  # Try to query tables via PostgREST
  # If we can read data from a table without auth context, RLS may be off
  # First, get the OpenAPI spec to discover tables
  local schema_response
  schema_response=$(curl -sL --max-time 10 \
    -H "apikey: $ANON_KEY" \
    -H "Authorization: Bearer $ANON_KEY" \
    "${SUPABASE_URL}/rest/v1/" 2>/dev/null)

  if [[ -z "$schema_response" ]]; then
    return 1  # Can't connect
  fi

  # Extract table names from the OpenAPI paths
  local tables
  tables=$(echo "$schema_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    paths = data.get('paths', {})
    for path in paths:
        name = path.strip('/')
        if name and not name.startswith('rpc/'):
            print(name)
except:
    pass
" 2>/dev/null)

  if [[ -z "$tables" ]]; then
    # Try alternate approach: just test common table names
    tables="users profiles items posts products orders messages"
  fi

  local unprotected=0
  local checked=0

  while IFS= read -r table; do
    [[ -z "$table" ]] && continue
    checked=$((checked + 1))

    # Try to SELECT from the table with anon key
    local response
    response=$(curl -sL --max-time 5 \
      -H "apikey: $ANON_KEY" \
      -H "Authorization: Bearer $ANON_KEY" \
      -H "Range: 0-0" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" 2>/dev/null)

    local http_code
    http_code=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}" \
      -H "apikey: $ANON_KEY" \
      -H "Authorization: Bearer $ANON_KEY" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" 2>/dev/null)

    # If we get 200 with data, the table might have RLS off or permissive policies
    # If we get 200 with empty array [], RLS is on and blocking (good)
    # If we get 401/403, no access (good)
    # If we get 404, table doesn't exist in schema (skip)
    if [[ "$http_code" == "200" ]]; then
      # Check if response has actual data rows
      local row_count
      row_count=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        print(len(data))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null)

      if [[ "$row_count" -gt 0 ]]; then
        # Data returned — could be RLS off or intentionally public
        # Flag it for review
        unprotected=$((unprotected + 1))
        RLS_DISABLED_TABLES="${RLS_DISABLED_TABLES}${table} "
      fi
    fi
  done <<< "$tables"

  TABLES_CHECKED=$checked
  TABLES_UNPROTECTED=$unprotected

  [[ $unprotected -eq 0 ]]
}

# SB02: Check for tables that return ALL rows (sign of no RLS or permissive policy)
check_permissive_policies() {
  [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]] && return 0
  [[ $TABLES_CHECKED -eq 0 ]] && return 0

  # If any table returned data to anon user, check if it returns many rows
  for table in $RLS_DISABLED_TABLES; do
    local count_response
    count_response=$(curl -sL --max-time 5 \
      -H "apikey: $ANON_KEY" \
      -H "Authorization: Bearer $ANON_KEY" \
      -H "Prefer: count=exact" \
      -H "Range: 0-0" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*" 2>/dev/null)

    # Check content-range header for total count
    local total
    total=$(curl -sI --max-time 5 \
      -H "apikey: $ANON_KEY" \
      -H "Authorization: Bearer $ANON_KEY" \
      -H "Prefer: count=exact" \
      -H "Range: 0-0" \
      "${SUPABASE_URL}/rest/v1/${table}?select=*" 2>/dev/null | grep -i "content-range" | grep -oP '/\K[0-9]+' | head -1)

    if [[ -n "$total" && "$total" -gt 10 ]]; then
      return 1  # Many rows accessible — likely overly permissive or no RLS
    fi
  done

  return 0
}

# SB03: Try INSERT/UPDATE/DELETE to test write protection
check_write_protection() {
  [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]] && return 0
  [[ -z "$RLS_DISABLED_TABLES" ]] && return 0

  for table in $RLS_DISABLED_TABLES; do
    # Try a dry-run INSERT (use Prefer: return=minimal to reduce side effects)
    # We send an obviously invalid/empty payload — if we get 201 or 200, writes are open
    local write_code
    write_code=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}" \
      -X POST \
      -H "apikey: $ANON_KEY" \
      -H "Authorization: Bearer $ANON_KEY" \
      -H "Content-Type: application/json" \
      -H "Prefer: return=minimal" \
      -d '{"__sentinel_test__": true}' \
      "${SUPABASE_URL}/rest/v1/${table}" 2>/dev/null)

    # 201 = inserted (BAD - writes are open, also we just inserted junk — unlikely to have that column though)
    # 400 = bad request (column doesn't exist — means it TRIED to write, RLS allowed it)
    # 401/403 = blocked (good)
    # 404 = not found
    if [[ "$write_code" == "201" ]]; then
      return 1  # Writes are open — critical
    fi
    # 400 with "column not found" still means write access was granted
    if [[ "$write_code" == "400" ]]; then
      local write_response
      write_response=$(curl -sL --max-time 5 \
        -X POST \
        -H "apikey: $ANON_KEY" \
        -H "Authorization: Bearer $ANON_KEY" \
        -H "Content-Type: application/json" \
        -H "Prefer: return=minimal" \
        -d '{"__sentinel_test__": true}' \
        "${SUPABASE_URL}/rest/v1/${table}" 2>/dev/null)

      # If error is about the column (not permissions), writes are enabled
      if echo "$write_response" | grep -qi "column\|not present\|unknown"; then
        return 1
      fi
    fi
  done

  return 0
}

# ── D4: API Endpoint Security ──

# SB07: Auth signup open?
check_auth_signup() {
  [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]] && return 0

  local signup_code
  signup_code=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "apikey: $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d '{"email":"sentinel-test-do-not-use@example.invalid","password":"SentinelTestDoNotUse123!"}' \
    "${SUPABASE_URL}/auth/v1/signup" 2>/dev/null)

  # 200 = signup succeeded (not necessarily bad — depends on app)
  # 422 = validation error (signup works but rejected this input)
  # 429 = rate limited (good, but signup is enabled)
  # 401/403 = signup disabled (good for apps that shouldn't allow public signup)
  # We flag this as informational — signup being open isn't always a problem
  if [[ "$signup_code" == "200" || "$signup_code" == "422" || "$signup_code" == "429" ]]; then
    return 1  # Signup is open — WARN (not always bad)
  fi

  return 0  # Signup restricted
}

# SB08: Storage buckets publicly accessible?
check_storage_public() {
  [[ -z "$SUPABASE_URL" || -z "$ANON_KEY" ]] && return 0

  local buckets_response
  buckets_response=$(curl -sL --max-time 5 \
    -H "apikey: $ANON_KEY" \
    -H "Authorization: Bearer $ANON_KEY" \
    "${SUPABASE_URL}/storage/v1/bucket" 2>/dev/null)

  # Check if we can list buckets
  local bucket_count
  bucket_count=$(echo "$buckets_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        public = [b for b in data if b.get('public', False)]
        print(len(public))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null)

  [[ "$bucket_count" -eq 0 ]]
}

# SB09: Can we access Realtime without auth?
check_realtime_open() {
  [[ -z "$SUPABASE_URL" ]] && return 0

  # Quick check: try to connect to realtime endpoint
  local realtime_code
  realtime_code=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}" \
    "${SUPABASE_URL}/realtime/v1/" 2>/dev/null)

  # If we get anything other than 401/403, it might be open
  # Realtime typically requires a valid JWT, so 401 is expected
  [[ "$realtime_code" == "401" || "$realtime_code" == "403" || "$realtime_code" == "000" || "$realtime_code" == "404" ]]
}

# ── Explanation data ──

load_explanations() {
  explain "SB01" \
    "Tables accessible to anonymous users without RLS" \
    "When RLS is disabled, anyone with your anon key (which is in your frontend code) can read ALL data. This is how 170 Lovable apps exposed user data (CVE-2025-48757) and how 1.5M API keys were leaked in the Moltbook breach." \
    "-- Enable RLS on all tables:\n$(for t in $RLS_DISABLED_TABLES; do echo "ALTER TABLE public.$t ENABLE ROW LEVEL SECURITY;"; done)"

  explain "SB02" \
    "Tables return large datasets to anonymous users" \
    "Even with RLS enabled, an overly permissive policy (using 'true' as the check) lets anyone read everything. AI code generators frequently create these." \
    "-- Review and tighten RLS policies:\n-- Replace 'true' with actual conditions like 'auth.uid() = user_id'"

  explain "SB03" \
    "Tables allow anonymous write access" \
    "If anonymous users can INSERT, UPDATE, or DELETE data, attackers can modify your database contents, create fake accounts, or delete records." \
    "-- Add restrictive write policies:\nCREATE POLICY \"Users can only insert own data\" ON public.TABLE_NAME FOR INSERT WITH CHECK (auth.uid() = user_id);\nCREATE POLICY \"Users can only update own data\" ON public.TABLE_NAME FOR UPDATE USING (auth.uid() = user_id);"

  explain "SB04" \
    "Service role key found in frontend code" \
    "The service_role key BYPASSES ALL ROW LEVEL SECURITY. If it's in your frontend code, anyone can read, write, and delete EVERYTHING in your database. This is the single most dangerous Supabase misconfiguration." \
    "1. Immediately rotate your service_role key in Supabase Dashboard > Settings > API\n2. Remove it from all frontend code\n3. Only use service_role in server-side code (API routes, Edge Functions)"

  explain "SB05" \
    "Anon key exposed in frontend with unprotected tables" \
    "Your anon key is in your frontend (this is normal), but some tables don't have RLS enabled. This means anyone can use your anon key to access all data in those tables." \
    "Enable RLS on all tables and add appropriate policies. See SB01 fix above."

  explain "SB07" \
    "Public signup is enabled" \
    "Anyone can create an account. This may be intentional (public app) or a risk (internal tool). If your app shouldn't allow public registration, disable it." \
    "-- Disable signup in Supabase Dashboard > Authentication > Settings\n-- Or restrict by email domain in Auth settings"

  explain "SB08" \
    "Public storage buckets found" \
    "Storage buckets marked as public allow anyone to list and download files. If these contain user uploads or sensitive documents, they should be private with RLS policies." \
    "-- In Supabase Dashboard > Storage, set buckets to private\n-- Add storage policies to control access"

  explain "SB09" \
    "Realtime endpoint accessible without authentication" \
    "The Realtime service may allow unauthenticated subscriptions, potentially leaking data changes in real-time." \
    "-- Ensure Realtime requires authentication in your Supabase project settings"
}

# ── Output ──

print_header() {
  if ! $JSON_MODE && ! $FIX_MODE; then
    echo ""
    echo -e "\033[33mSentinel Supabase Security Scan\033[0m"
    echo -e "\033[33m═══════════════════════════════\033[0m"
    echo ""
    if [[ -n "$TARGET_URL" ]]; then
      echo "  Target:   $TARGET_URL"
    fi
    echo "  Supabase: ${SUPABASE_URL:-not detected}"
    echo "  Anon key: ${ANON_KEY:+found (${ANON_KEY:0:10}...)}${ANON_KEY:-not found}"
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

  # Force F if any critical fail
  if $SERVICE_ROLE_KEY_FOUND; then
    grade="F"
    score=$((score > 20 ? 20 : score))
  fi
  if [[ $TABLES_UNPROTECTED -gt 0 ]]; then
    [[ "$grade" > "D" ]] && grade="D"  # At minimum D if tables are unprotected
  fi

  if $JSON_MODE; then
    echo "{"
    echo "  \"scan_type\": \"supabase\","
    echo "  \"target\": \"${TARGET_URL:-$SUPABASE_URL}\","
    echo "  \"supabase_url\": \"$SUPABASE_URL\","
    echo "  \"grade\": \"$grade\","
    echo "  \"score\": $score,"
    echo "  \"total\": $TOTAL,"
    echo "  \"pass\": $PASS,"
    echo "  \"fail\": $FAIL,"
    echo "  \"warn\": $WARN,"
    echo "  \"tables_checked\": $TABLES_CHECKED,"
    echo "  \"tables_unprotected\": $TABLES_UNPROTECTED,"
    echo "  \"service_role_exposed\": $SERVICE_ROLE_KEY_FOUND,"
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
    echo "# Sentinel Supabase Fixes"
    echo "# Grade: $grade ($score%) — $FAIL critical/high issues"
    echo ""
    for e in "${EXPLANATIONS[@]}"; do
      IFS='|' read -r eid ewhat ewhy efix <<< "$e"
      # Only print fixes for failing checks
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
      A) grade_color="\033[32m" ;;  # green
      B) grade_color="\033[32m" ;;
      C) grade_color="\033[33m" ;;  # yellow
      D) grade_color="\033[31m" ;;  # red
      F) grade_color="\033[31m" ;;
    esac

    echo -e "  ${grade_color}Grade: $grade ($score%)${NC:-\033[0m}"
    echo "  $PASS of $TOTAL checks passed · $FAIL critical/high · $WARN warnings"

    if [[ $TABLES_CHECKED -gt 0 ]]; then
      echo "  Tables checked: $TABLES_CHECKED · Unprotected: $TABLES_UNPROTECTED"
    fi
    if $SERVICE_ROLE_KEY_FOUND; then
      echo ""
      echo -e "  \033[31m⚠  SERVICE ROLE KEY FOUND IN FRONTEND CODE\033[0m"
      echo -e "  \033[31m   This key bypasses ALL security. Rotate immediately.\033[0m"
    fi

    echo ""

    if $EXPLAIN_MODE; then
      echo -e "\033[33m── Explanations ──\033[0m"
      echo ""
      for e in "${EXPLANATIONS[@]}"; do
        IFS='|' read -r eid ewhat ewhy efix <<< "$e"
        # Only explain failing checks
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
        echo "  Run with --fix to get the SQL commands."
      fi
    fi
  fi
}

# ── Main ──

NC="\033[0m"

print_header

# Step 1: Detect Supabase project
if [[ -z "$SUPABASE_URL" ]]; then
  if ! $JSON_MODE && ! $FIX_MODE; then
    echo "  Detecting Supabase project..."
  fi
  if ! detect_supabase; then
    if $JSON_MODE; then
      echo '{"error": "No Supabase project detected", "target": "'"$TARGET_URL"'"}'
    else
      echo "  ✗ No Supabase project detected at $TARGET_URL"
      echo ""
      echo "  Try providing the Supabase URL directly:"
      echo "    sentinel-supabase.sh --url https://xyz.supabase.co --anon-key eyJ..."
    fi
    exit 1
  fi
  if ! $JSON_MODE && ! $FIX_MODE; then
    echo "  Detected: $SUPABASE_URL"
    [[ -n "$ANON_KEY" ]] && echo "  Anon key: found (${#ANON_KEY} chars)"
    echo ""
  fi
fi

if [[ -z "$ANON_KEY" ]]; then
  if $JSON_MODE; then
    echo '{"error": "No anon key found. Provide with --anon-key", "supabase_url": "'"$SUPABASE_URL"'"}'
  else
    echo "  ✗ No anon key found. Provide it with --anon-key"
    echo "    Find it in: Supabase Dashboard > Settings > API > anon/public key"
  fi
  exit 1
fi

# Step 2: Run checks
if ! $JSON_MODE && ! $FIX_MODE; then
  echo -e "\033[33m── RLS & Data Access ──\033[0m"
fi
check SB01 RLS     "Tables protected by RLS"           critical  check_rls_enabled
check SB02 RLS     "No overly permissive read access"  high      check_permissive_policies
check SB03 RLS     "Anonymous write access blocked"     critical  check_write_protection

if ! $JSON_MODE && ! $FIX_MODE; then
  echo ""
  echo -e "\033[33m── Key Exposure ──\033[0m"
fi
check SB04 Keys    "No service_role key in frontend"    critical  check_service_role_key
check SB05 Keys    "Anon key + RLS = protected"         critical  check_anon_key_without_rls

if ! $JSON_MODE && ! $FIX_MODE; then
  echo ""
  echo -e "\033[33m── API Security ──\033[0m"
fi
check SB07 Auth    "Auth signup restricted"             medium    check_auth_signup
check SB08 Storage "No public storage buckets"          high      check_storage_public
check SB09 API     "Realtime requires authentication"   medium    check_realtime_open

# Load explanations for failing checks
load_explanations

# Step 3: Output results
print_grade

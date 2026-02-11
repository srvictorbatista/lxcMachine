#!/bin/bash
# /lxc_machine.sh - versão: 0.01. Cria e administra ambientes LXC + LV thin + migração rootfs + Servidor DNS
#
#
# Para edição rápida use (isto abrirá o arquivo em branco):
#    echo > /lxc_machine.sh; nano /lxc_machine.sh
#
# Realizar backup em segundo plano (mesmo após fechar terminal, ou via cron):
#     nohup /lxc_machine.sh backup <nome> > /lxc/backup/back_<nome>.log 2>&1 &
#
# Para confirmar se o backup esta em andamento, em segundo plano: 
#      ps aux | grep '[l]xc_machine.sh backup' &&  tail -f /lxc/backup/back_<nome>.log
#
#
# Para instalar o script em / (root é obrigatório). Verificando se LXC esta presente, use:
#     (dpkg -s lxc >/dev/null 2>&1 || { apt update -y >/dev/null 2>/dev/stderr && apt install lxc -y >/dev/null 2>/dev/stderr; }) && curl -sSL https://raw.githubusercontent.com/srvictorbatista/lxcMachine/refs/heads/main/lxc_machine.sh -o /lxc_machine.sh && chmod +x /lxc_machine.sh && /lxc_machine.sh start
#
#
# Para instalar LXC Clasico (apenas se necessário), use:
#    apt install lxc -y
#

set -euo pipefail && shopt -s nocasematch

# ----------------------------
# Configurações padrão
# ----------------------------
DEFAULT_MACHINE_NAME="VENERO01"
DEFAULT_MACHINE_USER="venero01"
DEFAULT_MACHINE_PASSWORD="#COLOQUEUMASENHAFORTEAQUI!!!" # <======= DEFINA UMA SENHA DEFAULT 
DEFAULT_TEMPLATE="download"
DEFAULT_DIST="ubuntu"
DEFAULT_RELEASE="jammy"
DEFAULT_ARCH="amd64"
DEFAULT_DISK="200G"          # tamanho do LV inicial
DEFAULT_RAM_MEM="4G"         # limite rígido (use 0G para ilimitado), Aplica lentidão ao atingir limite (para não comprometer o host)
DEFAULT_RAM_SWAP="0"         # limite de swap (0 para bloqueado)
VG_NAME="vg_lxc"
POOL_NAME="tp_lxc"           # thinpool já esperado no VG
LXC_BACKUP_PATH="/lxc/backup"
LXC_DIR="/lxc"
LOGDIR="/tmp"
IP_WAIT_RETRIES=60






DATATIMEZ="$(timedatectl show -p Timezone --value): $(echo Seg. Ter. Qua. Qui. Sex. Sab. Dom. | cut -d' ' -f$(date +%u)) $(date '+%d/%m/%Y  %H:%M:%S')"
DISPLAY_LXC_INFO="
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Comandos úteis e suas funções:
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 lxc start                          → Habilita e configura LXC para iniciar maquinas e aliases com auto-start neste host.
 lxc stat                           → Exibe este display, sem esperar nenhuma interação.
 lxc-ls --fancy -P ${LXC_DIR}             → Lista maquinas LXC com status, IP e outros detalhes.
 lxc-info -n <nome> -P ${LXC_DIR}         → Exibe recursos e estado da maquina.
 lxc-start -n <nome> -P ${LXC_DIR}        → Inicia maquina específica.
 lxc-stop -n <nome> -P ${LXC_DIR}         → Interrompe (desliga) maquina em execução.
 lxc-attach -n <nome> -P ${LXC_DIR}       → Acesso shell diretamente, como se fosse ssh (sem credenciais).
 lxc-freeze -n <nome> -P ${LXC_DIR}       → Salva estado (congela) a execução de todos os processos, sem desligar.
 lxc-unfreeze -n <nome> -P ${LXC_DIR}     → Retoma (descongela) a execução completa, previamente pausada.
 MENU INTERNO backups .tar.xz       → Após <nome> use [3] para criar ou [4] para restaurar backups.
 lxc backup <nome>                  → Realiza backup completo (tar.xz) de uma maquina sem acessar este display.
 lxc reborn <nome> <backup.tar.xz>  → Reconstroi uma maquina excluída, a partir de um arquivo de backup (tar.xz).
 lxc reboot <nome>                  → Reinicia a maquia, verifica integridade e acessa o terminal via lxc-attach.
 lxc boot                           → Testa/corrige inicialização do ambiente LXC.
 lxc com                            → Lista todos os domandos adicionais disponiveis no LXC Classico do host.
 lxc bin <comando>                  → Acessa LXC Classico diretamente. *Isto não é necessário para comandos com lxc-*
 lxc disc                           → Exibe resummo de discos físicos, presentes no host.
 lxc SCANER \"<portas>\" \"<faixas>\"   → Realiza scaner de rede por faixa de IPs e portas específicas.
 lvextend                           → Expande o tamanho de um volume lógico (LVM). *Consulte LXC doc/tolls.
 nano ${LXC_DIR}/<nome>/config            → Edita configurações e recursos de uma maquina manualmente.
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
\033[38;5;244;48;5;234m ${DATATIMEZ} \033[0m                                                               \033[38;5;55;244;8;5;234m Develop by: t.me/LevyMac \033[0m
"




DISPLAY_LXC_TABLE(){
  ImgSistDef=4.002
  local ROW=0 c ROOTFS info STATE CG_CPU u1 u2 CPU CG_MEM_MAX MAX_VAL RAM_RES CG_MEM MEM LV_PATH LV_TOTAL LV_USED LV_FREE LV_PERC COLOR_BG COLOR_FG DR DISK_TOTAL DISK_USED DISK_AVAIL DISK_REAL
  printf '\033[97m%-16s %-10s %-8s %-12s %-12s %-10s %-10s %-10s %-14s %-20s\033[0m\n' "NOME" "ESTADO" "CPU(s)" "RAM.MAX" "RAM.USO" "DISC.MAX" "DISC.USO" "DISC.LIVRE" "DISC.IMG" "IPV4"
  printf '\033[97m%s\033[0m\n' "───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"

  for c in $(lxc-ls -1 -P /lxc 2>/dev/null); do
    for ROOTFS in "/var/lib/lxc/$c/rootfs" "/lxc/$c/rootfs" "/srv/lxc/$c/rootfs"; do [[ -d "$ROOTFS" ]] && break || ROOTFS=""; done

    info=$(lxc-info -n "$c" -P /lxc 2>/dev/null || true)
    STATE=$(printf '%s' "$info" | awk -F: '/State:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}'); [[ -z "$STATE" ]] && STATE="N/A"

    CG_CPU="/sys/fs/cgroup/lxc.payload.$c/cpu.stat"; if [[ -f "$CG_CPU" ]]; then u1=$(awk '/usage_usec/ {print $2}' "$CG_CPU"); sleep 1; u2=$(awk '/usage_usec/ {print $2}' "$CG_CPU"); CPU=$(awk -v d="$((u2-u1))" -v n="$(nproc)" 'BEGIN{printf "%.1f%%",d/(10000*n)}'); else CPU="N/A"; fi

    CG_MEM_MAX="/sys/fs/cgroup/lxc.payload.$c/memory.max"; if [[ -f "$CG_MEM_MAX" ]]; then MAX_VAL=$(cat "$CG_MEM_MAX"); [[ "$MAX_VAL" == "max" ]] && RAM_RES="ILIMITADO" || RAM_RES=$(awk -v b="$MAX_VAL" 'BEGIN{u[1024]="Kb";u[1048576]="Mb";u[1073741824]="Gb";for(i=1073741824;i>=1024;i/=1024)if(b>=i){printf"%.2f%s",b/i,u[i];break}}'); else RAM_RES="N/A"; fi
    CG_MEM="/sys/fs/cgroup/lxc.payload.$c/memory.current"; MEM=$( [[ -f "$CG_MEM" ]] && awk '{u[1024]="Kb";u[1048576]="Mb";u[1073741824]="Gb";for(i=1073741824;i>=1024;i/=1024)if($1>=i){printf"%.2f%s",$1/i,u[i];break}}' "$CG_MEM" || echo "N/A" )
    DR=$(du -B1 -s "$ROOTFS" 2>/dev/null | awk '{print $1}')

    # Verifica se o container está rodando
    if [[ "$STATE" == "RUNNING" ]]; then
        DISK_REAL=$(awk -v b="$DR" 'BEGIN{printf"%.2fG",b/1073741824}')
        LV_PATH=$(lvs --noheadings -o lv_name,vg_name --separator '/' | awk -F/ -v c="$c" '$1=="lv_"c{print "/dev/"$2"/"$1}')
        if [[ -n "$LV_PATH" && -b "$LV_PATH" && -d "$ROOTFS" ]]; then
          LV_TOTAL=$(awk -v s="$ImgSistDef" "BEGIN{t=$(lvs --units g --nosuffix -o lv_size "$LV_PATH" | tail -n1); printf \"%.2f\",t+s}")
          LV_FREE=$(du -BG --max-depth=0 "$ROOTFS" 2>/dev/null | awk '{gsub("G","",$1); print $1}')
          LV_USED=$(awk -v t="$LV_TOTAL" -v f="$LV_FREE" 'BEGIN{printf "%.2f",t-f}')
          LV_PERC=$(awk -v u="$LV_USED" -v t="$LV_TOTAL" 'BEGIN{if(t>0) printf "%.0f",(u/t)*100; else print 0}')
          DISK_TOTAL="${LV_TOTAL}G"; DISK_USED="${LV_USED}G"; DISK_AVAIL="${LV_FREE}G"
        elif [[ -n "$ROOTFS" ]]; then
          read -r DT DU DA <<< $(df -BG --output=size,used,avail "$ROOTFS" 2>/dev/null | tail -n1)
          LV_TOTAL=$(awk -v s="$ImgSistDef" -v t="${DT//G/}" 'BEGIN{printf "%.2f",t+s}')
          LV_FREE="${DA//G/}"
          LV_USED=$(awk -v t="$LV_TOTAL" -v f="$LV_FREE" 'BEGIN{printf "%.2f",t-f}')
          LV_PERC=$(awk -v u="$LV_USED" -v t="$LV_TOTAL" 'BEGIN{if(t>0) printf "%.0f",(u/t)*100; else print 0}')
          DISK_TOTAL="${LV_TOTAL}G"; DISK_USED="${LV_USED}G"; DISK_AVAIL="${LV_FREE}G"
        else
          DISK_TOTAL="N/A"; DISK_USED="N/A"; DISK_AVAIL="N/A"; LV_PERC=0
        fi
    else
        DISK_TOTAL="N/A"; DISK_USED="N/A"; DISK_AVAIL="N/A"; LV_PERC=0
        DISK_REAL="N/A"
    fi

    

    COLOR_BG=""; COLOR_FG="\033[97m"
    if [[ "$LV_PERC" -ge 90 ]]; then COLOR_BG="\033[41m"; COLOR_FG="\033[97m"; elif [[ "$LV_PERC" -ge 70 ]]; then COLOR_FG="\033[38;2;255;140;0m"; fi
    if (( ROW++ % 2 == 0 )); then BG_ROW=$'\033[48;2;30;30;30m'; else BG_ROW=$'\033[48;2;10;10;10m'; fi
    printf '%b' "$BG_ROW"
    printf '%b%-16s %-10s %-8s %-12s %-12s %-10s %-10s %-10s %-14s %-20s\033[0m\n' "$COLOR_FG" "$c" "$STATE" "$CPU" "$RAM_RES" "$MEM" "$DISK_TOTAL" "$DISK_USED" "$DISK_AVAIL" "$DISK_REAL" "$(lxc-info -n "$c" -iH -P /lxc | grep -E '^[0-9]+\.' | grep -vE '\.0\.1$' | paste -sd',' - | tr -d '\n' || echo '[ off line ]')"

  done
}









# ----------------------------
# Funções utilitárias
# ----------------------------
RED='\033[38;5;196m'; ORANGE='\033[38;5;208m'; GREEN='\033[1;32m'; BLUE='\033[0;34m'; NC='\033[0m'
msg_info=1; msg_warn=1; msg_status=1;

info()  { [[ $msg_info  -eq 1 ]] && echo -e "${GREEN}[INFO] $*${NC}" || true; }
warn()  { [[ $msg_warn  -eq 1 ]] && echo -e "${ORANGE}[WARN] $*${NC}" || true; }
warn_info() { [[ $msg_info -eq 1 ]] && warn "$*" || true; } # Exibe este warn apenas se info também estiver ativo
status()  { [[ $msg_status  -eq 1 ]] && echo -e "${BLUE}[STATUS] $*${NC}" || true; }
error() { [[ $msg_error -eq 1 ]] && echo -e "${RED}[ERROR] $*${NC}" || true; }
err()   { echo -e "${RED}[ERRO] $*${NC}" >&2; }
pause() { read -rp "Pressione ENTER..."; }








        ###########################################################################################################
        # [AUTO-FIX BOOT] LXC + LVM após reboot - montagem segura e correção de rootfs
        ###########################################################################################################
        fixBoot(){
            # echo "Aguardando para iniciar..."; sleep 30;
            local LXC_DIR="$1" VG_NAME="$2" BACKING_FILE LOOP_DEV CONTAINERS CONTAINER_NAME LV_NAME LV_PATH ROOTFS_DIR CONFIG_FILE
            set -euo pipefail
            trap 'echo "[ERRO] Ocorreu um problema no script em linha $LINENO"; exit 1' ERR

            BACKING_FILE="$LXC_DIR/lvm_pool.img"
            mkdir -p "$LXC_DIR"
            LOOP_DEV=$(losetup -j "$BACKING_FILE" | cut -d: -f1) # Associa loop device se necessário
            [[ -z "$LOOP_DEV" ]] && LOOP_DEV=$(losetup --find --show "$BACKING_FILE") || true
            vgdisplay "$VG_NAME" &>/dev/null || vgchange -ay "$VG_NAME" &>/dev/null || { echo "[ERRO] Falha ao ativar VG $VG_NAME"; return 1; } # Ativa VG do LVM
            mapfile -t CONTAINERS < <(lxc-ls -1 -P "$LXC_DIR" 2>/dev/null) # Lista todos os containers existentes

            for c in "${CONTAINERS[@]}"; do # Monta rootfs e ajusta configs
                CONTAINER_NAME=$(echo "$c" | tr '[:lower:]' '[:upper:]')
                LV_NAME="lv_${CONTAINER_NAME,,}"
                LV_PATH="/dev/$VG_NAME/$LV_NAME"
                ROOTFS_DIR="$LXC_DIR/$CONTAINER_NAME/rootfs"
                mkdir -p "$ROOTFS_DIR"
                if [[ -b "$LV_PATH" ]]; then
                    lvdisplay "$LV_PATH" 2>/dev/null | grep -q "LV Status.*available" || lvchange -ay "$LV_PATH" &>/dev/null || { echo "[ERRO] Falha ao ativar $LV_PATH"; continue; }
                    mountpoint -q "$ROOTFS_DIR" || mount "$LV_PATH" "$ROOTFS_DIR" &>/dev/null || { echo "[ERRO] Falha ao montar $LV_PATH"; continue; }
                    chown -R root:root "$ROOTFS_DIR"; chmod -R 0755 "$ROOTFS_DIR"
                    CONFIG_FILE="$LXC_DIR/$CONTAINER_NAME/config"
                    [[ -f "$CONFIG_FILE" ]] && sed -i "s@^lxc.rootfs.path.*@lxc.rootfs.path = dir:$ROOTFS_DIR@g" "$CONFIG_FILE" || echo "lxc.rootfs.path = dir:$ROOTFS_DIR" > "$CONFIG_FILE"
                fi
            done &>/dev/null

            FAILED=0
            for c in "${CONTAINERS[@]}"; do
                CONFIG_FILE="$LXC_DIR/$c/config"
                if grep -q '^lxc.start.auto\s*=\s*1' "$CONFIG_FILE" 2>/dev/null; then
                    lxc-start -n "$c" -P "$LXC_DIR" -d &>/dev/null || { echo "[ERRO] Falha ao iniciar maquina $c"; FAILED=1; continue; }
                    sleep 2
                fi
            done

            # Se algum container falhou, aguarda e reinicia o boot
            [[ $FAILED -eq 1 ]] && (sleep 5; /lxc_machine.sh boot || true)



        }

        
        ###########################################################################################################


###########################################################################################################
# [ DNS BRIDGE ] Cria rede bridge, atribui IP, configura server DNS e resolve dominios internos
###########################################################################################################

# DNS_EXT01="8.8.8.8"; DNS_EXT02="8.8.4.4"                        # DNS Google
# DNS_EXT01="1.1.1.1"; DNS_EXT02="1.0.0.1"                        # DNS CloudFlare
# DNS_EXT01="176.103.130.130"; DNS_EXT02="176.103.130.131"        # DNS DNS-Guard
DNS_EXT01="1.1.1.1"; DNS_EXT02="1.0.0.1"; BRIDGE_NAME="lxcbr0"; HOST_IP="172.16.0.1/24"; HOST_NAME="SRV02"

hostOnlyNetWorkBridge(){
  ip link show "$BRIDGE_NAME" &>/dev/null || ip link add "$BRIDGE_NAME" type bridge
  ip link set "$BRIDGE_NAME" up
  ip addr show "$BRIDGE_NAME" | grep -q "${HOST_IP%/*}" || ip addr add "$HOST_IP" dev "$BRIDGE_NAME"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

  command -v dnsmasq >/dev/null 2>&1 || {
    DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsmasq >/dev/null 2>&1
  }

# Configura DNSMASQ apenas na interface criada:
cat >/etc/dnsmasq.d/lxcbr0.conf <<EOF
interface=${BRIDGE_NAME}                        # Escuta apenas na bridge host-only, evita interferir na rede física
bind-interfaces                                 # Força o dnsmasq a usar apenas a interface especificada
dhcp-range=172.16.0.2,172.16.0.254,12h          # Faixa de IPs que o DHCP pode fornecer aos contêineres, lease de 12h
dhcp-option=3,${HOST_IP%/*}                     # Define gateway padrão dos contêineres como IP do host (${HOST_IP%/*})
dhcp-option=6,${DNS_EXT01},${DNS_EXT02}         # Define DNS externo para os contêineres

# O parâmetro server só funciona se a variável DNS_EXT01 estiver definida; senão, comente ou use IP real
server=${DNS_EXT01}                             # DNS1 externo para resoluções de nomes fora da rede host-only. 
server=${DNS_EXT02}                             # DNS2 externo para resoluções de nomes fora da rede host-only. 

# Lista DNS de resoluções de nomes/IP fixos dentro da rede host-only (adicione quantos desejar ou comente, se preferir desabilitar)
address=/${HOST_NAME}/${HOST_IP%/*}             # Resolve ${HOST_NAME} para o IP do host (${HOST_IP%/*})
address=/seu_dominio_adicional/${HOST_IP%/*}    # Resolve dominio adicional para o IP do host

listen-address=${HOST_IP%/*}                    # Escuta apenas no IP da bridge, não nas outras interfaces do host
no-resolv                                       # Ignora /etc/resolv.conf do host, evita conflitos de DNS
no-hosts                                        # Ignora /etc/hosts do host, usa apenas as regras dnsmasq
log-queries                                     # Ativa logs de consulta DNS, útil para depuração
log-facility=/var/log/dnsmasq-lxc.log           # Define arquivo de log exclusivo para dnsmasq da bridge
EOF


# Fazer systemd-resolved ignorar a bridge criada
  mkdir -p /etc/systemd/resolved.conf.d
  cat >/etc/systemd/resolved.conf.d/no-lxcbr0.conf <<EOF
[Resolve]
DNS=
DNSStubListener=yes
ListenAddress=127.0.0.53
Domains=
MulticastDNS=no
LLMNR=no
Cache=yes
EOF
systemctl restart systemd-resolved


# Ordem de prioridade de servidores DNS (resolução de nomes)
cat >/etc/lxc/resolv-dnsmasq.conf <<EOF
# Faz com que o servidor DNSMASQ gerencie os serviços DNS deste terminal via politicas de rede
nameserver ${HOST_IP%/*}
nameserver 127.0.0.53
nameserver ${DNS_EXT01}
nameserver ${DNS_EXT02}
search .
EOF

cat >"/etc/lxc/50-${BRIDGE_NAME}.yaml" <<EOF
network:
  version: 2
  ethernets:
    eth1:
      dhcp4: true
      dhcp4-overrides: {route-metric: 5000}
EOF

# Configura symlink dentro do rootfs das maquinas
for M in $(lxc-ls -1 -P /lxc); do 
  rm -f "/lxc/$M/rootfs/etc/resolv.conf" && touch "/lxc/$M/rootfs/etc/resolv.conf" && cp "/etc/lxc/resolv-dnsmasq.conf" "/lxc/$M/rootfs/etc/resolv.conf" && cp "/etc/lxc/50-${BRIDGE_NAME}.yaml" "/lxc/$M/rootfs/etc/netplan/50-${BRIDGE_NAME}.yaml"; 
done


  # pkill dnsmasq 2>/dev/null || true; sleep 1; dnsmasq --no-daemon --conf-file=/etc/dnsmasq.d/lxcbr0.conf >/dev/null 2>&1 | awk '/error|failed|refused/i {print strftime("%Y-%m-%d %H:%M:%S"), $0}' >> /var/log/dnsmasq-lxc-errors.log & # Com captura de logs de erro para:     tail -f /var/log/dnsmasq-lxc-errors.log

  # Executa dnsmasq único, loga erros com timestamp em background. Com captura de logs de erro para:     tail -n 20 /var/log/dnsmasq-lxc-errors.log
  (flock -n /run/dnsmasq-lxc.lock -c 'pkill dnsmasq 2>/dev/null || true; sleep 1; dnsmasq --no-daemon --conf-file=/etc/dnsmasq.d/lxcbr0.conf 2>&1 | awk '\''/error|failed|refused|warning/i && !/Address already in use/ {print strftime("%Y-%m-%d %H:%M:%S"), $0}'\'' >> /var/log/dnsmasq-lxc-errors.log') & # Com captura de logs de erro para:     tail -n 20 -f /var/log/dnsmasq-lxc-errors.log
}
###########################################################################################################






#-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
### Funções para execução seletiva:
stat(){
        # ----------------------------
        # Pré checagens (status)
        # ----------------------------
        #echo -e "\n\n\033[37;44m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy)\n"
        #echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
        echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS: \033[0m\n$(lxc-ls -f -P /lxc | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
        echo -e "$(DISPLAY_LXC_TABLE)"
        echo -e "$DISPLAY_LXC_INFO"

}
disc(){
        #echo -e "\n\e[48;2;0;0;51m\e[38;2;255;255;255m  RESUMO DE DISCOS FISICOS  \e[0m"; for d in $(lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}'); do echo; printf "\033[48;5;17;38;5;15m%-12s %-20s %-6s %-20s %-28s %-10s %-25s\033[0m\n" "MONTADO" "BARRAMENTO" "TIPO" "PONTO/MONTAGEM" "ROTULO" "TAMANHO" "MODELO"; disco_modelo=$(lsblk -dn -o MODEL /dev/$d); disco_vendor=$(lsblk -dn -o VENDOR,TRAN /dev/$d | awk '{v=$1; if($2!="")v=v"-"$2; print v}'); disco_tipo=$(lsblk -dn -o ROTA /dev/$d | awk '{if($1==1) print "HDD"; else print "SSD"}'); lsblk -P -o MOUNTPOINT,LABEL,NAME,SIZE,TYPE -n /dev/$d | awk -v tipo="$disco_tipo" -v modelo="$disco_modelo" -v barr="$disco_vendor" '{mnt="não"; rotulo=""; size=""; ponto="-"; part=""; mp=""; for(i=1;i<=NF;i++){gsub(/"/,"",$i); split($i,a,"="); if(a[1]=="MOUNTPOINT") mp=a[2]; if(a[1]=="LABEL") rotulo=a[2]; if(a[1]=="NAME" && rotulo=="") rotulo=a[2]; if(a[1]=="SIZE") size=a[2]; if(a[1]=="TYPE") part=a[2]} if(part=="disk"){printf "\033[32m%-12s %-20s %-6s %-20s %-28s %-10s %-25s\033[0m\n","Fisicamente",barr,tipo,"-",rotulo,size,modelo}else{prefix="*(p) "; rotulo=prefix rotulo; if(mp!=""){mnt="sim"; ponto=mp} lines[++c]=sprintf("%-12s %-20s %-6s %-20s %-28s %-10s %-25s",mnt,barr,tipo,ponto,rotulo,size,modelo)}} END{for(i=1;i<=c;i++){if(i%2==0){printf "\033[48;5;236;38;5;188m%s\033[0m\n",lines[i]}else{printf "\033[48;5;0;38;5;188m%s\033[0m\n",lines[i]}}}'; done
        echo -e "\n\e[48;2;0;0;51m\e[38;2;255;255;255m  RESUMO DE DISCOS FISICOS  \e[0m"; for d in $(lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}'); do printf "\033[48;5;17;38;5;15m%-12s %-20s %-6s %-20s %-28s %-10s %-25s\033[0m\n" "MONTADO" "BARRAMENTO" "TIPO" "PONTO/MONTAGEM" "ROTULO" "TAMANHO" "MODELO"; disco_modelo=$(lsblk -dn -o MODEL /dev/$d); disco_vendor=$(lsblk -dn -o VENDOR,TRAN /dev/$d | awk '{v=$1; if($2!="")v=v"-"$2; print v}'); disco_tipo=$(lsblk -dn -o ROTA /dev/$d | awk '{if($1==1) print "HDD"; else print "SSD"}'); lsblk -P -o MOUNTPOINT,LABEL,NAME,SIZE,TYPE -n /dev/$d | awk -v tipo="$disco_tipo" -v modelo="$disco_modelo" -v barr="$disco_vendor" '{mnt="não"; rotulo=""; size=""; ponto="-"; part=""; mp=""; for(i=1;i<=NF;i++){gsub(/"/,"",$i); split($i,a,"="); if(a[1]=="MOUNTPOINT") mp=a[2]; if(a[1]=="LABEL") rotulo=a[2]; if(a[1]=="NAME" && rotulo=="") rotulo=a[2]; if(a[1]=="SIZE") size=a[2]; if(a[1]=="TYPE") part=a[2]} if(part=="disk"){printf "\033[32m%-12s %-20s %-6s %-20s %-28s %-10s %-25s\033[0m\n","Fisicamente",barr,tipo,"-",rotulo,size,modelo}else{prefix="*(p) "; rotulo=prefix rotulo; if(mp!=""){mnt="sim"; ponto=mp} lines[++c]=sprintf("%-12s %-20s %-6s %-20s %-28s %-10s %-25s",mnt,barr,tipo,ponto,rotulo,size,modelo)}} END{for(i=1;i<=c;i++){if(i%2==0){printf "\033[48;5;236;38;5;188m%s\033[0m\n",lines[i]}else{printf "\033[48;5;0;38;5;188m%s\033[0m\n",lines[i]}}}'; done
        exit 1
}
boot(){
    # Para vericicar o boot, use:
    ## systemctl status lxc-machine-boot.service &&  echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls -f -P /lxc | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"

    hostOnlyNetWorkBridge

    fixBoot $LXC_DIR $VG_NAME



    echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls -f -P /lxc | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"

    # Interrompe a execução após executar [AUTO-FIX BOOT]
    echo "Boot executado com sucesso."

    info "limpando backups excessivos..."
    rm -rf /var/lib/lxc/*.bak*
}
reboot(){
      MACHINE_NAME="${1:-}"   # Garante que não seja "unbound"
      MACHINE_NAME="${MACHINE_NAME^^}"      # Converte para maiúsculas

        # Verifica se foi informado o nome da máquina
        if [ -z "$MACHINE_NAME" ]; then            
            echo -e "\n\033[1;93m\033[40m[INFO] Para gerar um backup com este comando, o nome da máquina é obrigatório. \033[0m "; return 1
        fi

        # Verifica se a máquina existe
        if [ ! -d "$LXC_DIR/$MACHINE_NAME" ]; then
            echo -e "${RED}[ERRO] Máquina \"$MACHINE_NAME\" não localizada. ${NC} \n"; return 1
        fi


        #REINICIO COMOPLETO E ENTRADA
        echo -e "\nReiniciando ${MACHINE_NAME}: \nAo concluir, o terminal de ${MACHINE_NAME} será aberto. \nPor favor, aguarde... \n"
        lxc-stop -n "$MACHINE_NAME" -P "$LXC_DIR" || true && lxc-start -n "$MACHINE_NAME" -P "$LXC_DIR" || true && lxc-unfreeze -n "$MACHINE_NAME" -P "$LXC_DIR" && sleep 30; lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR";
        exit 1
}
start(){ 
    echo "Start (implementando LXC no Boot)"; 
    ###########################################################################################################
    # [AUTO-FIX] BOOT de inicialização antes do systemd LXC 

    # Cria a service systemd para preparar storage antes do LXC
    cat << 'EOF' > /etc/systemd/system/lxc-machine-boot.service
[Unit]
Description=Prepara storage LXC (loop + LVM) após boot completo do host
After=multi-user.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/lxc_machine.sh boot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Ajusta permissões do script principal
    chmod 750 /lxc_machine.sh
    chown root:root /lxc_machine.sh

    # Atualiza systemd e habilita a unit corretamente
    systemctl daemon-reload
    systemctl enable lxc-machine-boot.service

    # Aguarda systemd registrar a unit
    for i in {1..5}; do
        systemctl list-unit-files | grep -q '^lxc-machine-boot.service' && break
        sleep 0.5
    done

    # Verifica se a unit existe e está habilitada
    if systemctl is-enabled --quiet lxc-machine-boot.service; then
        echo -e "${GREEN} [OK] Unit criada e habilitada: lxc-machine-boot.service ${NC}"
        echo -e "${GREEN} [OK] Ordem de boot garantida: storage preparado antes do LXC ${NC}"
    else
        echo -e "${RED} [ERRO] Unit NÃO encontrada ou NÃO habilitada: lxc-machine-boot.service ${NC}"
        echo -e "${RED} [ERRO] Risco de falha no boot do LXC por storage indisponível ${NC}"
        echo -e "${ORANGE} [AÇÃO] Execute manualmente: systemctl enable lxc-machine-boot.service ${NC}"
    fi
    ###########################################################################################################


    #echo -e "# Alias LXC \nalias lxc='/lxc_machine.sh'\nalias LXC='/lxc_machine.sh'\n\n\n\n\n\n" >> /root/.bashrc

    echo -e "# Alias LXC (alias \"especial\")\nlxc(){\n    if [[ "\$1" == \"bin\" ]]; then\n        shift\n        /usr/bin/lxc \"\$@\"   # Alias lxc binario clássico (lxc bin)\n    else\n        /lxc_machine.sh \"\$@\"  # Alias gestor de conteiners (lxc)\n    fi\n}\nLXC(){ lxc \"\$@\"; }\n\n\n\n\n\n" >> /root/.bashrc

    source /root/.bashrc
    exit 1
}
clearing(){ 
      ## Verificar volumes logicos
      # lvs -o +data_percent,metadata_percent vg_lxc/tp_lxc && vgs vg_lxc && lvs -a -o +devices vg_lxc && lvs -a -o lv_name,origin,lv_size,data_percent,metadata_percent vg_lxc
      # Limpeza de LV e thin pools órfãos
      for lv in $(lvs -o lv_name --noheadings vg_lxc | tr -d ' '); do
          if ! lxc-ls -f -P /lxc | grep -q "$lv"; then
              lvremove -f /dev/vg_lxc/$lv && echo "LV $lv removido" || echo -e "${RED} [ERRO] Falha ao remover LV $lv ${NC}"
          fi
      done

      # Opcional: remover thin pool se não houver LV associado
      for tp in $(lvs -S lv_attr=twi--o-- --noheadings -o lv_name vg_lxc | tr -d ' '); do
          lv_count=$(lvs --noheadings -o lv_name vg_lxc | grep -v "$tp" | wc -l)
          if [[ $lv_count -eq 0 ]]; then
              lvremove -f /dev/vg_lxc/$tp && echo "Thin pool $tp removido" || echo -e "${RED} [ERRO] Falha ao remover thin pool $tp ${NC}"
          fi
      done

      echo "Lv e Tp limpos com sucesso!"

      exit 0
}
backup(){
      MACHINE_NAME="${1:-}"   # Garante que não seja "unbound"
      MACHINE_NAME="${MACHINE_NAME^^}"      # Converte para maiúsculas

        LXC_BACKUP_FILE="${LXC_BACKUP_PATH}/${MACHINE_NAME}-backup-$(date +%F).tar.xz"
        CONFIG_FILE="/lxc/backup/${MACHINE_NAME}_config"
        METADATA_FILE="/lxc/backup/metadata.yaml"
        ACTIVE_FILE="/lxc/backup/active"



        # Verifica se foi informado o nome da máquina
        if [ -z "$MACHINE_NAME" ]; then

            # LISTA BACKUPS DISPONIVEIS 
            [ -d "$LXC_BACKUP_PATH" ] && [ "$(ls -A "$LXC_BACKUP_PATH" 2>/dev/null)" ] && { echo -e "\nBACK-UPs DISPONIVEIS:"; ls -lh --color=never "$LXC_BACKUP_PATH" | awk 'NR>1{bg=(NR%2? "\033[48;2;30;30;30m":"\033[48;2;10;10;10m"); printf "* %s'"$LXC_BACKUP_PATH"'/%s (%s)\033[0m\n", bg,$9,$5}'; } || echo -e "\n${RED}[ERRO] Diretório ${LXC_BACKUP_PATH} inexistente ou vazio. ${NC}"
            
            echo -e "\n\033[1;93m\033[40m[INFO] Para gerar um backup com este comando, o nome da máquina é obrigatório. \033[0m "; return 1
        fi

        # Verifica se foi informado o local do backup
        if [ -z "$LXC_BACKUP_PATH" ]; then
            echo -e "${RED}[ERRO] Backup path é obrigatório. ${NC} \n"; return 1
        fi

        # Verifica se a máquina existe
        if [ ! -d "$LXC_DIR/$MACHINE_NAME" ]; then
            echo -e "${RED}[ERRO] Máquina '$MACHINE_NAME' inexistente em $LXC_DIR. ${NC} \n"; return 1
        fi


        [ -r "/lxc/$MACHINE_NAME/config" ] && cp "/lxc/$MACHINE_NAME/config" "$CONFIG_FILE"



        #-- ----------------------------------------------------
        # valores extraídos do config com defaults
        MACHINE_HOSTNAME=$(grep -E '^lxc\.uts\.name|^lxc\.hostname' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs||echo "$MACHINE_NAME")
        MACHINE_BRIDGE=$(grep '^lxc.net.0.link' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs||echo "lxcbr0")
        MACHINE_MEMORY=$(grep '^lxc.cgroup2.memory.max' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs|tr -d '\n'||echo "2048M")
        MACHINE_CPU=$(grep '^lxc.cgroup2.cpu.max' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs|cut -d' ' -f1|tr -d '\n'||echo "2")
        MACHINE_OS=$(grep '^lxc.os' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs|tr -d '\n'||echo "ubuntu")
        MACHINE_RELEASE=$(grep '^lxc.release' "$CONFIG_FILE" 2>/dev/null|cut -d= -f2|xargs|tr -d '\n'||echo "22.04")
        MACHINE_ARCH=$(uname -m); MACHINE_ARCH=${MACHINE_ARCH/x86_64/amd64}; MACHINE_ARCH=${MACHINE_ARCH/aarch64/arm64}
        MACHINE_LXC_VERSION=$(lxc-checkconfig 2>/dev/null|grep 'LXC version'|awk '{print $NF}'|tr -d '\n'||echo "6.x")

        #-- ----------------------------------------------------


# metadata.yaml completo
cat > "$METADATA_FILE" <<EOF
architecture: $MACHINE_ARCH
creation_date: $(date +%s)
creation_date_human: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
properties:
  description: $MACHINE_NAME em $(date +"%d/%m/%Y as %H:%M:%S")
  os: $MACHINE_OS
  release: $MACHINE_RELEASE
  template: local
  template_version: 1.0
  hostname: $MACHINE_HOSTNAME
  lxc_version: $MACHINE_LXC_VERSION
  cgroup_controllers: cpu,memory,blkio
  limits:
    cpu: $MACHINE_CPU
    memory: $MACHINE_MEMORY
  network:
    type: veth
    link: $MACHINE_BRIDGE
    flags: up
  root_uid: 0
  root_gid: 0
EOF

        START_TIME=$(date +%s)
        

        echo -e "\nPausando serviços e preparando backup: "

        # Cria diretório padrão de backup seguro
        # mkdir -p "$LXC_BACKUP_PATH" && chown root:root "$LXC_BACKUP_PATH" && chmod 700 "$LXC_BACKUP_PATH"
        [ "$LXC_BACKUP_PATH" != "/lxc/backup" ] && mkdir -p "$LXC_BACKUP_PATH" && chmod 700 "$LXC_BACKUP_PATH"
        mkdir -p "/lxc/backup" && chown root:root "/lxc/backup" && chmod 700 "/lxc/backup" || true

        #-- -----------------------------------------------------------------------------------------------------------
        # Captura containers Docker ativos (NOMES, não IDs)
        { echo "# $MACHINE_NAME: Containers Docker ativos em $(date +"%d/%m/%Y as %H:%M:%S")"; lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -c "docker ps --format '{{.Names}}'" 2>/dev/null || :; } > "$ACTIVE_FILE"


        # Captura os containers Docker ativos (NOMES, não IDs) contidos em $ACTIVE_FILE e popula em um array
        mapfile -t ACTIVE_CONTAINERS < <(grep -Ev '^[[:space:]]*(#|$)' "$ACTIVE_FILE") || ACTIVE_CONTAINERS=()


        #echo "Containers Docker ativos: ${ACTIVE_CONTAINERS[*]:-Nenhum}"

        # Para containers Docker ativos, exibindo apenas status resumido
        for CNAME in "${ACTIVE_CONTAINERS[@]}"; do
            lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- docker stop "$CNAME" &>/dev/null && echo -e "Parando Docker: ${CNAME} " || echo -e "${RED}[ERRO] Falha ao parar: ${CNAME} ${NC} \n"
        done


        #-- -----------------------------------------------------------------------------------------------------------
        # Congela LXC apenas após Docker parado
        lxc-freeze -n "$MACHINE_NAME" -P "$LXC_DIR" || { echo -e "${RED}[ERRO] Falha ao congelar LXC \"$MACHINE_NAME\" ${NC}"; exit 1; }


        echo -e "\nGerando arquivo de restauração: \n* \"${LXC_BACKUP_FILE}\" \nProcesso iniciado em $(date '+%F %T'). Isto pode levar vários minutos. \nPor favor, aguarde... \n"

        # Backup consistente do filesystem (silencioso, mostra logs apenas se falhar)
        if ! (umask 177 && umask 177 && tar -cJf "$LXC_BACKUP_FILE" -C "$(dirname "$METADATA_FILE")" "$(basename "$METADATA_FILE")" "$(basename "$CONFIG_FILE")" "$(basename "$ACTIVE_FILE")" -C "$LXC_DIR/$MACHINE_NAME/rootfs" . &>/dev/null); then
            [ -s /tmp/metadata.yaml ] || { echo -e "${RED}[ERRO] metadata.yaml ausente ou vazio ${NC}"; lxc-unfreeze -n "$MACHINE_NAME" -P "$LXC_DIR"; sleep 2; exit 1; }
            echo -e "${RED}[ERRO] Falha ao gerar backup. Saída do tar:"
            umask 177 && umask 177 && tar -cJf "$LXC_BACKUP_FILE" -C "$(dirname "$METADATA_FILE")" "$(basename "$METADATA_FILE")" "$(basename "$CONFIG_FILE")" "$(basename "$ACTIVE_FILE")" -C "$LXC_DIR/$MACHINE_NAME/rootfs"
            echo -e "${NC}"
            lxc-unfreeze -n "$MACHINE_NAME" -P "$LXC_DIR"; sleep 2
            [ -n "$METADATA_FILE$ACTIVE_FILE" ] && rm -f "$METADATA_FILE" "$CONFIG_FILE" "$ACTIVE_FILE" # remove arquivos temp
            exit 1
        fi



        lxc-unfreeze -n "$MACHINE_NAME" -P "$LXC_DIR"; sleep 2

        # Reinicia containers Docker
        for CNAME in "${ACTIVE_CONTAINERS[@]}"; do
            lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- docker start "$CNAME" &>/dev/null && echo "Retomando Docker: $CNAME " || echo -e "${RED}[ERRO] Falha ao iniciar: $CNAME ${NC}"
        done

        # Examina o arquivo gerado sem abri-lo (verificação rápida)
        tar -tJf "$LXC_BACKUP_FILE" >/dev/null || { echo -e "${RED}[ERRO] O arquivo de backup gerado esta corrompido ou inválido. ${NC}"; exit 1; }
        [ -n "$METADATA_FILE$ACTIVE_FILE" ] && rm -f "$METADATA_FILE" "$CONFIG_FILE" "$ACTIVE_FILE" # remove arquivos temp

        END_TIME=$(date +%s)
        DURATION=$((END_TIME-START_TIME))
        printf "\033[38;2;144;238;144m\033[48;2;20;20;20m Backup concluído em %s (Duração: %02d:%02d:%02d) \n\n\033[0m" "$(date '+%F %T')" $((DURATION/3600)) $((DURATION%3600/60)) $((DURATION%60))
        #-- -----------------------------------------------------------------------------------------------------------
        exit 0
}
reborn(){
      MACHINE_NAME="${1:-}"   # Garante que não seja "unbound"
      MACHINE_NAME="${MACHINE_NAME^^}"      # Converte para maiúsculas

      LXC_BACKUP_FILE="${2:-}"

        ###########################################################################################
        # Recriação direta (verosa):
        #      lxc-create -n "KAMAKISHIA" -P "/lxc" -t local -- -f "/lxc/backup/KAMAKISHIA-backup-2026-02-02.tar.xz"
        #
        # Recriação direta (discreta):
        #      OUTPUT="$(lxc-create -n "KAMAKISHIA" -P "/lxc" -t local -- -f "/lxc/backup/KAMAKISHIA-backup-2026-02-02.tar.xz" 2>&1)" || echo "[ERRO] Falha ao criar container: $OUTPUT"
        #
        # Restaura config ao seu lugar original
        #      mv -f /lxc/KAMAKISHIA/rootfs/KAMAKISHIA_config /lxc/KAMAKISHIA/config &>/dev/null
        #
        # Remove arquivo de Meta Data
        #      rm -f /lxc/KAMAKISHIA/rootfs/metadata.yaml &>/dev/null
        #
        ###########################################################################################

        # Verifica se foi informado o nome da máquina
        if [ -z "$MACHINE_NAME" ]; then
            echo -e "\n\033[1;93m\033[40m[INFO] Para usar este comando, o nome da máquina é obrigatório. \033[0m "; return 1
        fi

        # Verifica se a máquina existe
        if [ -d "$LXC_DIR/$MACHINE_NAME" ]; then
            echo -e "${RED}[ERRO] Máquina '$MACHINE_NAME' já existe! \n       Por isso, não pode ser recriada. ${NC} \n"; exit 1
        fi

        # Verifica se foi informado o arquivo de backup
        if [ -z "$LXC_BACKUP_FILE" ]; then
            echo -e "${RED}[ERRO] <Backup>.tar.xz é obrigatório. ${NC} \n"; return 1
        fi

        # Verifica se o arquivo tar.gz existe e é regular
        if [ ! -f "$LXC_BACKUP_FILE" ]; then
            echo -e "${RED}[ERRO] Arquivo '$LXC_BACKUP_FILE' não foi encontrado. ${NC}"
            exit 1
        fi
 
        START_TIME=$(date +%s)
        echo "Verificando integridade do arquivo de backup..."

        # Verifica se é um arquivo tar válido e íntegro: Verificando se existe a pasta /etc dentro de qualquer subdiretório
        if ! tar -tJf "$LXC_BACKUP_FILE" | awk '{if($0 ~ /.\/etc\/$/) found=1} END{exit !found}'; then
            echo -e "${RED}[ERRO] Arquivo \"$LXC_BACKUP_FILE\" não é um tar.xz válido ou está corrompido. ${NC}"
            exit 1
        fi
        #echo "Verificação concluída."

# ETAPA DE CRIAÇÃO E PRIMEIRO ARRANQUE DO CONTÊINER
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

# ----------------------------
# Criação do container LXC sobre LV thin com rootfs válido
# ----------------------------

LV_NAME="lv_${MACHINE_NAME,,}"
DEST_DIR="$LXC_DIR/$MACHINE_NAME"
ROOTFS_DIR="$DEST_DIR/rootfs"
TMP_NAME="${MACHINE_NAME}_tmp"

# diagnóstico preventivo
if mountpoint -q "$ROOTFS_DIR" 2>/dev/null; then
    echo -e "${RED}[ERRO] rootfs já está montado. Estado inconsistente detectado. ${NC}"
    exit 1
fi

# cria diretório seguro
mkdir -p "$ROOTFS_DIR"

# remove LV anterior se existir
lvremove -f /dev/$VG_NAME/$LV_NAME >/dev/null 2>&1 || true

# cria LV thin
LV_CREATE_OUTPUT=$(lvcreate -V "$DEFAULT_DISK" -T "$VG_NAME/$POOL_NAME" -n "$LV_NAME" 2>&1) || { echo -e "${RED}[ERRO] Falha ao criar LV thin $LV_NAME ${NC}"; exit 1; }

# captura warning (não interrompe)
LV_TOTAL_REQUIRED=$(echo "$LV_CREATE_OUTPUT" | grep "Sum of all thin volume sizes" | sed -E 's/.*\(([0-9.]+) GiB\).*/\1/') || true

# aborta apenas se exceder pool
# verifica warnings de thin pool
if echo "$LV_CREATE_OUTPUT" | grep -q "exceeds the size of thin pool"; then
    POOL_SIZE=$(lvs --units g --nosuffix -o lv_size /dev/$VG_NAME/$POOL_NAME | tail -n1)
    VG_SIZE=$(vgs --units g --nosuffix -o vg_size /dev/$VG_NAME | tail -n1)
    echo -e "${RED}[ERRO] \nThin pool $POOL_NAME insuficiente para alocar $DEFAULT_DISK.\n"\
"Thin pool atual:             $POOL_SIZE GiB\n"\
"Volume group atual:          $VG_SIZE GiB\n"\
"VG minimo esperado:            $LV_TOTAL_REQUIRED GiB\n"\
"A soma de thin LVs solicitados excede a capacidade do pool/volume group. ${NC}\n"\
"${ORANGE}[AÇÃO] \nPor favor, verifique os volumes logicos ou expanda manualmente o thin pool antes de continuar:\n"\
"[VERIFICAR VOLUMES]: lvs -o +data_percent,metadata_percent vg_lxc/tp_lxc && vgs vg_lxc && lvs -a -o +devices vg_lxc && lvs -a -o lv_name,origin,lv_size,data_percent,metadata_percent vg_lxc \n"\
"realizar limpeza de Volume group e Thin pools ofãos ( lxc clearing ) \n"\
"1) Expandir o VG (ex: 'lvextend -L+100G $VG_NAME/$POOL_NAME') ou adicionar PVs ao VG\n"\
"2) Ajustar thin pool se necessário (ex: 'lvextend -L+100G $VG_NAME/$POOL_NAME')\n"\
"Após expansão, execute o script novamente. ${NC}"
    exit 1
fi

# formata LV thin
mkfs.ext4 -F "/dev/$VG_NAME/$LV_NAME" &>/dev/null || { echo -e "${RED}[ERRO] Falha ao formatar LV $LV_NAME ${NC}"; exit 1; }

# monta LV thin
mount "/dev/$VG_NAME/$LV_NAME" "$ROOTFS_DIR" &>/dev/null || { echo -e "${RED}[ERRO] Falha ao montar LV $LV_NAME ${NC}"; exit 1; }

# path seguro para LXC
export LXC_LXCPATH="$LXC_DIR"

echo -e "${BLUE}[STATUS] Criando ambiente para popular rootfs... ${NC}"

# cria container temporário
OUTPUT="$(lxc-create -n "$TMP_NAME" -P "$LXC_DIR" -t local -- -f "$LXC_BACKUP_FILE" 2>&1)" || echo -e "${RED}[ERRO] Falha ao criar $TMP_NAME: $OUTPUT ${NC}"


echo -e "${BLUE}[STATUS] Populando dados para LV thin...${NC}"

# copia rootfs
rsync -aHAX --numeric-ids --exclude=/proc --exclude=/sys --exclude=/dev/pts --exclude=/tmp "$LXC_DIR/$TMP_NAME/rootfs/" "$ROOTFS_DIR/"

# remove container temporário
lxc-destroy -n "$TMP_NAME" -P "$LXC_DIR"

# cria devices essenciais
mkdir -p "$ROOTFS_DIR/dev"
mknod -m 666 "$ROOTFS_DIR/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/zero" c 1 5 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/random" c 1 8 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/urandom" c 1 9 2>/dev/null || true
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@





        # Restaura config ao seu lugar original
        mv -f "${LXC_DIR}/${MACHINE_NAME}/rootfs/${MACHINE_NAME}_config" "${LXC_DIR}/${MACHINE_NAME}/config" &>/dev/null

        # Remove arquivo de Meta Data
        rm -f "${LXC_DIR}/KAMAKISHIA/rootfs/metadata.yaml" &>/dev/null

        # Configura symlink dentro do rootfs das maquinas
        #for c in "$LXC_DIR"/*/rootfs/etc/resolv.conf; do rm -f "$c" && touch "$c"; done
        rm "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
        touch "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
        cp "/etc/lxc/resolv-dnsmasq.conf" "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
        cp "/etc/lxc/50-${BRIDGE_NAME}.yaml" "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/netplan/50-${BRIDGE_NAME}.yaml"
        sleep 1

        lxc-start -n "$MACHINE_NAME" -P "$LXC_DIR" &>/dev/null; sleep 5



        END_TIME=$(date +%s)
        DURATION=$((END_TIME-START_TIME))
        printf "\033[38;2;144;238;144m\033[48;2;20;20;20m Recriação concluída em %s (Duração: %02d:%02d:%02d) \n\n\033[0m" "$(date '+%F %T')" $((DURATION/3600)) $((DURATION%3600/60)) $((DURATION%60))

        exit 1
}
com(){
        echo -e "\n\e[48;2;0;0;51m\e[38;2;255;255;255m  COMANDOS DISPONIVEIS PELO BINARIO LXC \e[0m";
        ls /usr/bin/lxc* | sed 's|/usr/bin/||; s|^| |; s|$| |' | column -c 100 | while read -r line; do echo -e "\e[32;48;5;233m$line\e[0m"; done
        exit 0
}



SCANER(){
        local PORTAS_IN FAIXAS_IN PORTS_CSV SPIN_PID OUTPUT LINES F
        set +m; PORTAS_IN=${1:-'22 2222'}; FAIXAS_IN=${2:-'172.16.0'}; set -m
        
        read -r -a PORTAS <<< "$(printf '%s\n' "${PORTAS_IN//,/ }" | tr -cs '0-9' ' ' || echo "$SDEFAULT_PORT")"; PORT=$(IFS=' '; echo "${PORTAS[*]}")
        readarray -t FAIXAS < <(for f in ${FAIXAS_IN//,/ }; do OCT=(); for o in ${f//./ }; do n=$(echo "$o" | tr -cd '0-9' | cut -c1-3); [ -n "$n" ] && OCT+=("$n"); [ "${#OCT[@]}" -ge 3 ] && break; done; [ "${#OCT[@]}" -gt 0 ] && echo "${OCT[0]:-0}.${OCT[1]:-0}.${OCT[2]:-0}"; done); [ "${#FAIXAS[@]}" -eq 0 ] && read -r -a FAIXAS <<< "$SDEFAULT_FAIX"; FAIX=$(IFS=' '; echo "${FAIXAS[*]}")
        #echo -e "PORTAS: $PORT"; echo -e "FAIXAS: $FAIX"
        echo -e ""; ( while :; do printf "\033[48;5;208;30m    ESCANEANDO...  \033[0m\r"; sleep 0.11; printf "                    \r"; sleep 0.11; done ) & SPIN_PID=$!
        trap 'kill "${SPIN_PID}" 2>/dev/null || true; wait "${SPIN_PID}" 2>/dev/null || true' INT TERM EXIT; command -v nmap >/dev/null 2>&1 || { DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap >/dev/null 2>&1; }; PORTS_CSV=$(printf "%s," "${PORTAS[@]}"); PORTS_CSV="${PORTS_CSV%,}"
        declare -A TABLE
        for F in "${FAIXAS[@]}"; do TABLE["$F"]=$(printf "\033[48;5;52;38;5;250m %-66s\033[0m" "FAIXA $F.0/24 INEXISTENTE OU INACESSIVEL"); done
        for F in "${FAIXAS[@]}"; do
          OUTPUT=$(nmap -Pn -n -p"$PORTS_CSV" "$F.0/24" -oG - 2>/dev/null)
          LINES=$(awk -v PORTAS="${PORTAS[*]}" '
            BEGIN{split(PORTAS,pl," "); for(i in pl) hdr[pl[i]]="-"; r=0}
            /^Host:/{ ip=$2; name=$3; gsub(/[()]/,"",name); split($0,a,"Ports: "); ports=(length(a)>1?a[2]:"")
              for(i in hdr) hdr[i]="-"
              if(ports!=""){ np=split(ports,ps,","); for(j=1;j<=np;j++){ gsub(/^ +| +$/,"",ps[j]); split(ps[j],f,"/"); if(f[2]=="open") for(i in hdr) if(f[1]==i) hdr[i]="DISPONIVEL" } }
              openCount=0; for(i in hdr) if(hdr[i]!="-") openCount++
              if(openCount>0){
                if(name==""||name=="?") name=ip
                color=(openCount==1?"\033[48;5;16;90m":(++r%2?"\033[48;5;236;37m":"\033[48;5;235;37m"))
                line=sprintf("%s %-18s",color,name)
                for(i in hdr) line=line sprintf(" | %-12s",hdr[i])
                print line sprintf(" | %-15s\033[0m",ip)
              }
            }' <<< "$OUTPUT")
          [ -n "$LINES" ] && TABLE["$F"]="$LINES"
        done
        kill "${SPIN_PID}" 2>/dev/null || true; wait "${SPIN_PID}" 2>/dev/null || true; trap - INT TERM EXIT
        echo -ne "                    \r"
        printf "\033[48;5;17;37m DISPOSITIVOS ENCONTRADOS \033[0m\n\033[48;5;236;37m %-18s" "HOST"
        for P in "${PORTAS[@]}"; do printf " | %-12s" "PORT $P"; done
        printf " | %-15s\033[0m\n" "IPv4"
        for F in "${FAIXAS[@]}"; do echo -e "${TABLE[$F]}"; done
        echo; exit 0
}




#-- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

ask_default(){ local p="$1"; local d="$2"; read -rp "$p [$d]: " v; echo "${v:-$d}"; }
#ask_password(){ local prompt="$1"; local a b; while true; do read -rsp "$prompt: " a; echo; read -rsp "Confirme: " b; echo; [[ "$a" == "$b" ]] && break || echo "[ERRO] Senhas não coincidem."; done; echo "$a"; }
ask_password(){ local p="$1" a b; while true; do read -rsp "$p: " a; echo; [[ -z "$a" ]]&&{ echo "[ERRO] Senha não pode ser vazia."; continue; }; read -rsp "Confirme: " b; echo; [[ "$a" == "$b" ]]&&break||echo "[ERRO] Senhas não coincidem."; done; printf '%s' "$a"; unset a b; }


mask_pwd_display(){ [[ "$1" == "$DEFAULT_MACHINE_PASSWORD" ]] && echo "<senha_padrao>" || echo "$1"; }
mask_pwd(){ [[ "$1" == "$DEFAULT_MACHINE_PASSWORD" ]] && echo "<senha_padrao>" || printf '%*s' "${#1}" '' | tr ' ' '*'; }

wait_for_ssh() {
  local ip="$1"; status "Aguardando SSH em $ip:22 ..."
  for i in $(seq 1 $IP_WAIT_RETRIES); do
    if nc -z -w2 "$ip" 22 &>/dev/null; then echo "[OK] SSH disponível em $ip"; return 0; fi
    sleep 2
  done
  err "SSH não respondeu em $IP dentro do tempo."
  return 1
}







###########################################################################################################
#----------------------------
# Execução seletiva por variaval de evocação (antes da primeira interação)
#----------------------------
#[[ -n "$1" ]] && declare -F "$1" >/dev/null && { "$1"; exit 0; }; [[ -n "$1" ]] && { echo "Uso: $0 {stat|disc|boot|reboot|start|clearing|backup|reborn|com|SCANER}"; exit 1; }
case "${1-}" in
  stat|disc|boot|reboot|start|clearing|backup|reborn|com|SCANER) "$1" "${@:2}"; exit 0 ;;
  "") ;;
  *) stat; echo -e "${RED} [ERRO] Rota ou função não mapeada: ${NC} \n${ORANGE} Use: $0 {stat|disc|boot|reboot|start|clearing|backup|reborn|com|SCANER} ou <vazio> ${NC} \n\n"; exit 1 ;;
esac
###########################################################################################################


# ----------------------------
# Pré checagens
# ----------------------------
#echo -e "\n\n\033[37;44m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy)\n"
#echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls -f -P $LXC_DIR | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
echo -e "$(DISPLAY_LXC_TABLE)"
echo -e "$DISPLAY_LXC_INFO"

#echo -e "Se desejar use \"Ctrl+C\" para sair\n\n\n"
echo -e "\033[97;48;5;94m Se desejar use \"Ctrl+C\" para sair \033[0m\n\n\n"


if [[ "$(id -u)" -ne 0 ]]; then err "Execute como root"; exit 1; fi
mkdir -p "$LXC_DIR"








# ----------------------------
# Interação inicial
# ----------------------------
echo -e "\n=== Iniciando... / Configuração de Cluster LXC ==="
MACHINE_NAME=$(ask_default "Nome da maquina" "$DEFAULT_MACHINE_NAME")
MACHINE_USER=$(ask_default "Usuário padrão" "$DEFAULT_MACHINE_USER")
echo -e "\nSenha sugerida: \033[37;48;2;35;35;35m $(tr -dc 'A-Z1-9#!\$%&*' </dev/urandom | head -c 16) \033[0m \033[1;93m\033[40m Digite ou cole para usar esta sugestão. \033[0m"
read -rsp "Senha (ENTER para padrão): " first; echo
if [[ -z "$first" ]]; then
    MACHINE_PASSWORD="$DEFAULT_MACHINE_PASSWORD"
else
    while true; do
        read -rsp "Confirme: " second; echo
        if [[ "$first" == "$second" ]]; then MACHINE_PASSWORD="$first"; break
        else
            echo -e "\e[41;97m [ERRO] Senhas não coincidem. Tente novamente. \e[0m"; read -rsp "Digite a nova senha: " first; echo
        fi
    done
fi


# Codifica senha em BASE 64 para permitir qualquer caractere
MACHINE_PASSWORD_B64=$(printf '%s' "$MACHINE_PASSWORD" | base64 -w0)

# Normaliza nome do container para maiúsclas
MACHINE_NAME=$(echo "$MACHINE_NAME" | tr '[:lower:]' '[:upper:]')

#status "Maquina: $MACHINE_NAME | Usuário: $MACHINE_USER | Senha: $(mask_pwd_display "$MACHINE_PASSWORD")"
status "Maquina: $MACHINE_NAME | Usuário: $MACHINE_USER | Senha: $(mask_pwd "$MACHINE_PASSWORD")"


# ----------------------------
# Instala requisitos básicos
# ----------------------------
status "Verificando pacotes necessários..."
#apt-get update -y && apt-get upgrade -y
#apt-get install -y --no-install-recommends lxc lxc-templates lvm2 rsync debootstrap bridge-utils iproute2 wget xz-utils netcat-openbsd lsof || true
(apt-get update -y && apt-get upgrade -y && apt-get install -y --no-install-recommends lxc lxc-templates lvm2 rsync debootstrap bridge-utils iproute2 wget xz-utils netcat-openbsd lsof) >/dev/null 2>&1 \
&& status "Pacotes verificados com sucesso." \
|| echo -e "\e[97;41m Falha durante atualização ou instalação dos pacotes \e[0m\n"



# ----------------------------
# Verificação e criação automática do VG e thinpool (seguros)
# ----------------------------
trap 'for lv in "${MOUNTED_LVS[@]:-}"; do umount -lf "$lv" >/dev/null 2>&1 || true; done' EXIT

VG_EXISTE=$(vgs "$VG_NAME" 2>/dev/null || true)
if [[ -z "$VG_EXISTE" ]]; then
    warn "VG $VG_NAME não encontrado."

    # detecta discos livres (não montados e sem PV/FS existente)
    mapfile -t FREE_DISKS < <(
      lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print "/dev/"$1}' | while read d; do
        [[ -z $(lsblk -no MOUNTPOINT "$d" | grep -v '^$') ]] && [[ -z $(blkid "$d" 2>/dev/null) ]] && echo "$d"
      done
    )

    if [[ ${#FREE_DISKS[@]} -gt 0 ]]; then
        echo
        status "Discos livres disponíveis para uso:"
        for d in "${FREE_DISKS[@]}"; do echo "  $d"; done
        echo
        read -rp "Deseja utilizar um destes discos para o VG $VG_NAME? [s/N]: " USE_DISK

        if [[ "$USE_DISK" =~ ^[sS]$ ]]; then
            read -rp "Selecione o disco: " FREE_DISK
            [[ -z "$FREE_DISK" || ! " ${FREE_DISKS[*]} " =~ " $FREE_DISK " ]] && { err "Disco inválido."; exit 1; }

            read -rp "⚠️ Todos os dados do disco $FREE_DISK serão apagados. Continuar? [s/N]: " CONFIRM
            [[ ! "$CONFIRM" =~ ^[sS]$ ]] && { status "Operação cancelada."; exit 0; }

            status "Criando PV em $FREE_DISK..."
            pvcreate "$FREE_DISK" || { err "Falha ao criar PV em $FREE_DISK"; exit 1; }

            status "Criando VG $VG_NAME..."
            vgcreate "$VG_NAME" "$FREE_DISK" || { err "Falha ao criar VG $VG_NAME"; exit 1; }

            status "VG $VG_NAME criado com sucesso."
        fi
    fi

    # Se ainda não existe VG, usar backing file (loop)
    if ! vgs "$VG_NAME" &>/dev/null; then
        warn "Nenhum disco dedicado selecionado."
        warn "Será utilizado um arquivo de backing store no disco do sistema."

        BACKING_FILE="$LXC_DIR/lvm_pool.img"

        if [[ ! -f "$BACKING_FILE" ]]; then
            read -rp "Criar arquivo $BACKING_FILE para LVM (volume crítico no disco do SO)? [DIGITE CONFIRMO]: " CONFIRM
            [[ "$CONFIRM" != "CONFIRMO" ]] && { err "Operação abortada."; exit 1; }

            status "Criando arquivo de 500G em $BACKING_FILE..."
            truncate -s 500G "$BACKING_FILE"
            chmod 600 "$BACKING_FILE"
        fi

        LOOP_DEV=$(losetup -j "$BACKING_FILE" | cut -d: -f1)
        [[ -z "$LOOP_DEV" ]] && LOOP_DEV=$(losetup --find --show "$BACKING_FILE")

        status "Usando loop device $LOOP_DEV"
        pvcreate "$LOOP_DEV" 2>/dev/null || true
        vgcreate "$VG_NAME" "$LOOP_DEV" 2>/dev/null || true

        status "VG $VG_NAME criado sobre arquivo loop (disco do sistema)."
    fi
fi

# detecta thinpool existente
# EXISTING_POOL=$(lvs --noheadings -o lv_name,lv_attr "$VG_NAME" 2>/dev/null | awk '/twi|twi-/ {print $1; exit}')
# if [[ -n "$EXISTING_POOL" ]]; then
#   status "Thinpool detectado: $EXISTING_POOL no VG $VG_NAME. Usando-o."
#   POOL_NAME="$EXISTING_POOL"
# else
#   status "Nenhum thinpool detectado em $VG_NAME. Criando thinpool $POOL_NAME (90% FREE)..."
#   lvcreate -l 90%FREE --thinpool "$POOL_NAME" "$VG_NAME" --poolmetadatasize 1G || { err "Falha ao criar thinpool"; exit 1; }
# fi

# ----------------------------
# Detecta thinpool existente
# ----------------------------
EXISTING_POOL=$(lvs --noheadings -o lv_name,lv_attr "$VG_NAME" 2>/dev/null | awk '/twi|twi-/ {print $1; exit}')
if [[ -n "$EXISTING_POOL" ]]; then
    status "Thinpool detectado: $EXISTING_POOL no VG $VG_NAME. Usando-o."
    POOL_NAME="$EXISTING_POOL"
else
    # checa espaço livre no VG antes de criar thinpool
    FREE_BYTES=$(vgs --noheadings -o vg_free --units b "$VG_NAME" | tr -d ' ')
    MIN_REQUIRED=$((1 * 1024**3)) # 1Gb mínimo para pool metadata
    if (( FREE_BYTES < MIN_REQUIRED )); then
        err "Espaço insuficiente em VG $VG_NAME para criar thinpool (livres: $FREE_BYTES bytes)."
        exit 1
    fi

    read -rp "Nenhum thinpool detectado em $VG_NAME. Criar thinpool $POOL_NAME usando 90% do espaço livre? [s/N]: " CONFIRM
    [[ ! "$CONFIRM" =~ ^[sS]$ ]] && { status "Operação cancelada."; exit 0; }

    status "Criando thinpool $POOL_NAME..."
    lvcreate -l 90%FREE --thinpool "$POOL_NAME" "$VG_NAME" --poolmetadatasize 1G || { err "Falha ao criar thinpool"; exit 1; }
    status "Thinpool $POOL_NAME criado com sucesso."
fi









# ----------------------------
# Menu se container já existir
# ----------------------------
if [[ -d "$LXC_DIR/$MACHINE_NAME" || -d "/var/lib/lxc/$MACHINE_NAME" ]]; then
  echo
  echo -e "\n\n\n=== Maquina '$MACHINE_NAME' já existe - escolha: ==="
  echo "[1] Apagar maquina existente e recriar"
  echo "[2] Manter e aplicar correções"
  echo "[3] Gerar Backup (.tar.gz)"
  echo "[4] Restaurar Backup (.tar.gz)"
  echo "[5] Remover completamente"
  echo "[6] Cancelar/Sair"
  read -rp "Opção: " opt
  case "$opt" in
    1)
      echo -e "\n\nApagando e recriando $MACHINE_NAME..."   
      # Desmontando volumes   
      set +e
      lxc-stop -n "$MACHINE_NAME" >/dev/null 2>&1
      umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1
      umount -lf "/var/lib/lxc/$MACHINE_NAME/rootfs" >/dev/null 2>&1
      losetup -D >/dev/null 2>&1 || true
      sync
      LV_PATH="/dev/$VG_NAME/lv_${MACHINE_NAME,,}"
      # mata processos que usam o LV
      mapfile -t PIDS < <(lsof +f -- "$LV_PATH" 2>/dev/null | awk 'NR>1{print $2}' | sort -u)
      for p in "${PIDS[@]:-}"; do kill -9 "$p" >/dev/null 2>&1 || true; done
      sleep 1
      umount -lf "$LV_PATH" >/dev/null 2>&1 || true
      lxc-destroy -n "$MACHINE_NAME" >/dev/null 2>&1 || true
      if [[ -b "$LV_PATH" ]]; then lvremove -fy "$LV_PATH" >/dev/null 2>&1 || true; fi
      rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true
      sync
      set -e

      # Nova modelagem de exclusão (limpeza completa)
      lxc-stop -n "$MACHINE_NAME" -P /lxc >/dev/null 2>&1 || true; umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1 || true; lvremove -fy "/dev/vg_lxc/lv_${MACHINE_NAME}" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" >/dev/null 2>&1 || true;  echo "$MACHINE_NAME, seus LVs e resíduos removidos!"

      echo -e "Ambiente limpo."
      ;;
    2)
      status "Aplicando correções (sanitize config / reiniciar)..."
      # aqui chama funções de correção disponíveis
      clearing
      start
      exit 0
      ;;
    3)
      #-- -----------------------------------------------------------------------------------------------------------
      backup $MACHINE_NAME
      #-- -----------------------------------------------------------------------------------------------------------
      exit 0
      ;;
    4)
      # LISTA BACKUPS DISPONIVEIS 
      [ -d "$LXC_BACKUP_PATH" ] && [ "$(ls -A "$LXC_BACKUP_PATH" 2>/dev/null)" ] && { echo -e "\nBACK-UPs DISPONIVEIS:"; ls -lh --color=never "$LXC_BACKUP_PATH" | awk 'NR>1{bg=(NR%2? "\033[48;2;30;30;30m":"\033[48;2;10;10;10m"); printf "* %s'"$LXC_BACKUP_PATH"'/%s (%s)\033[0m\n", bg,$9,$5}'; } || echo -e "\n${RED}[ERRO] Diretório ${LXC_BACKUP_PATH} inexistente ou vazio. ${NC}"


      read -rp "Informe o caminho do .tar.gz: " bk
      [ ! -f "$bk" ] && { echo -e "${RED}[ERRO] Arquivo inválido (não encontrado). ${NC}"; exit 1; }

      ACTIVE_FILE="${bk%-backup-*}-active-$(basename "$bk" | cut -d'-' -f3).txt"
      echo -e "\n\nRestaurando $MACHINE_NAME a partir do back-up: "

      # Desmontando volumes
      set +e
      lxc-stop -n "$MACHINE_NAME" >/dev/null 2>&1
      umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1
      umount -lf "/var/lib/lxc/$MACHINE_NAME/rootfs" >/dev/null 2>&1
      losetup -D >/dev/null 2>&1 || true
      sync
      LV_PATH="/dev/$VG_NAME/lv_${MACHINE_NAME,,}"
      # mata processos que usam o LV
      mapfile -t PIDS < <(lsof +f -- "$LV_PATH" 2>/dev/null | awk 'NR>1{print $2}' | sort -u)
      for p in "${PIDS[@]:-}"; do kill -9 "$p" >/dev/null 2>&1 || true; done
      sleep 1
      umount -lf "$LV_PATH" >/dev/null 2>&1 || true
      lxc-destroy -n "$MACHINE_NAME" >/dev/null 2>&1 || true
      if [[ -b "$LV_PATH" ]]; then lvremove -fy "$LV_PATH" >/dev/null 2>&1 || true; fi
      rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true
      sync
      set -e

      # Nova modelagem de exclusão (limpeza completa)
      lxc-stop -n "$MACHINE_NAME" -P /lxc >/dev/null 2>&1 || true; umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1 || true; lvremove -fy "/dev/vg_lxc/lv_${MACHINE_NAME}" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" >/dev/null 2>&1 || true;
       

      reborn "$MACHINE_NAME" "$bk"

      exit 0 ########################





      #tar -C "$LXC_DIR" -xzf "$bk" || { echo -e "${RED}[ERRO] Algo deu errado durante a restauração. Revertendo...${NC}"; /lxc_machine.sh boot >> /lxc_machine.log 2>&1 & exit 1; }
      gzip -t "$bk" && tar -C "$LXC_DIR" -xzf "$bk" || { echo -e "${RED}[ERRO] Backup corrompido ou incompleto. Revertendo...${NC}\n\n"; /lxc_machine.sh boot >> /lxc_machine.log 2>&1 & exit 1; }
      /lxc_machine.sh boot >/dev/null 2>&1 & sleep 5 # Refixa o ambiente (refazendo a montagem) antes de iniciar
      lxc-start -n "$MACHINE_NAME" -P "$LXC_DIR" >/dev/null 2>&1 || true
      

      # Restaura containers Docker ativos no backup
      [ -f "$ACTIVE_FILE" ] && while read -r CNAME; do
          lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- docker start "$CNAME" || echo -e "${RED}[ERRO] Falha ao iniciar $CNAME ${NC}"
      done < "$ACTIVE_FILE"

        END_TIME=$(date +%s)
        DURATION=$((END_TIME-START_TIME))
        echo -e "\n\033[38;2;144;238;144m\033[48;2;20;20;20m Backup RESTAURADO com sucesso! (Duração: $(printf "%02d:%02d:%02d" $((DURATION/3600)) $((DURATION%3600/60)) $((DURATION%60)))) \n\n\033[0m"; exit 0
      # echo -e "\033[38;2;144;238;144m\033[48;2;20;20;20m Backup restaurado com sucesso! \033[0m\n\n\n"; exit 0
      ;;
    5)
      set +e
      lxc-stop -n "$MACHINE_NAME" >/dev/null 2>&1
      LV_PATH="/dev/$VG_NAME/lv_${MACHINE_NAME,,}"
      umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1 || true
      lxc-destroy -n "$MACHINE_NAME" >/dev/null 2>&1 || true
      lvremove -fy "$LV_PATH" >/dev/null 2>&1 || true
      rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true
      set -e

      # Nova modelagem de exclusão (limpeza completa)
      #echo -e $MACHINE_NAME $LXC_DIR; echo -e "\n\n\n"
      lxc-stop -n "$MACHINE_NAME" -P "$LXC_DIR" >/dev/null 2>&1 || true; umount -lf "$LXC_DIR/$MACHINE_NAME/rootfs" >/dev/null 2>&1 || true; lvremove -fy "/dev/vg_lxc/lv_${MACHINE_NAME}" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" "/var/lib/lxc/$MACHINE_NAME" >/dev/null 2>&1 || true; rm -rf "$LXC_DIR/$MACHINE_NAME" >/dev/null 2>&1 || true;  echo "$MACHINE_NAME, seus LVs e resíduos removidos!"

      
      status "Removido."; stat; exit 0
      ;;
    6) status "Cancelado."; exit 0 ;;
    *) status "Opção inválida"; exit 1 ;;
  esac
fi

# Limpa volumes logicos antes de continuar
#clearing


# ETAPA DE CRIAÇÃO E PRIMEIRO ARRANQUE DO CONTÊINER
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

# ----------------------------
# Criação do container LXC sobre LV thin com rootfs válido
# ----------------------------

LV_NAME="lv_${MACHINE_NAME,,}"
DEST_DIR="$LXC_DIR/$MACHINE_NAME"
ROOTFS_DIR="$DEST_DIR/rootfs"
TMP_NAME="${MACHINE_NAME}_tmp"

# diagnóstico preventivo
if mountpoint -q "$ROOTFS_DIR" 2>/dev/null; then
    echo -e "${RED}[ERRO] rootfs já está montado. Estado inconsistente detectado. ${NC}"
    exit 1
fi

# cria diretório seguro
mkdir -p "$ROOTFS_DIR"

# remove LV anterior se existir
lvremove -f /dev/$VG_NAME/$LV_NAME >/dev/null 2>&1 || true

# cria LV thin
LV_CREATE_OUTPUT=$(lvcreate -V "$DEFAULT_DISK" -T "$VG_NAME/$POOL_NAME" -n "$LV_NAME" 2>&1) || { echo -e "${RED}[ERRO] Falha ao criar LV thin $LV_NAME ${NC}"; exit 1; }

# captura warning (não interrompe)
LV_TOTAL_REQUIRED=$(echo "$LV_CREATE_OUTPUT" | grep "Sum of all thin volume sizes" | sed -E 's/.*\(([0-9.]+) GiB\).*/\1/') || true

# aborta apenas se exceder pool
# verifica warnings de thin pool
if echo "$LV_CREATE_OUTPUT" | grep -q "exceeds the size of thin pool"; then
    POOL_SIZE=$(lvs --units g --nosuffix -o lv_size /dev/$VG_NAME/$POOL_NAME | tail -n1)
    VG_SIZE=$(vgs --units g --nosuffix -o vg_size /dev/$VG_NAME | tail -n1)
    echo -e "${RED}[ERRO] \nThin pool $POOL_NAME insuficiente para alocar $DEFAULT_DISK.\n"\
"Thin pool atual:             $POOL_SIZE GiB\n"\
"Volume group atual:          $VG_SIZE GiB\n"\
"VG minimo esperado:            $LV_TOTAL_REQUIRED GiB\n"\
"A soma de thin LVs solicitados excede a capacidade do pool/volume group. ${NC}\n"\
"${ORANGE}[AÇÃO] \nPor favor, verifique os volumes logicos ou expanda manualmente o thin pool antes de continuar:\n"\
"[VERIFICAR VOLUMES]: lvs -o +data_percent,metadata_percent vg_lxc/tp_lxc && vgs vg_lxc && lvs -a -o +devices vg_lxc && lvs -a -o lv_name,origin,lv_size,data_percent,metadata_percent vg_lxc \n"\
"realizar limpeza de Volume group e Thin pools ofãos ( lxc clearing ) \n"\
"1) Expandir o VG (ex: 'lvextend -L+100G $VG_NAME/$POOL_NAME') ou adicionar PVs ao VG\n"\
"2) Ajustar thin pool se necessário (ex: 'lvextend -L+100G $VG_NAME/$POOL_NAME')\n"\
"Após expansão, execute o script novamente. ${NC}"
    exit 1
fi

# formata LV thin
mkfs.ext4 -F "/dev/$VG_NAME/$LV_NAME" &>/dev/null || { echo -e "${RED}[ERRO] Falha ao formatar LV $LV_NAME ${NC}"; exit 1; }

# monta LV thin
mount "/dev/$VG_NAME/$LV_NAME" "$ROOTFS_DIR" &>/dev/null || { echo -e "${RED}[ERRO] Falha ao montar LV $LV_NAME ${NC}"; exit 1; }

# path seguro para LXC
export LXC_LXCPATH="$LXC_DIR"

echo -e "${BLUE}[STATUS] Criando imagem temporária para popular rootfs... ${NC}"

# cria container temporário
lxc-create -n "$TMP_NAME" -t "$DEFAULT_TEMPLATE" -P "$LXC_DIR" -- --dist "$DEFAULT_DIST" --release "$DEFAULT_RELEASE" --arch "$DEFAULT_ARCH" &>/dev/null || { echo -e "${RED}[ERRO] Falha ao criar container temporário ${NC}"; umount -lf "$ROOTFS_DIR"; exit 1; }

echo -e "${BLUE}[STATUS] Copiando rootfs temporário para LV thin...${NC}"

# copia rootfs
rsync -aHAX --numeric-ids --exclude=/proc --exclude=/sys --exclude=/dev/pts --exclude=/tmp "$LXC_DIR/$TMP_NAME/rootfs/" "$ROOTFS_DIR/"

# remove container temporário
lxc-destroy -n "$TMP_NAME" -P "$LXC_DIR"

# cria devices essenciais
mkdir -p "$ROOTFS_DIR/dev"
mknod -m 666 "$ROOTFS_DIR/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/zero" c 1 5 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/random" c 1 8 2>/dev/null || true
mknod -m 666 "$ROOTFS_DIR/dev/urandom" c 1 9 2>/dev/null || true






# Define senha de root: Decodifica senha e passa via stdin para chpasswd dentro do chroot
printf 'root:%s\n' "$(printf '%s' "$MACHINE_PASSWORD_B64" | base64 -d)" | chroot "$ROOTFS_DIR" chpasswd || { echo -e "${RED}[ERRO] Falha ao definir senha root ${NC}"; exit 1; }
sleep 5

# configurações do container
mkdir -p "$DEST_DIR"
CONFIG_FILE="$DEST_DIR/config"
cat > "$CONFIG_FILE" <<EOF
lxc.rootfs.path = dir:$ROOTFS_DIR
lxc.uts.name = $MACHINE_NAME

# network
lxc.net.0.type = veth
lxc.net.0.link = br0
lxc.net.0.flags = up
lxc.net.0.name = eth0

######################################
# network bridge (host-only)
lxc.net.1.type = veth
lxc.net.1.link = ${BRIDGE_NAME}
lxc.net.1.flags = up
lxc.net.1.name = eth1

# IP fixo do contêiner (REVOGADO PARA DHCP)
#lxc.net.1.ipv4.address = ${HOST_IP%.*}.10
# Host como gateway lógico (opcional, mas recomendado)
#lxc.net.1.ipv4.gateway = ${HOST_IP%/*}


#Força DNS do host (dnsmasq em ${HOST_IP%/*})
lxc.mount.entry = /etc/lxc/resolv-dnsmasq.conf etc/resolv.conf none bind,create=file,ro 0 0

lxc.mount.entry = /etc/lxc/50-${BRIDGE_NAME}.yaml /etc/netplan/50-${BRIDGE_NAME}.yaml none bind,create=file,ro 0 0
######################################


# segurança
lxc.apparmor.profile = unconfined

# mounts essenciais para systemd
lxc.mount.auto = proc:mixed sys:mixed cgroup:mixed

# PTY / devpts (obrigatório para sudo, ssh, bash)
lxc.mount.entry = devpts dev/pts devpts defaults,newinstance,ptmxmode=0666,mode=0620 0 0

# limites de terminal
lxc.tty.max = 4
lxc.pty.max = 1024

# autostart
lxc.start.auto = 1
lxc.start.delay = 2
EOF


# limites de memória (opcional)
if (( ${DEFAULT_RAM_MEM//[^0-9]/}+0 > 0 )); then
cat >> "$CONFIG_FILE" <<EOF

# Limites de RAM e SWAP
lxc.cgroup2.memory.max = $DEFAULT_RAM_MEM
lxc.cgroup2.memory.high = $DEFAULT_RAM_MEM
lxc.cgroup2.memory.swap.max = $DEFAULT_RAM_SWAP
EOF
fi

# Configura symlink dentro do rootfs das maquinas
rm "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
touch "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
cp "/etc/lxc/resolv-dnsmasq.conf" "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/resolv.conf"
cp "/etc/lxc/50-${BRIDGE_NAME}.yaml" "${LXC_DIR}/${MACHINE_NAME}/rootfs/etc/netplan/50-${BRIDGE_NAME}.yaml"
sleep 1


# permissões finais
chown -R root:root "$ROOTFS_DIR" && chmod -R 0755 "$ROOTFS_DIR"

echo -e "${BLUE}[STATUS] Maquina $MACHINE_NAME criada corretamente sobre LV thin ${NC}"



# systemd unit
cat > "/etc/systemd/system/lxc-${MACHINE_NAME}.service" <<EOF
[Unit]
Description=LXC Container ${MACHINE_NAME}
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/lxc-start -n ${MACHINE_NAME} -P $LXC_DIR
ExecStop=/usr/bin/lxc-stop -n ${MACHINE_NAME} -P $LXC_DIR
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "lxc-${MACHINE_NAME}.service" >/dev/null 2>&1 || true

# inicia container pela primeira vez
lxc-start -n "$MACHINE_NAME" -P "$LXC_DIR" -d





wait_container_ready(){
  echo -e "${ORANGE}[SETUP] Verificando integridade estrutural... ${NC}"

  echo -e "${ORANGE}[SETUP] Aguardando maquina... ${NC}"
  until [ "$(lxc-info -n "$1" -P "$2" -s 2>/dev/null | awk '{print $2}')" = "RUNNING" ]; do sleep 1; done
  echo -e "${GREEN}[OK!] ${NC}"

  echo -e "${ORANGE}[SETUP] Aguardando systemd (PID 1)... ${NC}"
  until lxc-attach -n "$1" -P "$2" -- test "$(ps -o comm= -p 1 2>/dev/null)" = systemd; do sleep 1; done
  echo -e "${GREEN}[OK!] ${NC}"

  echo -e "${ORANGE}[SETUP] Aguardando DBus... ${NC}"
  until lxc-attach -n "$1" -P "$2" -- test -S /run/dbus/system_bus_socket; do sleep 1; done
  echo -e "${GREEN}[OK!] ${NC}"

  echo -e "${ORANGE}[SETUP] Verificando estado do systemd... ${NC}"
  until lxc-attach -n "$1" -P "$2" -- systemctl is-system-running --quiet; do sleep 2; done
  echo -e "${GREEN}[SAUDAVEL!] ${NC}"
}
wait_container_ready "$MACHINE_NAME" "$LXC_DIR"






echo -e "${ORANGE}[SETUP] instalando dependencias... ${NC}"

# Persiste o nome do host
lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -c "echo '$MACHINE_NAME' > /etc/hostname && sed -i '/127.0.1.1/d' /etc/hosts && echo '127.0.1.1 $MACHINE_NAME' >> /etc/hosts"

# aplica premissões corretas em netplan e atualiza pacotes
lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -c "chmod 0600 /etc/netplan/*.yaml && chown root:root /etc/netplan/*.yaml && netplan apply &>/dev/null"


# Restart conteiner
lxc-stop -n $MACHINE_NAME -P $LXC_DIR; lxc-start -n $MACHINE_NAME -P $LXC_DIR; sleep 5







#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@




# Aguarda IP do container
echo -e "${BLUE}[STATUS] Aguardando IP da maquina... ${NC}"
IP=""
for i in $(seq 1 $IP_WAIT_RETRIES); do
  #IP=$(lxc-info -n "$MACHINE_NAME"  -P $LXC_DIR -iH 2>/dev/null | head -n1 || true) # Obtem o primeiro IP informado
  #IP=$(lxc-info -n "$MACHINE_NAME" -P "$LXC_DIR" -iH 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | tail -n1); # obtem o ultima IP-v4 informado
  IP=$(lxc-attach -n KAMAKISHIA -P /lxc -- ip -4 -o addr show eth0 | awk '{split($4,a,"/"); print a[1]}'); # Obtem o IP da interface eth0 (rede física)
  [[ -n "$IP" && "$IP" != "-" ]] && break
  sleep 2
done
if [[ -z "$IP" || "$IP" == "-" ]]; then
  echo -e "${RED}[ERRO] Não foi possível obter IP da maquina $MACHINE_NAME ${NC}"
  exit 1
fi
echo -e "${BLUE}[STATUS] IP da maquina $MACHINE_NAME: $IP ${NC}"





#####################################################################################################################################
# instala e habilita Nano, SSH, Docker e docker-compose dentro do container
status "Instalando e configurando openssh-server no servidor..."
#lxc-attach -n "$MACHINE_NAME" -- bash -lc "export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y --no-install-recommends openssh-server; systemctl unmask ssh || true; systemctl enable ssh || true; sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config; systemctl restart ssh || true; id -u $MACHINE_USER >/dev/null 2>&1 || useradd -m -s /bin/bash $MACHINE_USER; echo \"$MACHINE_USER:$MACHINE_PASSWORD\" | chpasswd; echo \"root:$MACHINE_PASSWORD\" | chpasswd; usermod -aG sudo $MACHINE_USER || true"
# substitua a chamada original por este bloco robusto
lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -lc "
set -e
export DEBIAN_FRONTEND=noninteractive
{ apt-get update -qq >/dev/null 2>&1 && apt-get upgrade -qq -y >/dev/null 2>&1; } || true
apt-get install -y --no-install-recommends openssh-server nano curl ca-certificates gnupg lsb-release dos2unix dmidecode htop zip unzip acl net-tools bsdmainutils util-linux dnsutils >/dev/null 2>&1 || { echo \"Erro ao instalar pacotes\"; true;}

# habilita ssh e garante unit
systemctl unmask ssh >/dev/null 2>&1 || { echo \"Erro ao desbloquear ssh\"; true;}

# configura ssh para permitir root + senha
if grep -q '^#\\?PermitRootLogin' /etc/ssh/sshd_config; then
  sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
else
  echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
fi
if grep -q '^#\\?PasswordAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
  echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
fi



# cria usuário se não existir; se home já existe, não recria (-M), senão cria (-m)
if id -u \"$MACHINE_USER\" >/dev/null 2>&1; then
  echo \"[INFO] Usuário $MACHINE_USER já existe\"
else
  if [[ -d \"/home/$MACHINE_USER\" ]]; then
    useradd -M -s /bin/bash \"$MACHINE_USER\" || true
  else
    useradd -m -s /bin/bash \"$MACHINE_USER\" || true
  fi
fi

# aplica senhas e adiciona sudo
echo -e \"[SETUP] aplica senhas e adiciona ao grupo sudo\"
{ id \"$MACHINE_USER\" &>/dev/null && printf '%s:%s\n' \"$MACHINE_USER\" \"\$(printf '%s' '$MACHINE_PASSWORD_B64' | base64 -d)\" | chpasswd &>/dev/null && echo \"[INFO] Senha do usuário $MACHINE_USER definida com sucesso.\" || echo \"[WARN] Falha ao definir a senha do usuário $MACHINE_USER.\"; true;}

# adiciona o usuário $MACHINE_USER ao grupo sudo
usermod -aG sudo \"$MACHINE_USER\" || true




# Corrige ownership e permissões do home
if [[ -d \"/home/$MACHINE_USER\" ]]; then
  chown -R \"$MACHINE_USER\":\"$MACHINE_USER\" \"/home/$MACHINE_USER\" || true
  find \"/home/$MACHINE_USER\" -type d -exec chmod 0755 {} \\; || true
  find \"/home/$MACHINE_USER\" -type f -exec chmod 0644 {} \\; || true
  touch \"/home/$MACHINE_USER/.profile\" \"/home/$MACHINE_USER/.bashrc\" \"/home/$MACHINE_USER/.bash_profile\" 2>/dev/null || true
  chown \"$MACHINE_USER\":\"$MACHINE_USER\" \"/home/$MACHINE_USER/.profile\" \"/home/$MACHINE_USER/.bashrc\" \"/home/$MACHINE_USER/.bash_profile\" 2>/dev/null || true
  chmod 0644 \"/home/$MACHINE_USER/.profile\" \"/home/$MACHINE_USER/.bashrc\" \"/home/$MACHINE_USER/.bash_profile\" 2>/dev/null || true
fi

# garante permissões básicas de root
chown root:root /root/.bashrc 2>/dev/null || true
chmod 0644 /root/.bashrc 2>/dev/null || true

# === NANO COM NUMERAÇÃO DE LINHAS ===
sudo mkdir -p /etc/nanorc.d
sudo sed -i '/set linenumbers/d' /etc/nanorc
sudo grep -qxF 'set linenumbers' /etc/nanorc || echo 'set linenumbers' | sudo tee -a /etc/nanorc >/dev/null
sudo grep -qxF 'include /etc/nanorc.d/*.nanorc' /etc/nanorc || echo 'include /etc/nanorc.d/*.nanorc' | sudo tee -a /etc/nanorc >/dev/null
sudo bash -c 'echo \"# Arquivo reservado para futuras customizações de sintaxe\" > /etc/nanorc.d/01-linenumbers.nanorc'
sudo chmod 644 /etc/nanorc.d/01-linenumbers.nanorc

# === ⚠️ SUDO SEM SENHA PARA O USUÁRIO PADRÃO ===
echo \"$MACHINE_USER ALL=(ALL) NOPASSWD:ALL\" > \"/etc/sudoers.d/$MACHINE_USER\" && chmod 0440 \"/etc/sudoers.d/$MACHINE_USER\"

# === 3️⃣ INSTALAÇÃO DO DOCKER E DOCKER COMPOSE ===
install -m 0755 -d /etc/apt/keyrings >/dev/null 2>&1 || true
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc >/dev/null 2>&1 || true
chmod a+r /etc/apt/keyrings/docker.asc >/dev/null 2>&1 || true
echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \$VERSION_CODENAME) stable\" > /etc/apt/sources.list.d/docker.list
apt-get update -y && apt-get upgrade -y >/dev/null 2>&1 || true
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker >/dev/null 2>&1 || true
usermod -aG docker \"$MACHINE_USER\" >/dev/null 2>&1 || true



#-- -----------------------------------------------------------
# Criar o script start.sh
echo '#!/bin/bash
# /start.sh - RENOVA CHAVES E ATRIBUI AS PERMISSOES CORRETAS A CADA RESTART

while true; do
  sleep 5
  ##################!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  # RENOVA CHAVES E ATRIBUI AS PERMISSOES CORRETAS
  #ssh-keygen -A || true # Gera chaves apenas se inexistentes
  #for key in /etc/ssh/ssh_host_*_key; do [ -f \"\$key\" ] && chmod 600 \"\$key\"; done
  #for pub in /etc/ssh/ssh_host_*_key.pub; do [ -f \"\$pub\" ] && chmod 644 \"\$pub\"; done

  systemctl stop ssh
  # rm -f /etc/ssh/ssh_host_* && DEBIAN_FRONTEND=noninteractive dpkg-reconfigure openssh-server
  chmod 600 /etc/ssh/ssh_host_*_key && chmod 644 /etc/ssh/ssh_host_*_key.pub
  systemctl start ssh


  # Reabilita System SUDO
  chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo
  ##################!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
done
' > /usr/local/sbin/start.sh

# Criar a unit systemd fix-ssh-perms.service
echo '[Unit]
Description=Corrige permissões das chaves SSH antes do SSH iniciar
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/start.sh

[Install]
WantedBy=multi-user.target
' > /etc/systemd/system/fix-ssh-perms.service

# Conceder permissões corretas e habilitar a unit
chmod +x /usr/local/sbin/start.sh 1>/dev/null || true
systemctl daemon-reload 1>/dev/null || true
systemctl enable fix-ssh-perms.service 1>/dev/null || true
systemctl start fix-ssh-perms.service 1>/dev/null || true

#-- -----------------------------------------------------------



###########################
# === MENSAGEM DE BOAS-VINDAS PERSONALIZADA ===


# === MENSAGEM DE BOAS-VINDAS PERSONALIZADA ===
# === MOTD: criar banner estático e forçar PAM a mostrar apenas /etc/motd ===
# (executar dentro do container)
# desativa scripts dinâmicos e timer de notícias
chmod -x /etc/update-motd.d/* 1>/dev/null || true
systemctl disable --now motd-news.timer 1>/dev/null || true
rm -f /etc/motd.dynamic 1>/dev/null || true

# garante que /etc/motd seja limpo
: > /etc/motd 1>/dev/null || true

# cria banner exatamente como solicitado
cat <<EOF > /etc/motd
    ╔══════════════════════════════════════════════════════════╗
    ║          BEM-VINDO(A) AO SERVIDOR CLUSTERIZADO           ║
    ╚══════════════════════════════════════════════════════════╝
        Cluster : $(hostname)
        Server  : $MACHINE_NAME

        Usuário : $MACHINE_USER
        IP Atual : \$(hostname -I | awk '{print \$1}')
        Data/Hora: \$(date '+%d/%m/%Y %H:%M:%S')
    ════════════════════════════════════════════════════════════
EOF
chmod 0644 /etc/motd 1>/dev/null || true

###########################
# Garante .bashrc seja carregado ao conectar
for user_home in /root /home/${MACHINE_USER:-}; do
  [ -z \"\$user_home\" ] && continue
  [ -d \"\$user_home\" ] || continue
  for profile_file in \"\$user_home/.bash_profile\" \"\$user_home/.profile\"; do
    touch \"\$profile_file\"
    if ! grep -qxF 'if [ -f ~/.bashrc ]; then . ~/.bashrc; fi' \"\$profile_file\" 2>/dev/null; then
      echo 'if [ -f ~/.bashrc ]; then . ~/.bashrc; fi' >> \"\$profile_file\"
    fi
  done
done




# reinicia ssh para garantir que configurações entrem em vigor
systemctl restart ssh 1>/dev/null || true


echo '[OK] SSH, usuário, sudo, nano, Docker e MOTD configurados.' 
"




#####################################################################################################################################

# aguardar SSH
if [[ -n "${IP:-}" ]]; then
  wait_for_ssh "$IP" || warn "SSH não disponível. Verifique dentro da maquina."
fi

# ----------------------------
# Aplica .bashrc custom nos rootfs
# ----------------------------
ROOTFS="$DEST_DIR/rootfs"
#mkdir -p "$ROOTFS/root" && cp /etc/skel/.bashrc "$ROOTFS/root/.bashrc" 2>/dev/null || touch "$ROOTFS/root/.bashrc"

#cat >> "$ROOTFS/root/.bashrc" <<'EOF'
lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -c "mkdir -p /root" && lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- tee -a /root/.bashrc > /dev/null <<'EOF'
clear


MACHINE_NAME=$(hostname)
echo "#######################################################"
clear && lsb_release -d 2>/dev/null | cut -d ":" -f 2- | sed 's/^[[:space:]]*/ @/' && echo ""
echo " ➤      SERVIDOR: [ $MACHINE_NAME ]"
ImgSistDef=4.002
read -r DT DU DA <<< $(df -BG --output=size,used,avail / 2>/dev/null | tail -n1 | awk '{gsub("G","",$0); print $1,$2,$3}')
LV_TOTAL=$(awk -v t="$DT" -v i="$ImgSistDef" 'BEGIN{printf "%.2f", t+i}'); LV_FREE="$DA"; LV_USED=$(awk -v t="$LV_TOTAL" -v f="$LV_FREE" 'BEGIN{printf "%.2f", t-f}'); LV_PERC=$(awk -v u="$LV_USED" -v t="$LV_TOTAL" 'BEGIN{printf "%.1f", (u/t)*100}')
printf "\033[37;100m Armazenamento Principal:            \033[0m\nTOTAL\tEm Uso\tUso%%\tDisponível\n%sG\t%sG\t%s%%\t%sG\n" "$LV_TOTAL" "$LV_USED" "$LV_PERC" "$LV_FREE"
MEM_MAX_FILE=/sys/fs/cgroup/memory.max; MEM_CUR_FILE=/sys/fs/cgroup/memory.current
if [[ -f "$MEM_MAX_FILE" && -f "$MEM_CUR_FILE" ]]; then RAM_TOTAL=$(awk '{if($1=="max"){t=0} else t=$1; printf "%.2f", t/1073741824}' "$MEM_MAX_FILE"); RAM_USED=$(awk '{printf "%.2f", $1/1073741824}' "$MEM_CUR_FILE"); RAM_DISP=$(awk -v t="$RAM_TOTAL" -v u="$RAM_USED" 'BEGIN{if(t>0) printf "%.2f", t-u; else printf "%.2f", u}'); else RAM_TOTAL=$(free -b | awk '/Mem:/ {printf "%.2f",$2/1e9}'); RAM_DISP=$(free -b | awk '/Mem:/ {printf "%.2f",$7/1e9}'); fi
printf "\033[37;100m RAM TOTAL: %sGb | RAM DISP.: %.2fGb\033[0m\n" "$RAM_TOTAL" "$RAM_DISP"
MODS=($(dmidecode -t memory | awk -F: '/Size:/ && $2!~/No Module/ {gsub(/^[ \t]+/,"",$2); gsub(/[^0-9A-Za-z]/,"",$2); sub(/GB$/,"Gb",$2); sub(/B$/,"b",$2); print $2}')); NUM_MODS=${#MODS[@]}
if (( NUM_MODS > 1 )); then for i in "${!MODS[@]}"; do MOD_VAL=$(awk -v total="$RAM_TOTAL" -v n="$NUM_MODS" 'BEGIN{printf "%.2fGb", total/n}'); SEP=$', '; (( i == NUM_MODS-1 )) && SEP=$'\n'; printf "%dº Módulo: %s%s" $((i+1)) "$MOD_VAL" "$SEP"; done
elif (( NUM_MODS == 1 )); then printf "1º Módulo: %.2fGb\n" "$RAM_TOTAL"; fi
export IP=$(hostname -I | awk '{print $1}' | cut -d ':' -f 1)

#-- ------------------------------------------------------------
echo -e "\n\n"




# Alias atualizado
bind -x '"\C-l": "clear && source ~/.bashrc"'
alias docker-compose='docker compose'

# Logar na raiz
cd /

# Caracteres especiais
export LANG="pt_BR.utf8"
export LANGUAGE="pt_BR.utf8"
#export LC_ALL="pt_BR.utf8"

# Prompt com IP azul e caminho verde
PS1='\[\e[1;34m\]$(hostname -I | cut -d " " -f 1)\[\e[m\] \[\e[37m\]\u@\h:\[\e[32m\]\w\$\[\e[m\] '

# Define variável IP
export IP=$(hostname -I | awk '{print $1}' | cut -d ':' -f 1)

# Alias atualizado (repetido para garantir persistência)
bind -x '"\C-l": "clear && source ~/.bashrc"'
alias docker-compose='docker compose'
#-- ------------------------------------------------------------

# Verificar o config do serviço SSH
sshd -t




EOF





mkdir -p "$ROOTFS/home/$MACHINE_USER"
#cat >> "$ROOTFS/home/$MACHINE_USER/.bashrc" <<'EOF'
lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- bash -c "mkdir -p /home/$MACHINE_USER" && lxc-attach -n "$MACHINE_NAME" -P "$LXC_DIR" -- tee -a /home/$MACHINE_USER/.bashrc > /dev/null <<'EOF'
clear


MACHINE_NAME=$(hostname)
#######################################################
# Caracteres especiais
export LANG="pt_BR.utf8"
export LANGUAGE="pt_BR.utf8"
export IP=$(hostname -I | awk '{print $1}' | cut -d ':' -f 1)

#-- ------------------------------------------------------------
echo -e "  \n\n"

# Alias atualizado
bind -x '"\C-l": "clear && source ~/.bashrc"'
alias docker-compose='docker compose'

# Logar na raiz
cd /

# Caracteres especiais
export LANG="pt_BR.utf8"
export LANGUAGE="pt_BR.utf8"
#export LC_ALL="pt_BR.utf8"

# Prompt com IP azul e caminho verde
PS1='\[\e[1;34m\]$(hostname -I | cut -d " " -f 1)\[\e[m\] \[\e[37m\]\u@\h:\[\e[32m\]\w\$\[\e[m\] '

# Define variável IP
export IP=$(hostname -I | awk '{print $1}' | cut -d ':' -f 1)

# Alias atualizado (repetido para garantir persistência)
bind -x '"\C-l": "clear && source ~/.bashrc"'
alias docker-compose='docker compose'
#-- ------------------------------------------------------------


sudo -i



EOF


chown -R 1000:1000 "$ROOTFS/home/$MACHINE_USER" 2>/dev/null || true



# ----------------------------
# Verificação do LV thin e rootfs
# ----------------------------
LV_PATH="/dev/$VG_NAME/$LV_NAME"
echo -e "\n\e[44;97m [STATUS] Verificando LV da maquina... \e[0m"
echo -e "[COMMAND]: lvs --units g --nosuffix \"${LV_PATH}\""
lvs --units g --nosuffix "$LV_PATH"

echo -e "\e[44;97m [STATUS] Uso real do rootfs (crescimento do thin LV)...\e[0m"
echo -e "[COMMAND]: df -h \"${ROOTFS_DIR}\""
df -h "$ROOTFS_DIR"

# ----------------------------
# Resultado final
# ----------------------------
echo
# echo "=== CONTAINER CRIADO ==="
echo -e "\n\n\n\033[97;48;5;235m NOVO SERVIDOR CRIADO!!! \033[0m"
echo "Nome: $MACHINE_NAME"
echo "Usuário: $MACHINE_USER"
echo "Senha: $(mask_pwd_display "$MACHINE_PASSWORD")"
echo "IP: ${IP:-(não obtido)}"
echo "Acesso SSH: ssh $MACHINE_USER@${IP:-IP_NAO_OBTIDO}"
echo -e "Acesso ROOT: ssh root@${IP:-IP_NAO_OBTIDO} \n\n\n"

# echo -e "\033[37;100m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy)"
#echo -e "\033[37;100m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls --fancy | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
echo -e "\n\n\033[37;48;5;17m SERVIDORES DISPONÍVEIS \033[0m\n$(lxc-ls -f -P /lxc | sed -E 's/[0-9]+\.[0-9]+\.0\.1(, ?)?//g')\n"
echo -e "$(DISPLAY_LXC_TABLE)"
echo -e "$DISPLAY_LXC_INFO"

exit 0

#!/usr/bin/env bash
# Interactive IPv4 separation for simple Ubuntu/Debian Remnawave nodes.
# Run ON THE VPS, through SSH. No passwords, DNS or panel configuration collected.
# Unsupported layouts stop after audit; no attempt to guess provider networking.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

die() { printf '\nОСТАНОВКА: %s\n' "$*" >&2; exit 1; }
ask() { local value; read -r -p "$2" value; printf -v "$1" '%s' "$value"; }
ipv4() { python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); assert a.is_global and not a.is_multicast and not a.is_reserved' "$1" 2>/dev/null; }
ports() {
    python3 - "$1" <<'PY'
import sys
s=sys.argv[1].strip()
if s in ('','-'): print(''); sys.exit()
a=s.split(',')
assert all(x.strip().isdigit() and 1<=int(x)<=65535 for x in a), 'Порты: числа 1–65535 через запятую'
print(', '.join(str(x) for x in sorted(set(map(int,a)))))
PY
}
disable_split() {
    local target='' remove_ufw='' confirm='' backup unit
    for bin in python3 nft systemctl flock tar; do
        command -v "$bin" >/dev/null || die "Для отключения нужна команда $bin."
    done
    [[ -d /run/systemd/system ]] || die 'Нужен systemd.'
    exec 9>/run/node-ip-split.lock
    flock -n 9 || die 'Сначала завершите другой запущенный экземпляр скрипта.'
    # Confirm netlink access before treating an absent table as an uninstalled setup.
    nft list tables >/dev/null
    printf '%s\n' 'Будут удалены только таблица ip node_ip_split и автозапуск node-ip-split.' \
      'Панель, DNS, адреса, маршруты, WARP и остальные таблицы firewall не изменяются.' \
      'Резервные копии предыдущих запусков сохранятся.'
    if command -v ufw >/dev/null; then
        ufw status numbered
        ask remove_ufw 'Удалить также добавленный вручную запрет UFW для выходного IPv4:443/TCP? [да/нет]: '
        if [[ $remove_ufw == да ]]; then
            ask target 'Выходной IPv4, для которого добавляли запрет (например 185.252.177.114): '
            ipv4 "$target" || die 'Некорректный публичный IPv4.'
            printf 'Будет выполнено: ufw --force delete deny in proto tcp from any to %s port 443\n' "$target"
            printf '%s\n' 'У ручного правила нет метки владельца: подтвердите, что это именно добавленный нами запрет.'
        fi
    fi
    printf '%s\n' 'После удаления ограничений выходной IP снова сможет принимать подключения, если остальные правила разрешают.' \
      'После удаления SNAT новые соединения используют обычные настройки системы.' \
      'Уже установленные NAT-соединения могут сохранять адрес до переподключения; conntrack не очищается.'
    ask confirm 'Введите ОТКЛЮЧИТЬ для выполнения; Enter — отмена: '
    [[ $confirm == ОТКЛЮЧИТЬ ]] || { echo 'Отменено, изменений нет.'; return; }
    backup=$(mktemp -d /root/node-ip-split-disable-XXXXXXXX)
    nft list ruleset > "$backup/nft.before.txt"
    local files=()
    for unit in /etc/node-ip-split /etc/systemd/system/node-ip-split.service /etc/ufw; do
        [[ ! -e $unit ]] || files+=("${unit#/}")
    done
    if ((${#files[@]})); then tar -C / -czf "$backup/config.before.tar.gz" "${files[@]}"; fi
    printf 'Резервная копия перед отключением: %s\n' "$backup"
    # Stop watchdogs before taking their lock; a watchdog may already be running.
    systemctl list-units --all --plain --no-legend 'node-ip-split-rollback-*' > "$backup/watchdogs.before.txt"
    while read -r unit _; do
        [[ $unit =~ ^node-ip-split-rollback-[0-9]+-[0-9]+\.(timer|service)$ ]] || continue
        systemctl stop "$unit"
    done < "$backup/watchdogs.before.txt"
    exec 8>/run/node-ip-split-change.lock
    flock -x 8
    if [[ -e /etc/systemd/system/node-ip-split.service ]]; then
        systemctl disable --now node-ip-split.service
    fi
    if nft list table ip node_ip_split >/dev/null 2>&1; then
        nft delete table ip node_ip_split
    fi
    rm -f /etc/systemd/system/node-ip-split.service
    rm -f /etc/node-ip-split/rules.nft /etc/node-ip-split/apply.sh /etc/node-ip-split/committed
    if [[ -d /etc/node-ip-split ]]; then
        rmdir /etc/node-ip-split 2>/dev/null || printf '%s\n' 'В /etc/node-ip-split остались дополнительные файлы; они сохранены.'
    fi
    systemctl daemon-reload
    if [[ $remove_ufw == да ]]; then
        ufw --force delete deny in proto tcp from any to "$target" port 443
        ufw status numbered | tee "$backup/ufw.after.txt"
    fi
    nft list tables > "$backup/tables.after.txt"
    if nft list table ip node_ip_split >/dev/null 2>&1; then die 'Таблица осталась; отключение не завершено.'; fi
    [[ ! -e /etc/systemd/system/node-ip-split.service ]] || die 'Файл службы остался.'
    flock -u 8
    printf '%s\n' 'Отключено: таблица node_ip_split удалена/отсутствует, файл автозапуска удалён/отсутствует.' \
      'Сеть и сервер не перезапускались. Внешняя доступность портов этим скриптом не проверялась.' | tee "$backup/result.txt"
    if [[ $remove_ufw == да ]]; then
        printf 'Запрошено удаление точного запрета UFW для %s:443/TCP; итоговые правила в ufw.after.txt.\n' "$target" | tee -a "$backup/result.txt"
    fi
}

if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Запуск на VPS: sudo --preserve-env=SSH_CONNECTION bash node-ip-split.sh' \
      'По умолчанию только аудит. Применение требует отдельного подтверждения.' \
      'Только простой IPv4, два локальных публичных адреса, Docker host network.' \
      'WARP, policy routing, сторонний NAT и firewall managers: аудит и остановка.' \
      'Отключение: sudo bash node-ip-split.sh --disable (SSH_CONNECTION не требуется).' \
      'Без аргументов: меню настройки или отключения. --setup: сразу настройка.'
    exit 0
fi
[[ $EUID == 0 ]] || die 'Нужен root на VPS.'
[[ -t 0 ]] || die 'Нужен интерактивный терминал; не используйте curl | bash.'
MODE=${1:-}
if [[ -z $MODE ]]; then
    printf '%s\n' '1 — аудит и настройка разделения IP' '2 — отключить разделение IP и удалить добавленные правила' '0 — выход'
    ask CHOICE 'Выберите действие [0]: '
    case $CHOICE in 1) MODE=--setup ;; 2) MODE=--disable ;; ''|0) exit 0 ;; *) die 'Неизвестный пункт.' ;; esac
fi
case $MODE in
    --disable) disable_split; exit 0 ;;
    --setup) ;;
    *) die 'Допустимые аргументы: --setup, --disable, --help.' ;;
esac
for bin in python3 ip ss nft iptables-save systemctl systemd-run curl flock tar; do
    command -v "$bin" >/dev/null || die "Не найдена $bin. Установите соответствующий пакет отдельно и повторите."
done
[[ -d /run/systemd/system ]] || die 'Нужен systemd.'
exec 9>/run/node-ip-split.lock
flock -n 9 || die 'Уже запущен другой экземпляр.'

printf '\nНастройка выполняется на %s. Сначала только аудит.\n' "$(hostname)"
printf '%s\n' 'Никаких изменений панели/DNS, перезапуска сети или сервера.'
ask ENTRY 'Входной публичный IPv4: '
ask EXIT_IP 'Выходной публичный IPv4: '
ipv4 "$ENTRY" && ipv4 "$EXIT_IP" || die 'Нужны два корректных публичных IPv4.'
[[ $ENTRY != "$EXIT_IP" ]] || die 'Адреса должны различаться.'
ask SSH_PORT 'SSH-порт текущего подключения [22]: '
SSH_PORT=${SSH_PORT:-22}
[[ $SSH_PORT =~ ^[0-9]{1,5}$ ]] && ((10#$SSH_PORT > 0 && 10#$SSH_PORT <= 65535)) || die 'Некорректный SSH-порт.'
SSH_PORT=$((10#$SSH_PORT))
[[ -n ${SSH_CONNECTION:-} ]] || die 'Нет SSH_CONNECTION. Подключитесь к VPS по SSH; при sudo сохраните эту переменную.'
read -r CLIENT CLIENT_PORT SERVER SERVER_PORT <<< "$SSH_CONNECTION"
[[ $SERVER == "$ENTRY" && $SERVER_PORT == "$SSH_PORT" ]] || die 'Текущая SSH-сессия должна быть подключена к входному IP и указанному порту.'

RUN=$(mktemp -d /root/node-ip-split-XXXXXXXX)
printf '\nОтчёт и резервные копии: %s\n' "$RUN"
ip -j -4 addr show > "$RUN/addresses.json"
ip -j -4 route show table all > "$RUN/routes.json"
ip -j -4 rule show > "$RUN/rules.json"
nft -j list ruleset > "$RUN/nft.json"
nft list ruleset > "$RUN/nft.before.txt"
iptables-save > "$RUN/iptables.before.txt"
ss -lntup > "$RUN/listeners.txt"
systemctl list-units --type=service --state=running --no-pager > "$RUN/services.txt"
systemctl list-unit-files --no-pager > "$RUN/unit-files.txt"
ip -details link show > "$RUN/links.txt"
if command -v iptables-legacy-save >/dev/null; then
    iptables-legacy-save > "$RUN/iptables-legacy.txt"
fi
BACKUP_PATHS=()
for p in /etc/netplan /etc/network /etc/systemd/network /etc/NetworkManager/system-connections /etc/nftables.conf /etc/iptables /etc/ufw; do
    [[ ! -e $p ]] || BACKUP_PATHS+=("${p#/}")
done
if ((${#BACKUP_PATHS[@]})); then tar -C / -czf "$RUN/network-backup.tar.gz" "${BACKUP_PATHS[@]}"; fi
printf '%s\n' '=== Слушающие порты ==='
cat "$RUN/listeners.txt"
printf '%s\n' '=== Маршруты ==='
ip -4 route show
if command -v docker >/dev/null; then
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' | tee "$RUN/docker.txt"
fi
ask NODE 'Имя Docker-контейнера VPN-ноды (или - если VPN отсутствует): '
NODE_MODE=none
if [[ $NODE != - ]]; then
    [[ $NODE =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die 'Некорректное имя контейнера.'
    command -v docker >/dev/null || die 'Docker не найден.'
    NODE_MODE=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NODE")
    [[ $(docker inspect --format '{{.State.Running}}' "$NODE") == true ]] || die 'Контейнер ноды не запущен.'
fi
TCP_PORTS='' UDP_PORTS=''
if [[ $NODE != - ]]; then
    printf '%s\n' 'Укажите только публичные VPN-порты ноды, не порт API Remnawave, SSH или панели.'
    printf '%s\n' 'Если VPN делит порт с панелью/сайтом, автоматическое ограничение такого порта не подходит.'
    ask RAW_TCP 'TCP-порты VPN через запятую (или -): '
    ask RAW_UDP 'UDP-порты VPN через запятую (или -): '
    TCP_PORTS=$(ports "$RAW_TCP") || die 'Неверные TCP-порты.'
    UDP_PORTS=$(ports "$RAW_UDP") || die 'Неверные UDP-порты.'
    [[ -n $TCP_PORTS$UDP_PORTS ]] || die 'Не указан ни один VPN-порт.'
    for p in ${TCP_PORTS//,/ }; do [[ $p != "$SSH_PORT" ]] || die 'VPN-порт совпадает с SSH.'; done
fi

# Strict eligibility gate. Any unexplained configuration is audit-only.
BLOCKERS="$RUN/blockers.txt"
: > "$BLOCKERS"
[[ $NODE_MODE == host || $NODE_MODE == none ]] || echo 'VPN-контейнер не использует host network.' >> "$BLOCKERS"
for svc in warp-svc wg-quick@wgcf tailscaled firewalld ufw; do
    if systemctl is-active --quiet "$svc"; then echo "Активен $svc: требуется индивидуальная настройка." >> "$BLOCKERS"; fi
done
if grep -Eiq 'wireguard|tun |tun:|happ|wgcf|warp|tailscale' "$RUN/links.txt"; then
    echo 'Обнаружен туннельный интерфейс.' >> "$BLOCKERS"
fi
if [[ -f $RUN/iptables-legacy.txt ]] && grep -q '^-A ' "$RUN/iptables-legacy.txt"; then
    echo 'Есть правила legacy iptables.' >> "$BLOCKERS"
fi
python3 - "$RUN" "$ENTRY" "$EXIT_IP" "$TCP_PORTS" "$UDP_PORTS" <<'PY' >> "$BLOCKERS"
import json,sys,ipaddress,re
from pathlib import Path
d=Path(sys.argv[1]); a,b=sys.argv[2:4]
addresses=json.loads((d/'addresses.json').read_text())
found={}
public=[]
for iface in addresses:
    for v in iface.get('addr_info',[]):
        ip=v.get('local','')
        found[ip]=iface['ifname']
        if ipaddress.ip_address(ip).is_global: public.append(ip)
if a not in found or b not in found: print('Оба IP должны быть уже назначены интерфейсам VPS; настройте дополнительный IP по документации хостера.')
elif found[a]!=found[b]: print('IP находятся на разных интерфейсах.')
if set(public)!={a,b}: print('Ожидаются ровно два публичных IPv4; остальные требуют отдельного анализа.')
rules=json.loads((d/'rules.json').read_text())
if len(rules)!=3 or {(r.get('priority'),str(r.get('table'))) for r in rules}!={(0,'local'),(32766,'main'),(32767,'default')}:
    print('Есть нестандартные policy routing rules; они не будут изменены.')
routes=json.loads((d/'routes.json').read_text())
defaults=[r for r in routes if r.get('dst')=='default']
if len(defaults)!=1 or defaults[0].get('dev')!=found.get(a) or 'nexthops' in defaults[0]:
    print('Ожидается один default route через интерфейс обоих IP.')
if any(str(r.get('table','main')) not in ('main','local','254','255') for r in routes):
    print('Обнаружены дополнительные таблицы маршрутизации.')
if a in found and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',found[a]): (d/'interface').write_text(found[a])
else: print('Не удалось безопасно определить интерфейс.')
nft=json.loads((d/'nft.json').read_text())
chains={}
for item in nft.get('nftables',[]):
    if 'chain' in item:
        c=item['chain']; chains[(c['family'],c['table'],c['name'])]=c
for item in nft.get('nftables',[]):
    if 'rule' not in item: continue
    r=item['rule']; text=json.dumps(r.get('expr',[])).lower()
    # Docker's own NAT is left intact. All other NAT/mangle/redirect semantics stop setup.
    if any(x in text for x in ('"snat"','"dnat"','"masquerade"','"redirect"')):
        if not (r['table']=='nat' and (r['chain'].startswith('DOCKER') or 'docker' in text)):
            # Docker's source masquerade rule has no DOCKER name in the expression.
            if not (r['table']=='nat' and r['chain']=='POSTROUTING' and '"masquerade"' in text and ('docker0' in text or 'br-' in text)):
                print('Есть сторонний NAT: '+r['table']+'/'+r['chain'])
    if any(x in text for x in ('"mark"','"tproxy"','"notrack"','"flow"','"queue"')):
        print('Есть маркировка/особая обработка трафика: '+r['table']+'/'+r['chain'])
    c=chains.get((r['family'],r['table'],r['chain']),{})
    if c.get('type')=='route': print('Есть route chain.')
# Ensure supplied ports actually listen on entry/wildcard. No ownership guessed.
lines=(d/'listeners.txt').read_text().splitlines()
for proto,raw in zip(('tcp','udp'),sys.argv[4:6]):
    for p in filter(None,(x.strip() for x in raw.split(','))):
        ok=False
        for line in lines:
            s=line.split()
            if len(s)>4 and s[0]==proto and s[4] in (a+':'+p,'0.0.0.0:'+p,'*:'+p,'[::]:'+p): ok=True
        if not ok: print(f'Не найден listener {proto}/{p} на входном IP или wildcard.')
PY
if [[ -s $BLOCKERS ]]; then
    cat "$BLOCKERS"
    die "Автонастройка не применяется. Аудит сохранён в $RUN. Секреты из архива не публикуйте."
fi
IFACE=$(cat "$RUN/interface")
[[ ! -e /etc/node-ip-split && ! -e /etc/systemd/system/node-ip-split.service ]] || die 'Уже есть установка node-ip-split; сначала используйте её rollback.sh.'
if nft list table ip node_ip_split >/dev/null 2>&1; then die 'Таблица node_ip_split уже существует.'; fi

printf '\nПроверка исходящей доступности обоих IP (HTTPS к api.ipify.org и checkip.amazonaws.com).\n'
probe() {
    local bind=$1 url result
    for url in https://api.ipify.org https://checkip.amazonaws.com; do
        result=$(curl --noproxy '*' -4 --interface "$bind" --connect-timeout 8 --max-time 15 -fsS "$url") || return 1
        result=${result//$'\r'/}; result=${result//$'\n'/}
        [[ $result == "$bind" ]] || { printf 'Ожидался %s, получен %s\n' "$bind" "$result" >&2; return 1; }
    done
}
probe "$ENTRY" || die 'Входной IP не прошёл проверку исходящей связности.'
probe "$EXIT_IP" || die 'Выходной IP не прошёл проверку исходящей связности.'
printf '%s\n' 'Оба IP работают как источники HTTPS. Это не подтверждает все маршруты провайдера или доступность VPN извне.'
printf '%s\n' 'Скрипт не назначает адреса и не переписывает netplan: оба IP должны быть постоянными уже сейчас.'
ask PERSIST 'Оба IP настроены постоянно у хостера/в сетевой конфигурации, а не временным ip addr add? [да/нет]: '
[[ $PERSIST == да ]] || die 'Сначала нужно отдельно обеспечить постоянство обоих IP по инструкции провайдера.'

cat > "$RUN/rules.nft" <<EOF
add table ip node_ip_split
flush table ip node_ip_split
add chain ip node_ip_split outbound { type nat hook postrouting priority 110; policy accept; }
add rule ip node_ip_split outbound ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return
add rule ip node_ip_split outbound fib daddr type local return
add rule ip node_ip_split outbound ct status dnat return
add rule ip node_ip_split outbound ct mark != 0 return
add rule ip node_ip_split outbound meta mark != 0 return
add rule ip node_ip_split outbound oifname "$IFACE" ip saddr { $ENTRY, $EXIT_IP } ct direction original counter snat to $EXIT_IP
add chain ip node_ip_split inbound { type filter hook input priority -10; policy accept; }
EOF
if [[ -n $TCP_PORTS ]]; then
    echo "add rule ip node_ip_split inbound ip daddr $EXIT_IP ct state new tcp dport { $TCP_PORTS } counter reject with tcp reset" >> "$RUN/rules.nft"
fi
if [[ -n $UDP_PORTS ]]; then
    echo "add rule ip node_ip_split inbound ip daddr $EXIT_IP ct state new udp dport { $UDP_PORTS } counter reject" >> "$RUN/rules.nft"
fi
nft -c -f "$RUN/rules.nft" || die 'Проверка nftables не пройдена.'
printf '\nПлан: новые обычные IPv4-соединения хоста и host-network ноды → %s.\n' "$EXIT_IP"
printf 'Новые VPN-подключения к %s на TCP [%s], UDP [%s] будут отклоняться.\n' "$EXIT_IP" "$TCP_PORTS" "$UDP_PORTS"
printf '%s\n' 'Установленные соединения и ответы клиентам сохраняют прежнюю conntrack-привязку.' \
  'После отката уже созданные NAT-соединения могут сохранять IP до переподключения.' \
  'IPv6, bridge-контейнеры, частные сети и отмеченный трафик не перенастраиваются.' \
  'При ошибке — откат. Через 10 минут без подтверждения — автоматический откат.' \
  'Второе НОВОЕ SSH-подключение обязательно для сохранения изменений.' \
  'Если порт разделён с панелью/сайтом, не применяйте план.'
cat "$RUN/rules.nft"
ask APPLY 'Введите ПРИМЕНИТЬ для выполнения; Enter — закончить только аудитом: '
[[ $APPLY == ПРИМЕНИТЬ ]] || { printf 'Только аудит: %s\n' "$RUN"; exit 0; }

NFT=$(command -v nft)
TIMER="node-ip-split-rollback-$(date +%s)-$$"
cat > "$RUN/rollback.sh" <<EOF
#!/usr/bin/env bash
set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec 8>/run/node-ip-split-change.lock
flock -x 8
if [[ \${1:-} == --pending && -e /etc/node-ip-split/committed ]]; then exit 0; fi
systemctl disable --now node-ip-split.service >/dev/null 2>&1 || true
if nft list table ip node_ip_split >/dev/null 2>&1; then
    nft delete table ip node_ip_split || exit 1
fi
rm -f /etc/systemd/system/node-ip-split.service
rm -rf /etc/node-ip-split
systemctl daemon-reload
date -Is > '$RUN/rolled-back'
echo 'Правила node-ip-split удалены; снимки и отчёт: $RUN'
EOF
chmod 700 "$RUN/rollback.sh"
ARMED=0
cleanup() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if ((ARMED)); then
        flock -u 8 2>/dev/null || true
        printf '\nИзменения не подтверждены. Выполняется откат.\n'
        if bash "$RUN/rollback.sh"; then systemctl stop "$TIMER.timer" || true; fi
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
systemd-run --unit="$TIMER" --on-active=10min --timer-property=AccuracySec=1s /bin/bash "$RUN/rollback.sh" --pending
ARMED=1
mkdir -m 700 /etc/node-ip-split
install -m 600 "$RUN/rules.nft" /etc/node-ip-split/rules.nft
cat > /etc/node-ip-split/apply.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
ip -4 addr show dev '$IFACE' | grep -Fq 'inet $ENTRY/'
ip -4 addr show dev '$IFACE' | grep -Fq 'inet $EXIT_IP/'
exec '$NFT' -f /etc/node-ip-split/rules.nft
EOF
chmod 700 /etc/node-ip-split/apply.sh
cat > /etc/systemd/system/node-ip-split.service <<EOF
[Unit]
Description=IPv4 source separation and VPN entry restriction
Wants=network-online.target
After=network-online.target nftables.service docker.service
ConditionPathExists=/etc/node-ip-split/committed

[Service]
Type=oneshot
ExecStart=/etc/node-ip-split/apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
bash /etc/node-ip-split/apply.sh
nft list table ip node_ip_split > "$RUN/nft.after.txt"
OBSERVED=$(curl --noproxy '*' -4 --connect-timeout 8 --max-time 15 -fsS https://api.ipify.org)
[[ $OBSERVED == "$EXIT_IP" ]] || die "Обычный исходящий IPv4: $OBSERVED, ожидался $EXIT_IP."
printf 'Исходящий IPv4 сервера подтверждён: %s\n' "$OBSERVED"
cat > "$RUN/verify-ssh.sh" <<EOF
#!/usr/bin/env bash
set -eu
[[ \$EUID == 0 ]] || exit 1
read -r client port server sshport <<< "\${SSH_CONNECTION:-}"
[[ \$server == '$ENTRY' && \$sshport == '$SSH_PORT' ]] || { echo 'Нужна SSH-сессия через входной IP'; exit 1; }
[[ "\$client \$port" != '$CLIENT $CLIENT_PORT' ]] || { echo 'Нужно НОВОЕ SSH-подключение'; exit 1; }
date -Is > '$RUN/ssh-verified'
echo 'Новое SSH-подключение через входной IP подтверждено.'
EOF
chmod 700 "$RUN/verify-ssh.sh"
printf '\nВ другом терминале подключитесь заново (без SSH multiplexing):\n'
printf 'ssh -o ControlMaster=no -o ControlPath=none -p %s root@%s\n' "$SSH_PORT" "$ENTRY"
printf 'В новой сессии выполните: bash %s/verify-ssh.sh\n' "$RUN"
printf '%s\n' 'Также переподключите VPN к входному IP и проверьте внешний IPv4 в браузере.' \
  'Проверьте, что VPN к выходному IP не подключается. UDP проверяется реальным VPN-клиентом.' \
  'Скрипт не может автоматически проверить внешнюю доступность портов и полный VPN-путь.'
ask KEEP 'После проверок введите СОХРАНИТЬ (до истечения 10 минут); иначе Enter для отката: '
[[ $KEEP == СОХРАНИТЬ && -f $RUN/ssh-verified ]] || die 'Нет подтверждения или нового SSH-подключения.'
[[ ! -f $RUN/rolled-back ]] || die 'Таймер уже выполнил откат.'
# Stop the watchdog before committing, and detect a concurrently started rollback.
exec 8>/run/node-ip-split-change.lock
flock -x 8
systemctl stop "$TIMER.timer"
if systemctl is-active --quiet "$TIMER.service" || [[ -f $RUN/rolled-back ]]; then die 'Откат уже начался.'; fi
[[ -e /etc/node-ip-split/rules.nft ]] || die 'Файлы конфигурации отсутствуют.'
touch /etc/node-ip-split/committed
systemctl enable --now node-ip-split.service
systemctl is-enabled --quiet node-ip-split.service
systemctl is-active --quiet node-ip-split.service
nft -c -f /etc/node-ip-split/rules.nft
ARMED=0
flock -u 8
cat > "$RUN/result.txt" <<EOF
Вход: $ENTRY; выход: $EXIT_IP; интерфейс: $IFACE
Исходящий IPv4 сервера проверен через HTTPS: $OBSERVED
Новая SSH-сессия: подтверждена файлом ssh-verified.
VPN TCP: $TCP_PORTS; UDP: $UDP_PORTS
Созданы /etc/node-ip-split/{rules.nft,apply.sh,committed}
Создан /etc/systemd/system/node-ip-split.service (enabled, active).
Добавлена nft-таблица ip node_ip_split; исходные правила: nft.before.txt.
Netplan/панель/DNS не изменены. Архив: network-backup.tar.gz.
Откат: bash $RUN/rollback.sh
НЕ проверены автоматически: VPN-клиент, доступность портов извне, реальная перезагрузка.
Постоянство обоих адресов подтверждено оператором, не доказано скриптом.
EOF
printf '\nСохранено. Отчёт/резервные копии: %s\n' "$RUN"
printf 'Ручной откат: bash %s/rollback.sh\n' "$RUN"
printf '%s\n' 'Созданы: /etc/node-ip-split/{rules.nft,apply.sh,committed}, /etc/systemd/system/node-ip-split.service.' \
  'Добавлена только собственная nft-таблица ip node_ip_split. Netplan, панель и DNS не менялись.' \
  'Проверены: исходящий IPv4, новое SSH-соединение, синтаксис nft, включение systemd unit.' \
  'Реальная перезагрузка и проверка VPN-клиентом скриптом НЕ выполнялись.' \
  'Постоянство адресов у провайдера/в netplan требует проверки: скрипт не назначает IP заново.' \
  'Сторонний flush ruleset удалит правила: после него потребуется systemctl restart node-ip-split.' \
  'Архив network-backup.tar.gz может содержать сетевые секреты; не публикуйте его.'

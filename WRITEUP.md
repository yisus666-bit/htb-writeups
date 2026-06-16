# [Nombre de la Máquina] — HackTheBox Write-up

| Campo | Detalle |
|---|---|
| **Máquina** | [Nombre] |
| **OS** | Linux / Windows |
| **Dificultad** | Easy / Medium / Hard |
| **Fecha de pwn** | DD MMM YYYY |
| **Autor del write-up** | Andres |
| **Tags** | `web`, `privesc`, `cve-xxxx-xxxx` *(agregar según aplique)* |

---

## Resumen Ejecutivo

> Breve descripción de la máquina en 2-3 oraciones. Qué tipo de vulnerabilidad principal tiene, qué tecnologías usa y cómo fue la ruta de explotación general. Ejemplo: *"Cap es una máquina Linux fácil que expone un panel web de captura de red. Aprovechando un IDOR en los IDs de sesión, se obtiene un pcap con credenciales en texto claro. El acceso root se logra abusando de la capability `cap_setuid` en Python."*

---

## Reconocimiento

### Escaneo de Puertos

```bash
nmap -sC -sV -oN nmap/initial.txt <IP>
```

**Resultados:**

```
PORT   STATE SERVICE VERSION
xx/tcp open  ???     ???
```

### Enumeración Web *(si aplica)*

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
```

**Hallazgos:**
- `/ruta1` — descripción
- `/ruta2` — descripción

### Tecnologías Identificadas

- **CMS / Framework:** *(Ej: WordPress 5.x, Next.js, Flask)*
- **Servidor web:** *(Ej: Apache 2.4, Nginx)*
- **Lenguaje backend:** *(Ej: PHP, Python, Node.js)*
- **Base de datos:** *(Ej: MySQL, SQLite, PostgreSQL)*

---

## Análisis de Vulnerabilidades

### Vulnerabilidad Principal

**Tipo:** *(Ej: IDOR, SQLi, RCE, SSRF, Buffer Overflow)*  
**CVE:** *(si aplica, Ej: CVE-2025-XXXX)*  
**CVSS Score:** X.X  

**Descripción:**  
Explica la vulnerabilidad encontrada. ¿Por qué existe? ¿Qué configuración incorrecta o fallo de código la genera?

### Otras Vulnerabilidades Identificadas *(si aplica)*

- **[Tipo]:** descripción breve

---

## Explotación

### Paso 1 — [Nombre del paso]

```bash
# Comando utilizado
comando --flag valor
```

**Resultado:**
```
output del comando
```

> Explicación breve de qué hace este paso y por qué funciona.

### Paso 2 — [Nombre del paso]

```bash
comando
```

### Paso 3 — Obtención de User Flag

```bash
cat /home/<usuario>/user.txt
```

```
flag: <hash>
```

---

## Escalada de Privilegios

### Enumeración de Privilegios

```bash
# Verificar sudo
sudo -l

# Buscar SUID binaries
find / -perm -4000 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Procesos corriendo como root
ps aux | grep root
```

**Hallazgo clave:**
```
output relevante
```

### Explotación de PrivEsc

**Método:** *(Ej: SUID Python, sudo misconfiguration, cron job writable, capability abuse)*

```bash
# Comandos de explotación
comando_privesc
```

### Root Flag

```bash
cat /root/root.txt
```

```
flag: <hash>
```

---

## Post-Explotación *(opcional)*

```bash
# Persistencia, dump de credenciales, etc.
```

---

## Lecciones Aprendidas

### Lo que aprendí

- **Concepto 1:** Explicación de algo nuevo que aprendiste técnicamente.
- **Concepto 2:** Herramienta o técnica que usaste por primera vez.
- **Concepto 3:** Error cometido y cómo lo resolví.

### Técnicas / Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| `nmap` | Escaneo inicial de puertos y servicios |
| `gobuster` | Enumeración de directorios web |
| `burpsuite` | Intercepción y manipulación de requests |
| *(agregar)* | *(agregar)* |

---

## Referencias

- [Nombre del recurso](URL) — descripción breve
- [CVE-XXXX-XXXX](https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX)
- [HackTricks - Técnica usada](URL)

---

*Write-up por Andres | [LinkedIn](https://linkedin.com/in/tu-perfil) | [GitHub](https://github.com/tu-usuario)*

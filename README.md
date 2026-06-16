
# HackTheBox Write-ups

> Documentación técnica de máquinas resueltas en HackTheBox.  
> Cada write-up incluye reconocimiento, análisis de vulnerabilidades, explotación y escalada de privilegios.

**Autor:** Andres  
**Perfil HTB:** [yisus666
#CR] 


---

## Máquinas Completadas

| # | Máquina | OS | Dificultad | Técnicas Clave | Write-up |
|---|---|---|---|---|---|
| 1 | [Cap](./Cap/) |  Linux | 🟢 Easy | IDOR, PCAP analysis, Linux Capabilities | [Ver](./Cap/README.md) |
| 2 | [Silentium](./Silentium/) |  Linux | 🟢 Easy | *(completar)* | [Ver](./Silentium/README.md) |
| 3 | [Facts](./Facts/) |  Linux | 🟢 Easy | *(completar)* | [Ver](./Facts/README.md) |
| 4 | [MonitorsFour](./MonitorsFour/) |  Windows | 🟢 Easy | *(completar)* | [Ver](./MonitorsFour/README.md) |
| 5 | [Manage](./Manage/) |  Linux | 🟢 Easy | *(completar)* | [Ver](./Manage/README.md) |

**Total:** 5 máquinas | **Linux:** 4 | **Windows:** 1

---

## Metodología General

```
Reconocimiento → Enumeración → Análisis → Explotación → PrivEsc → Post-Explotación
```

### Herramientas que uso regularmente

| Categoría | Herramientas |
|---|---|
| Reconocimiento | `nmap`, `masscan`, `rustscan` |
| Web | `gobuster`, `ffuf`, `nikto`, `burpsuite` |
| Explotación | `metasploit`, `searchsploit`, scripts custom |
| Post-Explotación | `linpeas`, `winpeas`, `bloodhound` |
| Scripting | `bash`, `python` |

---

## Estructura de Repositorio

```
htb-writeups/
├── README.md               ← Este archivo (índice general)
├── TEMPLATE.md             ← Plantilla para nuevos write-ups
├── Cap/
│   ├── README.md           ← Write-up completo
│   └── screenshots/        ← Evidencias
├── Silentium/
│   ├── README.md
│   └── screenshots/
├── Facts/
│   ├── README.md
│   └── screenshots/
├── MonitorsFour/
│   ├── README.md
│   └── screenshots/
└── Manage/
    ├── README.md
    └── screenshots/
```

---

## ⚠️ Disclaimer

> Todos los ataques documentados aquí fueron realizados en entornos **controlados y legales** de HackTheBox, exclusivamente con fines educativos. No apliques estas técnicas en sistemas sin autorización explícita.

---

*Última actualización: Junio 2026*

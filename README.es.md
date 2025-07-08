> **🌍 Este proyecto está disponible en inglés y español.**
> [🇪🇸 Español](./README.es.md) | [🇬🇧 English](./README.md)
>
> ---

# Colección de Scripts Sultanovich

Una colección seleccionada de scripts para administración de sistemas, seguridad y monitoreo en múltiples sistemas operativos. Este repositorio está estructurado para ser claro y escalable.

## Estructura

- `scripts/`
  - `security/`: Scripts relacionados con seguridad, como chequeos de vulnerabilidades y hardening.
    - `python/`: Utilidades desarrolladas en Python para scripting multiplataforma (siempre que se cuente con Python y sus dependencias instaladas).
    - `linux/`: Scripts específicos para sistemas operativos GNU/Linux (aunque la mayoría también funcionará en otros sistemas tipo Unix).
    - `windows/`: Scripts específicos para el sistema operativo Windows.
  - `sysadmin/`: Scripts para tareas de administración de sistemas, como gestión de usuarios y automatización de tareas administrativas. 
    - `python/`: Utilidades desarrolladas en Python para scripting multiplataforma. Estas herramientas están diseñadas para funcionar en distintos sistemas operativos, siempre que se cuente con Python y sus dependencias instaladas.
    - `linux/`: Scripts específicos para sistemas operativos GNU/Linux (aunque la mayoría también funcionará en otros sistemas tipo Unix).
    - `windows/`: Scripts específicos para el sistema operativo Windows.


## Resumen de Scripts

| Script                                                                                       | Descripción                                      | Categoría/SO        |
|----------------------------------------------------------------------------------------------|--------------------------------------------------|---------------------|
| [security-check-cve-2025-6018-6019.sh](scripts/security/linux/security-check-cve-2025-6018-6019.sh)                                                        | Verifica vulnerabilidades CVE-2025-6018 y CVE-2025-6019 (PAM, udisks2/libblockdev) | Seguridad / Linux   |
| [add-linux-local-user.sh](scripts/sysadmin/linux/add-linux-local-user.sh)                                                       | Script Bash para crear un usuario local en Linux con política de expiración de contraseña (SOC/PCI compliant), registro seguro, etc. | Sysadmin / Linux    |
| [delete-linux-local-user.sh](scripts/sysadmin/linux/delete-linux-local-user.sh) | Script Bash para eliminar de forma segura un usuario local de Linux (con opción de eliminar el home), registro seguro, modo dry-run, etc. | Sysadmin / Linux    |
| [security-check-cve-2025-4322.sh](scripts/security/linux/security-check-cve-2025-4322.sh) | Verifica la vulnerabilidad CVE-2025-4322 (Motors Theme para WordPress) y opcionalmente intenta un PoC seguro (cambio de contraseña del usuario admin) | Seguridad / Linux   |
| [gha-prtarget-misconfig-audit.py](scripts/security/python/gha-prtarget-misconfig-audit/gha-prtarget-misconfig-audit.py) | Audita GitHub Actions en busca de configuraciones inseguras del evento `pull_request_target` que pueden exponer secretos o permitir la ejecución de PRs desde forks no confiables | Seguridad / Python |


## Uso

1. Clona el repositorio:
   ```bash
   git clone https://github.com/<your-username>/sysops-automation-scripts.git
   ```
2. Navega por el directorio `scripts/` para ver los scripts disponibles.
3. Cada script contiene instrucciones de uso en su cabecera.

## Ejemplo

```bash
bash scripts/security/linux/check_cve.sh
```

## Contribuciones

¡Las contribuciones son bienvenidas! Por favor, lee [CONTRIBUTING.md](CONTRIBUTING.es.md) antes de enviar pull requests.

## Licencia

Este proyecto está licenciado bajo la [GNU GPL v2](LICENSE).

## Seguridad

Si encuentras una vulnerabilidad de seguridad, por favor sigue las instrucciones en nuestra [Política de Seguridad](SECURITY.es.md) antes de divulgar cualquier detalle públicamente.

También puedes usar los Issues de GitHub para reportar problemas de seguridad, siguiendo el proceso descrito en la política.
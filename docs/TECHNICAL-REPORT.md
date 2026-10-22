# Hyperium Code-Audit v4.0 — Informe Tecnico
## Plataforma de Auditoria de Seguridad de Codigo Fuente (SAST) con Modulo Roblox/Luau

**Autor:** Hyperium IA — www.hyperiumia.com
**Version del documento:** 1.0 | **Version del producto:** 4.0.0
**Clasificacion:** Publico — para desarrolladores de software, estudios de videojuegos y equipos de seguridad (CISO)
**Estado:** Fases 0-4 completadas | Suite de pruebas: 140 passed, 1 skipped (0.38 s)

---

## 1. Resumen Ejecutivo

Hyperium Code-Audit es un analizador estatico de codigo (SAST — Static Application Security Testing) de grado produccion que detecta vulnerabilidades OWASP Top 10, secretos incrustados, exposicion de pasarelas de pago, dependencias vulnerables, configuraciones de infraestructura inseguras y —como extension de esta fase— riesgos de seguridad especificos del ecosistema Roblox/Luau.

Este informe documenta la arquitectura del sistema, los defectos de ingenieria detectados y corregidos durante la fase de saneamiento, el diseno del modulo de seguridad para videojuegos y la metodologia de desarrollo empleada (TDD, integracion protegida por suite de pruebas).

**Resultados clave:**

| Metrica | Resultado |
|---|---|
| Pruebas automatizadas | 140 aprobadas, 1 omitida (dependencia opcional) |
| Defectos de ingenieria detectados y corregidos | 6 (2 no reportados previamente, incluyendo 1 critico de empaquetado) |
| Reglas de seguridad Roblox/Luau implementadas | 14 en 5 categorias |
| Falsos positivos en codigo Luau legitimo | 0 (garantizado por prueba automatizada) |
| Tiempo de analisis completo | < 0.4 s (suite), milisegundos por archivo |
| Fases de ingenieria cerradas | 4 (core, Luau, rule pack, vitrina comercial) |

---

## 2. Alcance y Entorno de Ejecucion

- **Lenguajes analizados:** Python, JavaScript, TypeScript, PHP, Java, Go, C#, Ruby, HTML, **Lua/Luau (nuevo)**, mas formatos de configuracion (YAML, TOML, JSON, ENV, Dockerfile, Terraform, Kubernetes)
- **Entorno de validacion:** Linux x86_64, CPython 3.12.15 (gestion de versiones con uv), suite de pruebas con pytest 9.x
- **Integracion continua:** plantillas para GitHub Actions, GitLab CI y Bitbucket Pipelines; exportacion SARIF v2.1.0 compatible con la pestana Security de GitHub

---

## 3. Arquitectura del Sistema

### 3.1 Pipeline de analisis

El motor orquesta un pipeline de cinco fases con separacion estricta de responsabilidades:

    1. DISCOVER   -> Descubrimiento de archivos fuente (extension + exclusiones)
    2. SCAN       -> Ejecucion de todos los analizadores sobre cada archivo
    3. TRIAGE     -> Puntuacion de riesgo y priorizacion de hallazgos
    4. COMPLIANCE -> Mapeo a marcos regulatorios (frameworks configurables)
    5. REPORT     -> Generacion de salida (terminal, SARIF, PDF, historial)

### 3.2 Analizadores (modulos del motor)

| Modulo | Funcion | Tecnica |
|---|---|---|
| pattern_scanner | 22 reglas OWASP (SQLi, XSS, SSRF, command injection, path traversal, deserializacion, crypto, auth) | Regex multicapa con indice por lenguaje |
| taint_analyzer | Seguimiento de flujo de datos: source -> sanitizer -> sink | Analisis de taint sobre Python (aceleracion compilada opcional) |
| ast_engine / js_ast_engine | Deteccion de alta confianza mas alla de regex | AST (Python), tree-sitter (JS/TS) |
| secret_detector | 20+ patrones de secretos (AWS, Stripe, GitHub, JWT, claves privadas) + verificacion por entropia de Shannon | Regex + scoring de entropia |
| payment_scanner / payment_logic | 7 pasarelas de pago + logica: verificacion de webhooks, idempotencia, montos confiados en cliente (PCI) | Reglas semanticas (modulo protegido) |
| dep_analyzer | 65 CVEs reales sobre 30 paquetes Python/JS, con EPSS y CISA KEV (opcional, online) | Base de datos offline |
| iac_scanner | Dockerfile, Terraform, Kubernetes: root user, tags :latest, buckets publicos, contenedores privilegiados | Reglas por tecnologia |
| api_security | CORS wildcard, debug mode, endpoints sin autenticacion, fugas de stack trace | Reglas de contexto API |
| custom_rules | Reglas definidas por el usuario en YAML — base de los rule packs modulares | Carga de datos, validacion de regex |
| sarif_exporter | Exportacion SARIF v2.1.0 | Estandar OASIS |
| triage_engine / compliance_mapper | Scoring de riesgo, activos criticos, mapeo a marcos | Heuristicas configurables |
| scan_history / checkpoint_manager / incremental | Historial de tendencias, reanudacion, escaneo incremental (--since) | Persistencia + git |

### 3.3 Modelo de datos central

Todos los hallazgos convergen en el modelo Finding (Pydantic): rule_id, categoria, severidad, confianza, ubicacion exacta (archivo/linea), descripcion, **remediacion**, referencias CWE/OWASP y metadatos. Este modelo es el contrato unificado entre analizadores, triage, compliance y reportes — y es el punto de extension natural para nuevos dominios (como Roblox).

### 3.4 Extensibilidad: reglas como datos

El sistema de reglas personalizadas (YAML) permite anadir detecciones **sin modificar ni recompilar el motor**. Formato de regla:

    rules:
      - id: RBX-BD-001
        title: Dynamic code execution via loadstring
        severity: critical          # critical | high | medium | low
        category: security_misconfig
        cwe_id: CWE-94
        owasp_id: A03
        languages: [lua, luau]
        pattern: 'loadstring[(]'
        description: ...
        remediation: ...
        confidence: 0.95

Los patrones evitan deliberadamente secuencias de escape ([(] en lugar de parentesis escapado), lo que garantiza portabilidad entre cargadores YAML y robustez ante corrupcion de formato en flujos de copia/distribucion.

---
## 4. Resultados de la Auditoria de Ingenieria (Fase 0-1)

La revision del codigo base detecto **6 defectos**, de los cuales 2 no estaban en el reporte inicial. Todos fueron corregidos bajo metodologia TDD (prueba que falla -> correccion -> prueba que pasa), cada uno con regresion automatizada permanente.

| # | Defecto | Severidad | Estado |
|---|---|---|---|
| 1 | **Reglas personalizadas desconectadas**: extra_rules se cargaba desde YAML pero nunca se inyectaba en el PatternScanner — silencioso: el usuario configura reglas, el motor las ignora y reporta "0 hallazgos" (falsa confianza) | **Critico** | Corregido + prueba de regresion |
| 2 | **Backend de empaquetado invalido**: setuptools.backends._legacy:_Backend no existe en setuptools actual; cualquier pip install fallaba con BackendUnavailable | **Critico** | Corregido a setuptools.build_meta |
| 3 | **Versionado inconsistente**: setup.py declaraba 4.0.0, pyproject.toml 1.0.0 | Alto | Unificado a 4.0.0 + prueba de consistencia |
| 4 | **tool_version hardcodeado** en el motor (1.0.0): el SARIF que se sube a GitHub Security reportaba la version incorrecta | Alto | Corregido + prueba tool_version vs pyproject |
| 5 | **Descubrimiento de Luau ausente**: SCAN_EXTENSIONS y Language no contemplaban .lua/.luau | Alto | Corregido (Fase 2) |
| 6 | **Documentacion enganosa**: los modulos protegidos referenciaban un script build_protected.py inexistente | Medio | Corregido |

**Hallazgo estructural adicional (decision estrategica abierta):** los modulos payment_logic y taint_analyzer estan compilados como binarios nativos para CPython 3.12 (.so), sin fallback en Python puro, lo que restringe la ejecucion a una ABI exacta pese a declarar requires-python >= 3.10. Ver seccion 8.

---

## 5. Modulo de Seguridad para Videojuegos — Roblox/Luau

### 5.1 Contexto de riesgo

La cadena de suministro de desarrollo en Roblox tiene un vector de riesgo conocido y frecuente: **backdoors insertadas mediante modelos gratuitos ("Toolbox")**, scripts de freelancers o dependencias externas. Un script malicioso puede exfiltrar datos de jugadores, manipular la economia interna del juego o destruir progresos persistidos. Los estudios que operan juegos con miles de jugadores concurrentes concentran este riesgo en sus repositorios y su proceso de revision de codigo.

### 5.2 Rule Pack Roblox v1 — 14 reglas, 5 categorias

**A. Backdoors y ejecucion dinamica (RBX-BD)**

| ID | Deteccion | Severidad |
|---|---|---|
| BD-001 | loadstring — ejecucion dinamica de codigo (vector estandar de payloads) | Critica |
| BD-002 | HttpGet — descarga de contenido en runtime (intercambio de payloads post-publicacion) | Alta |
| BD-003 | require() sobre asset ID numerico — carga de modulos de terceros no controlados | Alta |
| BD-004 | getfenv/setfenv — manipulacion de entorno para ocultar payloads | Alta |
| BD-005 | string.char(...) — ofuscacion de cadenas maliciosas | Media |

**B. Exfiltracion de datos (RBX-EXF)**

| ID | Deteccion | Severidad |
|---|---|---|
| EXF-001 | PostAsync/HttpPostAsync — envio de datos fuera de la plataforma | Alta |
| EXF-002 | Webhooks de Discord en codigo — canal de exfiltracion estandar de backdoors | Critica |
| EXF-003 | RequestAsync — API de bajo nivel que evade puntos de revision | Media |

**C. Frontera de confianza cliente-servidor (RBX-TRUST)**

| ID | Deteccion | Severidad |
|---|---|---|
| TRUST-001 | Handlers OnServerEvent:Connect sin validacion aparente — vector de exploits y duplicacion de items | Media |
| TRUST-002 | OnServerInvoke sin validacion de argumentos | Media |

**D. Integridad de economia (RBX-ECON)**

| ID | Deteccion | Severidad |
|---|---|---|
| ECON-001 | ProcessReceipt sin idempotencia — concesiones duplicadas de compras | Media |
| ECON-002 | SetAsync sin manejo de errores — perdida silenciosa de progreso | Baja |

**E. Configuracion (RBX-CFG)**

| ID | Deteccion | Severidad |
|---|---|---|
| CFG-001 | Referencia a LoadStringEnabled — ejecucion arbitraria habilitada | Alta |
| CFG-002 | Manipulacion de metatables — ocultamiento de comportamiento | Baja |

### 5.3 Garantia de calidad del pack

- **Cero falsos positivos en codigo legitimo**: prueba automatizada ejecuta el pack sobre codigo Luau valido y exige cero hallazgos. Esta prueba corre en cada build del producto.
- **Prueba de extremo a extremo**: un proyecto con backdoor simulada produce exactamente los hallazgos esperados por archivo, incluida exportacion SARIF verificada.
- **Actualizacion sin releases**: el pack es un artefacto de datos (YAML). Nuevas firmas de backdoors se publican como versiones del pack sin tocar el motor.

### 5.4 Demostrador ejecutable

examples/roblox-demo/ contiene un proyecto de demostracion auditable por cualquier persona:

| Archivo | Contenido | Hallazgos esperados |
|---|---|---|
| backdoor.luau | Backdoor estilo Toolbox (simulada, inofensiva) | BD-001/002/003/005, EXF-002 |
| remotes.luau | Trust boundary y economia sin validacion | TRUST-001/002, ECON-001/002 |
| clean.luau | Codigo Luau legitimo | ninguno |

---
## 6. Metodologia de Ingenieria

### 6.1 Desarrollo guiado por pruebas (TDD)

Todo defecto y toda funcionalidad se implemento con ciclo rojo-verde: se escribe primero la prueba que documenta el comportamiento esperado y que falla contra el codigo actual; luego se corrige hasta que pasa. Los defectos criticos (como las reglas personalizadas desconectadas) quedaron cubiertos por pruebas de regresion permanentes.

### 6.2 Flujo de integracion protegida

- Modelo de ramas: master (desplegable) <- develop (integracion) <- ramas feat/*, fix/*, hotfix/*
- Commits atomicos con convencion semantica (fix:, feat:, test:, docs:)
- **Merge guard**: toda integracion a develop se ejecuta con git merge --no-commit, la suite completa se ejecuta sobre el resultado combinado y el merge solo se confirma en verde (commit) o se aborta (merge --abort). Durante el desarrollo este guard bloqueo correctamente dos integraciones con pruebas fallidas — evidencia operativa de la disciplina.

### 6.3 Trazabilidad

Historia completa en git: cada correccion referencia su prueba, cada merge documenta la fase cerrada. La suite actua como especificacion ejecutable del producto.

---

## 7. Resultados y Metricas Verificadas

| Indicador | Linea base (Fase 0) | Estado actual |
|---|---|---|
| Pruebas automatizadas | 120 passed, 1 skipped | **140 passed, 1 skipped** |
| Defectos abiertos | 6 | 0 (decision estrategica seccion 8 aparte) |
| Soporte de lenguajes | 8 + configs | **9 + configs (Lua/Luau)** |
| Reglas de dominio Roblox | — | **14** |
| Falsos positivos demostrados en demo limpio | — | **0** |
| Instalacion del paquete | rota (BackendUnavailable) | funcional (pip install -e ., CLI code-audit operativo) |
| Consistencia de version (paquete/motor/SARIF) | inconsistente | **unificada y protegida por prueba** |

---

## 8. Decision Estrategica Abierta: Nucleo Auditable vs. Propiedad Intelectual Protegida

El proyecto hereda modulos compilados a binario nativo (proteccion de propiedad intelectual para la logica de pagos y el analisis de taint). El analisis tecnico establece el contexto de la decision:

- **Proteccion de IP**: los binarios impiden la redistribucion directa de la logica comercial — un modelo legitimo y coherente con la estrategia de productos de Hyperium IA.
- **Compatibilidad**: cada ABI de Python requiere su compilacion; hoy el paquete solo opera en CPython 3.12 pese a declarar soporte >= 3.10.
- **Credibilidad**: un security tool auditable genera mas confianza en compradores tecnicos que uno opaco.

**Alternativas evaluadas:** (A) Open core — nucleo Python auditable + binarios como modulo opcional premium; (B) apertura completa con reescritura en Python puro; (C) compilacion multiplataforma completa. El proyecto se encuentra en evaluacion de esta decision con recomendacion tecnica por la opcion A, que alinea proteccion de IP comercial con credibilidad del producto base.

---
## 9. Limites y Alcance de la Garantia (Declaracion para CISOs)

Hyperium Code-Audit es un analizador **estatico**. Su alcance y sus limites se declaran de forma explicita:

**Lo que garantiza:**

- Deteccion automatizada de patrones de vulnerabilidad conocidos (OWASP, CWE, firmas de backdoors documentadas)
- Cobertura reproducible en cada commit/PR, sin dependencia de revision manual
- Trazabilidad de hallazgos (ubicacion, severidad, remediacion) compatible con flujos de auditoria (SARIF)

**Lo que no garantiza:**

- Backdoors ofuscadas, payloads generados en runtime o ataques polimorficos pueden evadir analisis estatico
- No certifica un sistema como "seguro" o "limpio"
- La defensa primaria de todo juego multijugador sigue siendo la **autoridad del servidor**: validacion de todo input del cliente, idempotencia en transacciones de economia y minimizacion de superficie en la frontera de red

**Postura del producto:** este instrumento reduce el costo del atacante y automatiza la revision; la verificacion de seguridad es un proceso continuo, no un certificado unico.

---

## 10. Hoja de Ruta

| Fase | Contenido | Estado |
|---|---|---|
| 0-4 | Core saneado, pipeline Luau, rule pack v1, demo, SARIF, CI | **Completadas** |
| 5 | Validacion de mercado (entrevistas con estudios, publicacion tecnica), modelo open-core | En curso |
| 6 | Rule pack FiveM (ESX/QBCore, oxmysql, confianza de eventos de economia) | Planificada |
| 7 | Proteccion de IP del lado cliente (ofuscacion Luau) como producto premium | Evaluacion |
| 8 | Plugin de Roblox Studio (puente del CLI hacia el flujo de creadores) | Planificada |

---

## 11. Anexo Tecnico — Referencia Rapida

**Instalacion y uso:**

    pip install hyperium-code-audit
    code-audit scan ./mi-proyecto                          # analisis estandar
    code-audit scan . --rules rulepacks/roblox.yaml        # con rule pack Roblox
    code-audit scan . --format sarif --output roblox.sarif # para GitHub Security
    code-audit scan . --since main                         # incremental (PRs)
    code-audit scan . --fail-on critical                   # gate de CI

**Integracion CI (GitHub Actions):** plantilla lista en templates/github-actions-roblox-scan.yml — escaneo automatico de .lua/.luau en cada PR con subida de SARIF.

**Estructura de extension para nuevos dominios:**

    1. Definir reglas en YAML (formato documentado en seccion 3.4)
    2. Probar contra corpus de fixtures (positivos + codigo limpio para falsos positivos)
    3. Distribuir como rule pack versionado — sin intervencion del motor

---

**Contacto:** Hyperium IA — www.hyperiumia.com | github.com/hyperiumia
**Producto:** github.com/hyperiumia/hyperium-code-audit | Licencia: MIT (nucleo)

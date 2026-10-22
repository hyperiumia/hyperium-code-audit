# Rule Packs — Hyperium Code-Audit

Los rule packs son DATOS (YAML), no codigo: nuevas reglas sin nuevo release.

## Politica de actualizacion (Roblox)

- Actualizacion de reglas: continua. Firmas nuevas de backdoors se publican
  como versiones del pack sin tocar el motor.
- Versionado: cada pack declara su version en el header del YAML.
- Compatibilidad: las reglas usan el formato `custom rules` estable de
  Code-Audit (id, title, severity, category, languages, pattern,
  description, remediation, confidence, cwe_id, owasp_id).

## Limites honestos

Un SAST detecta patrones conocidos. Backdoors ofuscadas o payloads
generados en runtime pueden evadir analisis estatico. Este pack aumenta
el costo del atacante y automatiza la revision; no certifica un juego
como "limpio". La defensa real sigue siendo autoridad del servidor.

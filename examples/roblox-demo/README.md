# Roblox / Luau Demo — Hyperium Code-Audit

Proyecto de demostracion del rule pack Roblox. Archivos separados:

| Archivo | Contenido | Reglas esperadas |
|---|---|---|
| backdoor.luau | Backdoor estilo Toolbox (simulada) | RBX-BD-001/002/003/005, RBX-EXF-002 |
| remotes.luau | Trust boundary y economia sin validar | RBX-TRUST-001/002, RBX-ECON-001/002 |
| clean.luau | Codigo Luau legitimo | ninguno (garantia anti falsos positivos) |

Escanear:

    code-audit scan examples/roblox-demo --custom-rules rulepacks/roblox.yaml

NOTA: los patrones son simulaciones inofensivas con fines educativos.

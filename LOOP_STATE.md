# Estado del loop

Backlog en uso: `docs/BACKLOG.md` (el del proyecto; no se crea otro en la raíz).

## Tarea actual: Campos que hacen invisible una limitación (bloque 1 de la auditoría de visibilidad)

De `docs/BACKLOG.md` → «Workbench UI — the visibility audit», item ◐. Cuatro cerrados en `1a2fa17`
(`Finding.rationale`, `elfBudgetExhausted`, cobertura de búsqueda, `kev.reason`). Quedan los de abajo.

## Definición de hecho (DoD)

- [x] 1. `ResearchResult.hashLookup` se renderiza, y sus **seis** desenlaces son distinguibles entre sí —
      en particular `skipped_salted` (nunca se envió) no puede leerse como `miss` (se consultó y no había).
- [x] 2. `BootDiagnosis.daemonsStarted` / `daemonsExited` se renderizan: «nunca arrancó» ≠ «arrancó y murió con SIGSEGV».
- [ ] 3. `SecureBootPosture.note` y `DeviceTreeResult.rejected` se renderizan.
- [ ] 4. `OperatorAssertion.withdrawnReason` y `FuzzResult.reason` se renderizan.
- [ ] 5. Denominadores de investigación: `osv.skipped`, `nvd.notQueried`, `nvd.truncated[]`, `egress.neverSent`.
- [ ] 6. Cada uno lleva un test que afirma que el caso «no se preguntó» se distingue del caso «se preguntó y no había».

## Puntos flojos detectados

- [x] `hashLookup` entero sin lector — impacto: **alto** — evidencia: `grep -rn hashLookup apps/web/src` sólo
      encontraba `api.ts:676` (el tipo) y un fixture de test. Seis desenlaces producidos por
      `providers/hashlookup.ts:272-366` y ninguno llegaba a pantalla.
- [x] `daemonsStarted`/`daemonsExited` sin lector — impacto: medio — evidencia: `SimulationMenu.tsx` pintaba
      `cause`/`summary`/`evidence` y no la lista de demonios; `api.ts:183-184`.
- [ ] `SecureBootPosture.note` sin lector — impacto: medio — evidencia: `api.ts:126`; `SimulationMenu.tsx:363-386`
      pinta `secureBoot`/`setupMode`/`testKey`/`variableCount` y no `note`, que es la frase del proveedor para
      cuando el almacén de variables no era extraíble.
- [ ] `DeviceTreeResult.rejected` sin lector — impacto: medio — evidencia: `api.ts:948`.
- [ ] `OperatorAssertion.withdrawnReason` sin lector — impacto: medio — evidencia: `OperatorPanel.tsx:67` sólo
      comprueba `status === 'withdrawn'` para un badge; la razón de la retractación no se lee.
- [ ] `FuzzResult.reason` sin lector — impacto: bajo — evidencia: `api.ts:231`.
- [ ] `BootDiagnosis.cause` se muestra como identificador crudo — impacto: bajo — evidencia:
      `SimulationMenu.tsx:466` pinta `{egressShown.unreachable.cause}` sin pasar por locales.
- [ ] Denominadores OSV/NVD sin lector — impacto: medio — evidencia: `api.ts:639-647`, `:671`.

## Historial

- iter 1: renderizado `hashLookup` completo en el panel de investigación (`ImageDetail.tsx:1523` + componente en
  `:1581`), seis desenlaces con etiqueta y significado propios, `skipped_salted` separado de `miss`, y el carril
  apagado dicho como «la pregunta no llegó a hacerse» en vez de una lista vacía. 3 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1731 / web 297, todo verde ·
  `pnpm check` → Done · `pnpm biome` → 413 ficheros, sin errores.
  Punto flojo nuevo detectado, NO implementado (fuera de alcance de esta iteración): `egress.destinations` y
  `egress.neverSent` siguen sin lector aunque `neverSent` es literalmente «estos destinos no se contactaron» —
  ya estaba en la lista del DoD #5, se confirma su ubicación en `api.ts:636`.
- iter 2: lista de demonios renderizada (`SimulationMenu.tsx:501` `DaemonList`), y dos defectos encontrados al
  auditarla: (a) `diagnoseUnreachable` elegía `exited[0]` — truncado por orden de llegada, justo lo que prohíbe la
  regla 4 del proyecto — ahora `rankExits` antepone la muerte por señal, dice cuántos otros salieron y los lista;
  (b) el panel guardaba el resultado del ledger sólo si traía `egress`, así que descartaba el diagnóstico
  precisamente en los arranques que no contactaron nada — que son la mayoría del corpus. 7 tests nuevos.
  Verificación: `pnpm test` → core 75 / api 1735 / web 300, todo verde · `pnpm check` → Done ·
  `pnpm biome` → 431 ficheros sin NUL, 413 comprobados, sin errores.
  Punto flojo nuevo detectado, NO implementado (fuera de alcance): el `cause` se pinta como código crudo
  (`badge` con `no-service-started`) sin frase traducida; `unreachableTitle` es sólo cabecera. Anotado abajo.

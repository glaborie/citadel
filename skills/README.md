# Skill packs

Documentation a specialist may read. Never authority (ADR-011).

```
skills/<agent>/
  manifest.json      pins the sha256 of every file below, plus the pack name
  SKILL.md           the index: always loaded, says which reference is worth reading
  references/*.md    loaded only when the index says the situation matches
```

`src/citadel/skills.py` loads a pack, recomputes every hash and refuses the pack
if one file is missing, changed, or present on disk without being pinned. A
refused pack is a deployment fault, not a retry. `load_pack(agent).prompt(...)`
returns the index, plus the references the caller asked for — that call is the
progressive-disclosure boundary.

A run records `prompt_pack_version`, and `POST /runs` rejects any value that is
not the pack name the deployment actually has. So the version in a trajectory,
an audit event or an eval fixture names hashed content, not a label.

## The boundary

A pack is prose. It cannot declare a tool, widen an allowlist, skip DLP or
override a policy decision — `policy/tools.json` and OpenFGA decide what exists,
and the model loop asks policy for every call regardless of what a skill says. A
pack that does claim authority is a documentation bug caught in review;
`tests/redteam` case RT-INJ-04 proves the runtime consequence is still a deny.

## Editing a pack

1. Change the markdown.
2. Bump `version` and `pack` in that pack's `manifest.json`.
3. `make skills-lock` to re-hash every pack.
4. Review the manifest diff: a hash change you cannot explain is the signal this
   mechanism exists for.

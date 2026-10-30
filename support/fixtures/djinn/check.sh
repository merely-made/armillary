#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
metadata_dir="${DJINN_METADATA_DIR:-${TMPDIR:-/tmp}/djinn-fixture-metadata}"
mkdir -p "$metadata_dir"
for fixture in portable native custody-types custody resident; do
  echo "Fixture: $fixture"
  cargo test --offline --locked --manifest-path "$fixture/Cargo.toml" --lib
  cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path "$fixture/Cargo.toml" > "$metadata_dir/$fixture.json"
  python3 - "$metadata_dir/$fixture.json" "$metadata_dir/$fixture-cone.json" <<'PYCODE'
import json,sys
m=json.load(open(sys.argv[1])); packages={p['id']:p for p in m['packages']}; nodes={n['id']:n for n in m['resolve']['nodes']}; seen=set(); pending=[m['resolve']['root']]
while pending:
    ident=pending.pop()
    if ident in seen: continue
    seen.add(ident)
    for d in nodes[ident]['deps']:
        if any(k['kind'] in (None,'build') for k in d['dep_kinds']): pending.append(d['pkg'])
forbidden=('mere','knot','graphshell','sceno','distillery','hest','chirograph')
bad=sorted({packages[i]['name'] for i in seen if any(x in packages[i]['name'].lower() for x in forbidden)})
root=nodes[m['resolve']['root']]
djinn=next(d['pkg'] for d in root['deps'] if packages[d['pkg']]['name']=='djinn')
direct=[]
for dep in nodes[djinn]['deps']:
    kinds=sorted({k['kind'] or 'normal' for k in dep['dep_kinds'] if k['kind'] in (None,'build')})
    if kinds: direct.append({'name':packages[dep['pkg']]['name'],'kinds':kinds,'features':nodes[dep['pkg']]['features']})
report={'normal_build_packages':sorted({packages[i]['name'] for i in seen}), 'forbidden':bad, 'root_features':root['features'], 'djinn_features':nodes[djinn]['features'], 'djinn_direct_edges':sorted(direct,key=lambda e:e['name'])}
with open(sys.argv[2],'w') as out: json.dump(report,out,indent=2);out.write('\n')
print('normal/build packages:',len(seen),'forbidden:',bad,'djinn features:',report['djinn_features'])
assert not bad
PYCODE
  if [[ -f "$fixture/examples/forbidden.rs" ]]; then
    logfile="$metadata_dir/$fixture-forbidden.log"
    case "$fixture" in
      portable|native) symbol=custody ;;
      custody-types) symbol=custody_client ;;
      resident) symbol=door ;;
      *) echo "Unknown forbidden fixture: $fixture"; exit 1 ;;
    esac
    if cargo check --offline --locked --manifest-path "$fixture/Cargo.toml" --example forbidden > "$logfile" 2>&1; then cat "$logfile"; exit 1; fi
    if ! grep -q 'error\[E0432\]' "$logfile" || ! grep -Fq "no \`$symbol\` in" "$logfile"; then cat "$logfile"; exit 1; fi
    echo "forbidden import: expected E0432 for $symbol"
  fi
done
cargo check --offline --locked --manifest-path portable/Cargo.toml --target wasm32-unknown-unknown

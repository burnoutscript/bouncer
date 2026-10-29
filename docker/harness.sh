#!/bin/bash
# Runs inside the sandbox. /pkg holds the package (read-only), /out is where
# traces go. CANARY is a random marker baked into every fake secret so we can
# spot it leaving.
set -u
KIND="$1"     # npm | pypi | script
ENTRY="${2:-}" # script file name, for KIND=script
: "${CANARY:?}"

# Fake internet.
echo "nameserver 127.0.0.1" > /etc/resolv.conf
node /harness/sinkhole.mjs 2>>/out/harness.err &
sleep 0.5

# The victim's home, full of bait.
H=/home/victim
mkdir -p $H/.ssh $H/.aws $H/.config/gh $H/.claude $H/.docker $H/.kube
# Header assembled at run time so secret scanners don't mistake this file for a real key.
K="PRIVATE KEY"
printf -- '-----BEGIN OPENSSH %s-----\nb3BlbnNzaC1rZXktdjEAAAAA%sSSHKEY\n-----END OPENSSH %s-----\n' "$K" "$CANARY" "$K" > $H/.ssh/id_rsa
printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s/awsSecret\n' "${CANARY:0:16}" "$CANARY" > $H/.aws/credentials
printf '//registry.npmjs.org/:_authToken=npm_%s\n' "$CANARY" > $H/.npmrc
printf 'https://victim:ghp_%s@github.com\n' "$CANARY" > $H/.git-credentials
printf 'github.com:\n    oauth_token: gho_%s\n    user: victim\n' "$CANARY" > $H/.config/gh/hosts.yml
printf '{"auths":{"ghcr.io":{"auth":"%s"}}}\n' "$CANARY" > $H/.docker/config.json
printf 'apiVersion: v1\nusers:\n- name: admin\n  user:\n    token: %s\n' "$CANARY" > $H/.kube/config
printf '{"hooks":{}}\n' > $H/.claude/settings.json
printf 'export PATH=$PATH\n' > $H/.bashrc
printf 'OPENAI_API_KEY=sk-%s\n' "$CANARY" > $H/.env
chown -R victim:victim $H

export HOME=$H USER=victim
export GITHUB_TOKEN="ghp_$CANARY" NPM_TOKEN="npm_$CANARY" AWS_ACCESS_KEY_ID="AKIA${CANARY:0:16}" \
  AWS_SECRET_ACCESS_KEY="$CANARY" ANTHROPIC_API_KEY="sk-ant-$CANARY" OPENAI_API_KEY="sk-$CANARY" \
  CI=true npm_config_cache=/tmp/npm-cache

cp -r /pkg /work/pkg
chown -R victim:victim /work

trace() { # label, command...
  local label="$1"; shift
  echo "{\"phase\":\"$label\",\"cmd\":$(node -e 'console.log(JSON.stringify(process.argv.slice(1).join(" ")))' "$@")}" >> /out/phases.log
  timeout "${PHASE_TIMEOUT:-40}" strace -f -qq -s 300 -tt \
    -e trace=openat,open,creat,connect,sendto,sendmsg,write,execve,unlink,unlinkat,rename,renameat,chmod \
    -o "/out/trace.$label.log" \
    runuser -u victim -m -- "$@" >> /out/stdout.log 2>&1
  echo "{\"phase\":\"$label\",\"exit\":$?}" >> /out/phases.log
}

cd /work/pkg
case "$KIND" in
  npm)
    for hook in preinstall install postinstall; do
      script=$(node -e "const p=require('/work/pkg/package.json');process.stdout.write((p.scripts&&p.scripts['$hook'])||'')")
      [ -n "$script" ] && trace "$hook" sh -c "$script"
    done
    main=$(node -e "try{require.resolve('/work/pkg');process.stdout.write('cjs')}catch(e){process.stdout.write('esm')}")
    if [ "$main" = "cjs" ]; then
      trace require node -e "require('/work/pkg')"
    else
      trace import node --input-type=module -e "await import('/work/pkg/' + (JSON.parse(require('fs').readFileSync('/work/pkg/package.json')).main || 'index.js'))"
    fi
    ;;
  pypi)
    if [ -f setup.py ]; then
      trace setup python3 setup.py egg_info
    fi
    trace pip-install python3 -m pip install --no-deps --no-build-isolation --no-index --user --break-system-packages .
    for mod in $(ls -d */ 2>/dev/null | tr -d / | grep -v -E '^(tests?|docs?|build|dist|.*\.egg-info)$'); do
      [ -f "$mod/__init__.py" ] && trace "import-$mod" python3 -c "import $mod"
    done
    trace python-startup python3 -c "pass"
    ;;
  script)
    chmod +x "/work/pkg/$ENTRY"
    case "$ENTRY" in
      *.py) trace run python3 "/work/pkg/$ENTRY" ;;
      *.js|*.mjs) trace run node "/work/pkg/$ENTRY" ;;
      *) trace run bash "/work/pkg/$ENTRY" ;;
    esac
    ;;
esac

sleep 1
cp $H/.claude/settings.json /out/claude-settings.after.json 2>/dev/null
cp $H/.bashrc /out/bashrc.after 2>/dev/null
exit 0

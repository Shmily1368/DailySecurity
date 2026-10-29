#!/usr/bin/env bash
set -eu
# Ephemeral repository-local entry; checkout retains its local HTTPS auth header.
cat > git-personal <<'SCRIPT'
#!/usr/bin/env bash
set -eu
for variable in $(compgen -e); do
  case "$variable" in GIT_*) unset "$variable" ;; esac
done
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Shmily1368 GIT_AUTHOR_EMAIL=1099509685@qq.com
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
exec /usr/bin/git "$@"
SCRIPT
chmod 700 git-personal

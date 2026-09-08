#!/bin/sh
# waxseal installer. POSIX sh — no bashisms, no arrays, no `local`.
#
#   curl -fsSL https://raw.githubusercontent.com/cuongbphv/waxseal/main/deploy/install.sh | sh
#   sh install.sh --version 0.1.6 --method pyz
#   sh install.sh --method pyz --from-dir dist --prefix /opt/waxseal   # offline
#   sh install.sh --dry-run                                            # print, do nothing
#
# Preference order: `uv tool install` -> `pipx install` -> `pip install --user`
# -> the single-file zipapp. The first three come from PyPI and are the normal
# answer; the zipapp is the answer for an air-gapped machine, and it is the
# only path this script downloads a raw file for. That path therefore VERIFIES
# the file before anything is executed:
#
#   * SHA256SUMS is fetched alongside the artifact and the digest must match.
#     A mismatch aborts, and nothing is run, moved or installed.
#   * The sigstore bundle is checked too, IF `python3 -m sigstore` is present.
#     If it is not, the run prints a LABELLED notice saying the signature was
#     not checked, and says what would check it. CLAUDE.md rule 6: a
#     degradation is recorded in the output, never swallowed. "Unchecked" with
#     no remedy is only marginally better than silence.
#
# A checksum-verified download is not a provenance guarantee: SHA256SUMS comes
# from the same release as the artifact, so it proves the bytes are the bytes
# that release published, not who published them. The sigstore step is the one
# that speaks to origin, which is why its absence is printed rather than
# assumed away.
#
# Every path this script writes is ABSOLUTE. src/waxseal/integrations/
# _trail.py refuses a `WAXSEAL_TRAIL` beginning with `~` because a tilde that
# reaches a unit file or a container never expands; the same discipline applies
# to a prefix, so `--prefix ~/x` is expanded by the shell that calls this
# script or not accepted at all.

set -eu

REPO="cuongbphv/waxseal"
VERSION=""
METHOD=""
PREFIX=""
FROM_DIR=""
DRY_RUN=0

MIN_PY_MAJOR=3
MIN_PY_MINOR=11

# ---- output ------------------------------------------------------------------
# stderr for everything but the final "installed at" line, so piping this
# script's stdout somewhere never swallows a warning.

info()  { printf '    %s\n' "$*" >&2; }
step()  { printf '\n==> %s\n' "$*" >&2; }
warn()  { printf 'warning: %s\n' "$*" >&2; }
die()   { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# A degradation, labelled as one. Distinct from warn() so it is greppable in a
# CI log and so it always names its own remedy (CLAUDE.md rule 6).
notice_unchecked() {
    printf '\nNOTICE [unverified]: %s\n' "$1" >&2
    printf '            remedy: %s\n' "$2" >&2
}

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] %s\n' "$*" >&2
        return 0
    fi
    "$@"
}

# ---- arguments ---------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --version)   shift; [ $# -gt 0 ] || die "--version needs a value"; VERSION="$1" ;;
        --version=*) VERSION="${1#--version=}" ;;
        --method)    shift; [ $# -gt 0 ] || die "--method needs a value"; METHOD="$1" ;;
        --method=*)  METHOD="${1#--method=}" ;;
        --prefix)    shift; [ $# -gt 0 ] || die "--prefix needs a value"; PREFIX="$1" ;;
        --prefix=*)  PREFIX="${1#--prefix=}" ;;
        --from-dir)  shift; [ $# -gt 0 ] || die "--from-dir needs a value"; FROM_DIR="$1" ;;
        --from-dir=*) FROM_DIR="${1#--from-dir=}" ;;
        --dry-run)   DRY_RUN=1 ;;
        -h|--help)   usage ;;
        *)           die "unknown flag $1 (try --help)" ;;
    esac
    shift
done

case "$METHOD" in
    ""|uv|pipx|pip|pyz) : ;;
    *) die "--method must be one of uv, pipx, pip, pyz (got '$METHOD')" ;;
esac

case "$PREFIX" in
    "~"*) die "--prefix must be an absolute path, not '$PREFIX' — a tilde that reaches a unit file or a container never expands (see src/waxseal/integrations/_trail.py)" ;;
esac

if [ -n "$FROM_DIR" ] && [ "$METHOD" != "pyz" ]; then
    die "--from-dir applies to --method pyz only (an offline install has no index to reach)"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# ---- python floor ------------------------------------------------------------
# requires-python = ">=3.11" in pyproject.toml. Checked before anything is
# downloaded: an artifact on disk that this machine cannot run is worse than a
# clear refusal, because it looks installed.

check_python() {
    have python3 || die "python3 is not on PATH. waxseal needs Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR} or newer."
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)"; then
        found="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo unknown)"
        die "python3 is $found, but waxseal needs ${MIN_PY_MAJOR}.${MIN_PY_MINOR} or newer. Install a newer Python (or use \`uv tool install waxseal\`, which fetches its own) and re-run."
    fi
    info "python3 $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
}

# ---- checksum ----------------------------------------------------------------

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "neither sha256sum nor \`shasum -a 256\` is available, so the download cannot be verified. Refusing to install an unverified artifact — install coreutils (or use --method uv/pipx/pip)."
    fi
}

# The expected digest for one file name, read out of a SHA256SUMS in the
# `<digest>  <name>` format `sha256sum` writes. Matching on the basename so a
# SHA256SUMS generated with `./dist/x.pyz` and one with `x.pyz` both work.
expected_digest() {
    sums="$1"; name="$2"
    awk -v want="$name" '
        {
            n = $NF
            sub(/^\*/, "", n)
            sub(/.*\//, "", n)
            if (n == want) { print $1; found = 1; exit }
        }
        END { if (!found) exit 1 }
    ' "$sums"
}

verify_checksum() {
    artifact="$1"; sums="$2"
    name="$(basename "$artifact")"
    step "Verifying $name"
    want="$(expected_digest "$sums" "$name")" || die "$name is not listed in $(basename "$sums"). Refusing to install an artifact whose digest was never published."
    got="$(sha256_of "$artifact")"
    if [ "$want" != "$got" ]; then
        # The one branch that matters. Nothing downloaded has been executed at
        # this point and nothing will be: the file stays where it is, unmoved
        # and unrun, so the operator can look at it.
        die "CHECKSUM MISMATCH for $name
    expected: $want
    actual:   $got
  The downloaded file does NOT match the digest published for this release.
  It has not been executed, installed or moved. Do not run it. Re-download,
  and if it mismatches again, report it before running anything."
    fi
    info "sha256 ok: $got"
}

# Signature checking is a separate dimension from the checksum, with three
# outcomes and not two: verified, verifiably bad, or not checked. The third is
# printed with its own label and its own remedy rather than passed over.
verify_signature() {
    artifact="$1"; bundle="$2"
    step "Verifying signature of $(basename "$artifact")"
    if ! python3 -m sigstore --version >/dev/null 2>&1; then
        notice_unchecked \
            "signature NOT checked: \`python3 -m sigstore\` is not available. The sha256 above proves these are the bytes the release published; it says nothing about who published them." \
            "python3 -m pip install sigstore, then re-run this installer (or verify by hand: python3 -m sigstore verify github --repository $REPO $artifact)"
        return 0
    fi
    if [ ! -f "$bundle" ]; then
        notice_unchecked \
            "signature NOT checked: no sigstore bundle found at $bundle. sigstore is installed, so this is a missing input, not a missing tool." \
            "download ${artifact##*/}.sigstore.json from the release next to the artifact and re-run"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] python3 -m sigstore verify github --repository $REPO --bundle $bundle $artifact"
        return 0
    fi
    if python3 -m sigstore verify github \
            --repository "$REPO" \
            --bundle "$bundle" \
            "$artifact" >&2; then
        info "sigstore ok"
    else
        die "SIGNATURE VERIFICATION FAILED for $(basename "$artifact"). Checked, and false — this is not an unchecked state. The file has not been installed. Do not run it."
    fi
}

# ---- download ----------------------------------------------------------------

fetch() {
    url="$1"; dest="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] fetch $url -> $dest"
        return 0
    fi
    if have curl; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    elif have wget; then
        wget -q -O "$dest" "$url"
    else
        die "neither curl nor wget is available, so nothing can be downloaded. Use --from-dir <dir> with artifacts already on this machine."
    fi
}

# ---- methods -----------------------------------------------------------------

pkg_spec() {
    if [ -n "$VERSION" ]; then
        printf 'waxseal==%s' "$VERSION"
    else
        printf 'waxseal'
    fi
}

install_uv() {
    step "Installing with uv"
    run uv tool install "$(pkg_spec)"
    info "uv manages its own shims; \`uv tool update-shell\` if \`waxseal\` is not on PATH"
}

install_pipx() {
    step "Installing with pipx"
    run pipx install "$(pkg_spec)"
}

install_pip() {
    step "Installing with pip (--user)"
    check_python
    run python3 -m pip install --user --upgrade "$(pkg_spec)"
    info "installs into your user site; \`python3 -m site --user-base\`/bin must be on PATH"
}

install_pyz() {
    step "Installing the single-file zipapp"
    check_python

    bindir="${PREFIX:-$HOME/.local}/bin"
    libdir="${PREFIX:-$HOME/.local}/lib/waxseal"

    if [ -n "$FROM_DIR" ]; then
        # Offline: the artifacts are already here. Absolute-ised so every
        # message and every wrapper below names a path that still resolves
        # from anywhere.
        [ -d "$FROM_DIR" ] || die "--from-dir $FROM_DIR is not a directory"
        srcdir="$(cd "$FROM_DIR" && pwd)"
        artifact="$(ls "$srcdir"/waxseal-*.pyz 2>/dev/null | head -n 1)" \
            || die "no waxseal-*.pyz in $srcdir (build one with: python3 tools/build_pyz.py)"
        [ -n "$artifact" ] || die "no waxseal-*.pyz in $srcdir (build one with: python3 tools/build_pyz.py)"
        sums="$srcdir/SHA256SUMS"
        [ -f "$sums" ] || die "no SHA256SUMS in $srcdir. Refusing to install an artifact whose digest was never published — an unverified installer is worse than none."
        bundle="$artifact.sigstore.json"
        info "offline install from $srcdir"
    else
        [ -n "$VERSION" ] || die "--method pyz needs --version <x.y.z> (or --from-dir <dir> for an offline install): the release assets are addressed by tag."
        base="https://github.com/$REPO/releases/download/v$VERSION"
        workdir="$(mktemp -d)"
        # No `trap ... EXIT` cleanup on the MISMATCH path by design: if the
        # digest is wrong the operator is told exactly where the file is, and
        # deleting the evidence out from under them would be the wrong help.
        artifact="$workdir/waxseal-$VERSION.pyz"
        sums="$workdir/SHA256SUMS"
        bundle="$artifact.sigstore.json"
        step "Downloading waxseal $VERSION"
        fetch "$base/waxseal-$VERSION.pyz" "$artifact"
        fetch "$base/SHA256SUMS" "$sums"
        # Best-effort: a release without a bundle is an unchecked signature,
        # which verify_signature reports as such rather than failing over.
        fetch "$base/waxseal-$VERSION.pyz.sigstore.json" "$bundle" 2>/dev/null || true
        srcdir="$workdir"
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        verify_checksum "$artifact" "$sums"
    else
        info "[dry-run] verify sha256 of $(basename "$artifact") against $sums"
    fi
    verify_signature "$artifact" "$bundle"

    # ONLY past this point does anything downloaded get moved or executed.
    step "Installing to $bindir"
    run mkdir -p "$bindir" "$libdir"
    target="$libdir/$(basename "$artifact")"
    run cp "$artifact" "$target"
    run chmod 0755 "$target"

    wrapper="$bindir/waxseal"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] write wrapper $wrapper -> exec python3 $target"
    else
        # A wrapper rather than a symlink: `exec python3 <pyz>` works whatever
        # the file is called and whatever the shebang's `python3` resolves to
        # on this box, and it keeps the exit code intact — `exec` replaces the
        # shell, so verify's 0/1/2/3 reach the caller unmodified. A wrapper
        # that ran the pyz as a child and forgot to propagate `$?` would print
        # a break and exit 0.
        cat > "$wrapper" <<WRAPPER
#!/bin/sh
exec python3 "$target" "\$@"
WRAPPER
        chmod 0755 "$wrapper"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%s\n' "[dry-run] would install: $wrapper"
    else
        "$wrapper" --help >/dev/null || die "installed, but \`$wrapper --help\` did not run cleanly"
        printf '%s\n' "installed: $wrapper"
    fi
    case ":${PATH}:" in
        *":$bindir:"*) : ;;
        *) info "$bindir is not on PATH — add it: export PATH=\"$bindir:\$PATH\"" ;;
    esac
}

# ---- main --------------------------------------------------------------------

if [ -n "$METHOD" ]; then
    case "$METHOD" in
        uv)   have uv   || die "--method uv asked for, but \`uv\` is not on PATH"
              install_uv ;;
        pipx) have pipx || die "--method pipx asked for, but \`pipx\` is not on PATH"
              install_pipx ;;
        pip)  install_pip ;;
        pyz)  install_pyz ;;
    esac
    exit 0
fi

# No --method: take the first that is present. The order is preference, not
# capability — every one of these installs the same wheel.
if have uv; then
    install_uv
elif have pipx; then
    install_pipx
elif have python3 && python3 -m pip --version >/dev/null 2>&1; then
    install_pip
else
    info "no uv, pipx or pip found — falling back to the single-file zipapp"
    install_pyz
fi

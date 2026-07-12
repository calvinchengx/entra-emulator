# Demo GIF

`demo.gif` is the README hero — OIDC discovery → a client-credentials token →
its decoded Entra v2.0 claims, all against the local binary.

## Regenerate

Deterministic via [VHS](https://github.com/charmbracelet/vhs) — the `.tape` is
the source of truth:

```sh
brew install vhs        # pulls ttyd + ffmpeg
vhs docs/demo/demo.tape # run from the repo root → rewrites demo.gif
```

The tape builds and starts the emulator itself (compat mode on `:8099`), runs
the demo commands, then stops it. `jwt` is a tiny base64url JWT-claims decoder
used by the recording.

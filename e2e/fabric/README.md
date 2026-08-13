# Fabric companion witness

[fabric-emulator](https://github.com/calvinchengx/fabric-emulator) completing
the workspace-identity handshake against **this** entra checkout. entra's own
Go tests already cover the admin API and the Fabric-audience mint; they cannot
prove a stranger consumes them.

```sh
python3 e2e/fabric/run.py
```

The script clones fabric-emulator at a pinned commit, `go mod edit -replace`s
`github.com/calvinchengx/entra-emulator` to this tree, and runs
`TestWorkspaceIdentityHandshake` and `TestWorkspaceIdentityCascadeDelete`.
Those tests start entra in-process via the public `emulator` package, then
drive provision / mint / rename / deprovision / cascade-delete over HTTP —
the same calls fabric makes in production. `newFixture` also performs a real
`client_credentials` grant for `https://api.fabric.microsoft.com/.default`.

Override `FABRIC_REPO` / `FABRIC_PIN` only when bisecting the pin.

# If `deno` not found, use `mise`

Use [mise](https://mise.jdx.dev/) to manage tool versions.
The steps below show how to work with the configured runtimes.

## install mise
`curl https://mise.run | sh`

Ensure the configured tools are installed:
```bash
mise install
```

## Deno
Run any Deno command through mise so the pinned version is used. Examples:
   ```bash
   mise exec -- deno check
   mise exec -- deno task dev
   mise exec -- deno run --allow-env --allow-net server/src/index.ts
   ```

## Python (optional)

If you need Python, activate it via mise and then execute commands the same way:

```bash
mise use python
mise exec -- python path/to/script.py
```

`mise exec` ensures the tools defined in `mise.toml` are on PATH without
polluting your shell environment.

# run `deno fmt && deno lint` after your jobs
If `deno lint` returns error, fix them.

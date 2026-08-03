# Releasing — tags, versioning

`userauth` is a library: a release is just a semver tag on `main` — there are no
binaries, packages, or release workflows.

## How a release happens

```bash
make tag version="v1.2.3"
```

`make tag` refuses unless you are on `main` with a clean working tree, then runs
the full `make verify` gate (test + license-check + lint + benchmark + coverage)
before creating and pushing the annotated `vX.Y.Z` tag. Any stale local/remote
tag of the same name is deleted first, so a botched tag can be redone with the
same command.

## Things to keep in mind

- **The `replace github.com/go-bumbu/http => ../http` directive in go.mod**
  affects local development only — module consumers resolve the published
  `go-bumbu/http` version. Make sure the required version in `require` is
  actually published before tagging.
- Breaking API changes are acceptable pre-v1 but should be deliberate — the
  library is consumed by sibling applications (e.g. Persona); grep those for
  usage before renaming exported identifiers.

# Git tracking policy

Track source, tests, example configuration, dependency lockfiles, contracts and
compact evidence. Keep credentials, environments, build outputs and runtime
databases outside source control. Generate Git contribution reports under
`reports/gitinspector/` or in an external directory.

Store new observation-scale arrays, model payloads and release archives outside
Git. Keep existing tracked arrays and models available until a recipient can
obtain the replacement archive, verify its checksum and reproduce the consuming
workflow. Follow the [experiment artifact guide](experiment-artifacts.md).

Preserve the original bytes of accepted results, receipts and manifests. Record
corrections in a new receipt and retain original run IDs and source revisions.
Treat a lockfile migration as a separate change with a verified install and build.

Before merging a cleanup, review the exact staged paths and run
`git diff --cached --check`. Confirm that removed paths are backed up and that
documented commands still work from a clean checkout.

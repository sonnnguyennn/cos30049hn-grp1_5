# Git contribution reports (Windows / PowerShell)

Gitinspector is installed as an isolated user tool using `uv`, separate from
the backend and ML environments. The verified upstream revision is
`b3a0a5a395499c5508c9a45a97da5397c75e1e86` (0.5.2dev).

```powershell
uv tool install --python 3.10 git+https://github.com/ejwa/gitinspector.git@b3a0a5a395499c5508c9a45a97da5397c75e1e86
gitinspector --version
```

From the repository root, generate HTML and text reports:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\git-report.ps1
Start-Process .\reports\gitinspector\HEAD\source.html
```

Analyze another branch without checking it out:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\git-report.ps1 -Branch origin/main
Start-Process .\reports\gitinspector\origin_main\source.html
```

Each output directory contains:

- `source.html` / `source.txt`: code changes, surviving lines, activity timeline,
  and files associated with each author. Extensions include Python, JavaScript,
  TypeScript, JSX/TSX, CSS, HTML, SQL, shell and PowerShell.
- `all.html` / `all.txt`: all tracked file types, including documentation,
  notebooks, CSV data, JSON artifacts and lockfiles. Generated files can dominate
  these line counts; binary content is not measured as text lines.
- `scope.txt`: selected branch, exact commit and unfiltered author commit counts.

Reports are ignored by Git. Only committed history reachable from the chosen
revision is analyzed. Local uncommitted work and other branches are not included.
Remote-tracking branches reflect the last fetch; run `git fetch origin` when you
want to refresh them before reporting.

For an overview of all refs currently available locally:

```powershell
git rev-list --all --count
git shortlog -sne --all
```

These overview commands combine reachable commits across refs and count each
commit once. They have a different scope from a single-branch Gitinspector report.
Author names/emails may represent multiple identities for one person; review
them before creating a `.mailmap`. Commit totals and lines changed are evidence
of Git activity, not a complete assessment of a teammate's work or quality.

Official documentation: https://github.com/ejwa/gitinspector

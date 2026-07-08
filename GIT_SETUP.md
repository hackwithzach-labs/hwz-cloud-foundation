> NOTE: delete the stray `.git/` folder in this directory first (a failed init left it behind on the synced drive). On Windows just delete the `.git` folder in Explorer, then run the commands below.

# Turning this into your git repo

This folder is the reference build. It ships as plain files, not a git repo, so
you create the repo yourself. That is step one of the course anyway.

```bash
cd module-01-cloud-foundation
git init
git add -A
git commit -m "Module 1: cloud foundation baseline + hwz-scan"
# then create an EMPTY private repo on GitHub and:
git remote add origin git@github.com:<you>/hwz-cloud-foundation.git
git branch -M main
git push -u origin main
```

The .gitignore here already blocks terraform state and real tfvars, so your
credentials never leave your machine. Commit the settings, never the state.

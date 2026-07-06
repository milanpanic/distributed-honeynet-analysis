# GitHub upload guide

## Recommended repository name

`distributed-honeynet-analysis`

## Recommended visibility

Use a **private** repository until the paper is accepted and all co-authors agree that the code may be public.

## Option A - Upload through GitHub web interface

1. Open GitHub and create a new repository named `distributed-honeynet-analysis`.
2. Choose **Private** first.
3. Do not add a README on GitHub if you are uploading this prepared folder, because it already contains one.
4. Upload the files/folders from this package.
5. Add professors/co-authors as collaborators if needed.

## Option B - Upload using Git from your computer

```bash
cd distributed-honeynet-analysis
git init
git add .
git commit -m "Initial honeynet analysis code"
git branch -M main
git remote add origin https://github.com/USERNAME/distributed-honeynet-analysis.git
git push -u origin main
```

Replace `USERNAME` with your GitHub username or organization.

## Option C - GitHub CLI

```bash
cd distributed-honeynet-analysis
gh repo create USERNAME/distributed-honeynet-analysis --private --source=. --remote=origin --push
```

## What should not be uploaded publicly

- Raw Cowrie/DDoSPot logs with real source IP addresses
- Downloaded payloads or malware samples
- Credentials captured by honeypots
- PCAP files
- Internal IP ranges and firewall details
- Unpublished manuscript/email text before co-author and journal approval

## Suggested GitHub release structure

After the paper is accepted, create a release such as `v1.0-paper-supplement` and attach:

- source code
- anonymized sample dataset
- generated statistical report
- citation information

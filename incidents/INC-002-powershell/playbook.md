# INC-002 — Playbook: PowerShell Execution & Persistence

## Trigger

Alert fires on PowerShell execution with `ExecutionPolicy Bypass` spawned from `cmd.exe`.

## Step 1 — Triage

- [ ] Confirm parent process chain: `explorer.exe → cmd.exe → powershell.exe`
- [ ] Review `CommandLine` field for suspicious arguments
- [ ] Check if execution originated from a user download or temp directory
- [ ] Determine if the process is still running

## Step 2 — Investigation

- [ ] Query Sysmon Event ID 1 for full process tree
- [ ] Search for file creation events (Event ID 11) from the PowerShell process
- [ ] Search for registry modification events (Event ID 13) — focus on Run keys
- [ ] Check for network connections (Event ID 3) from PowerShell process
- [ ] Retrieve and analyze the script file if accessible

## Step 3 — Containment

- [ ] Isolate endpoint if live malware confirmed
- [ ] Kill the PowerShell process if still running
- [ ] Remove the registry persistence key
- [ ] Delete payload script and any created artifacts

## Step 4 — Recovery

- [ ] Verify registry key is removed
- [ ] Confirm no additional persistence mechanisms (scheduled tasks, startup folder)
- [ ] Reset user credentials if compromise is suspected
- [ ] Re-image endpoint if persistence was confirmed active for an extended period

## Step 5 — Post-Incident

- [ ] Update detection rules with observed indicators
- [ ] Create/update Sigma rule for this pattern
- [ ] Document IOCs (script path, registry key name, artifact path)
- [ ] Review PowerShell execution policy across all endpoints

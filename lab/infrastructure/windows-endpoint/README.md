# Windows Endpoint

> Victim machine used for adversary emulation scenarios. Runs Sysmon for deep endpoint telemetry and Winlogbeat to ship Windows Event Logs to the ELK SIEM.

---

## Host Profile

| Field | Value |
|---|---|
| Hostname | DESKTOP-DPU3CDQ |
| OS | Windows 10 x64 |
| IP | 172.16.0.10/24 |
| RAM | 2 GB |
| CPU | 2 vCPU |
| User | END-Alex |
| Network | VMnet3 (lab internal) |

---

## Sysmon

| Field | Value |
|---|---|
| Version | v15.15 |
| Binary | C:\Sysmon\Sysmon64.exe |
| Service | Sysmon64 — Running, Automatic |
| Config | C:\Sysmon\sysmonconfig.xml |
| Installed | 12/23/2025 |

### What Sysmon Captures

| Event ID | Description |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded (DLL) |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess (credential dumping) |
| 11 | File created |
| 12/13 | Registry events |
| 22 | DNS query |

> Sysmon events are forwarded to Elasticsearch via Winlogbeat under the `winlogbeat-*` index pattern.

---

## Winlogbeat

| Field | Value |
|---|---|
| Version | 8.17.0 (amd64) |
| Binary | C:\winlogbeat\winlogbeat.exe |
| Service | winlogbeat — Running, Automatic |
| Config | C:\winlogbeat\winlogbeat.yml |
| Installed | 1/28/2026 |
| Ships to | Logstash on 172.16.0.4:5044 |

### Event Channels Collected

| Channel | Purpose |
|---|---|
| Microsoft-Windows-Sysmon/Operational | All Sysmon events |
| Windows PowerShell | PowerShell activity |
| Microsoft-Windows-PowerShell/Operational | Script block logging |
| Security | Logon/logoff, auth events |
| System | System-level events |

---

## Log Flow

```
Windows Endpoint
     |
  Sysmon (kernel-level telemetry)
     |
  Windows Event Log
     |
  Winlogbeat
     |
  Logstash :5044 (172.16.0.4)
     |
  Elasticsearch
     |
  Kibana (SIEM dashboards)
```

---

## Lab Role

- **Primary target** for all adversary emulation scenarios
- **Telemetry source** — Sysmon provides process, network, and registry visibility
- **Detection validation** — attacks executed here trigger alerts visible in Kibana

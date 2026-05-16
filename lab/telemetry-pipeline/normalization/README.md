# Log Normalization

This folder contains Logstash pipeline configs and ECS normalization work for the lab.

---

## Current Status

| Source | ECS Normalized | Notes |
|---|---|---|
| Winlogbeat (Sysmon) | ✅ Partial | Standard ECS fields populated by Winlogbeat |
| Filebeat (auth.log) | ❌ Raw only | `source.ip`, `user.name`, `event.outcome` not parsed yet |
| Suricata EVE JSON | ✅ Good | Most fields map to ECS natively |
| pfSense syslog | ❌ Raw only | Needs grok parsing |

---

## Next Step — SSH Auth Log Grok Parser

Add this filter to Logstash to parse ECS fields from raw SSH messages:

```ruby
filter {
  if [log_source] == "filebeat-linux" {
    grok {
      match => {
        "message" => [
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host.name} sshd\[%{NUMBER:process.pid}\]: %{WORD:event.outcome:failure} password for %{USERNAME:user.name} from %{IP:source.ip} port %{NUMBER:source.port} ssh2",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host.name} sshd\[%{NUMBER:process.pid}\]: %{WORD:event.outcome:success} password for %{USERNAME:user.name} from %{IP:source.ip} port %{NUMBER:source.port} ssh2"
        ]
      }
    }
    mutate {
      add_field => { "event.category" => "authentication" }
    }
  }
}
```

> Once deployed, this enables EQL correlation rules in Elastic Security.

# Correlation Rules — EQL

This folder will contain EQL Event Correlation rules once ECS field parsing is implemented.

---

## Status

**Blocked** — ECS fields `source.ip`, `user.name`, `event.outcome`, and `event.category` are not yet parsed from raw SSH auth log messages. The ingest pipeline must be built first.

---

## Planned Rules

### SSH Brute-Force Success Sequence (INC-009)

```eql
sequence by host.name, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
```

**Requires:**
- Logstash grok filter parsing `source.ip`, `user.name`, `event.outcome` from `/var/log/auth.log`
- Or an Elasticsearch ingest pipeline with the same grok patterns

---

## Engineering Path

1. Build Logstash grok filter for SSH auth log parsing
2. Validate ECS fields appear in Kibana Discover
3. Build EQL rule in Elastic Security → Event Correlation type
4. Add alert suppression by `source.ip`
5. Wire notification connector (email / webhook)

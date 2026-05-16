# Sigma — Detection Engineering Drafts

This folder is the **working area** for Sigma rule development.  
Finalized and validated rules are promoted to [`detections/sigma/`](../../detections/sigma/).

---

## Workflow

1. Draft rule here during incident investigation
2. Validate the rule logic against real lab data in Kibana
3. Test for false positives in a clean environment
4. Move to `detections/sigma/` once validated
5. Reference from the incident's `detection.md`

> See [`detections/sigma/README.md`](../../detections/sigma/README.md) for validated rules.

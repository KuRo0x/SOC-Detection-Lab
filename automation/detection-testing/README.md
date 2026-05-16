# Detection Testing

Scripts and test cases to validate that detection rules fire correctly on known-bad input.

---

## Testing Approach

1. Run the corresponding attack script from `attack-scripts/`
2. Wait for Elastic Security to process the alert (rule schedule: 1 min)
3. Verify alert appears in Kibana → Security → Alerts
4. Confirm fields: `host.name`, `message`, rule name, MITRE tags
5. Log the result in `metrics/detection-coverage/`

> Add test case scripts and validation checklists here.

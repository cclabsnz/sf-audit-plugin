# spec/

Rules in when/then form. Each rule:

```
## RULE-001 <title>
cites: INT-001, MN-001
- When ...
- then ...
```

The `cites:` line is what the link-checker reads. A rule that cites nothing, or cites an id that does not exist, fails CI. A rule with no test (visible or hidden) fails CI.

Rules are the contract the agent builds against. The agent may propose a rule; a human agrees it before implementation on high-risk work.

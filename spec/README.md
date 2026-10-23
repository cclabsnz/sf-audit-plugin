# spec/

Rules in when/then form. Each rule:

```
## RULE-001 <title>
cites: INT-001, MN-001
- When ...
- then ...
```

The `cites:` line ties a rule to the intent and must-never it serves. Tests name the rule ids they cover.

Rules are the contract the agent builds against. The agent may propose a rule; a human agrees it before implementation on high-risk work.

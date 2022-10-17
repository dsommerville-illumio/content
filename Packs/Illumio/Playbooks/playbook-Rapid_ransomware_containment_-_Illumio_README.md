Isolate one or more workloads based on traffic flows to a given port/protocol.



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Update enforcement mode - Illumio

### Integrations
This playbook does not use any integrations.

### Scripts
* Print

### Commands
* illumio-virtual-service-create
* illumio-object-provision
* illumio-rule-create
* illumio-enforcement-boundary-create
* illumio-service-binding-create
* illumio-traffic-analysis
* illumio-workloads-list
* illumio-ruleset-create

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Port | Provide Port to be blocked. |  | Required |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| Protocol | Protocol of Port. |  TCP | Optional |
| Allow Traffic | Do You want to allow traffic on this port? \(Yes or No\) | Yes | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Rapid ransomware containment - Illumio](../doc_files/Rapid_ransomware_containment_-_Illumio.png)
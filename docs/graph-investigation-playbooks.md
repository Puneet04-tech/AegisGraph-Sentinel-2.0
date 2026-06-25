# Graph Investigation Playbooks

## Overview

This guide provides practical graph investigation workflows for common cybersecurity and fraud analysis scenarios using AegisGraph Sentinel 2.0.

The playbooks demonstrate how graph-based relationships between accounts, devices, IP addresses, merchants, and transaction activity can be used to identify suspicious behavior, investigate incidents, and document findings.

The examples are intended for security analysts, fraud investigators, threat intelligence teams, contributors, and researchers who want to understand graph-driven investigation methodologies.

---

# 1. Malicious IP Investigation

## Objective

Identify whether a suspicious IP address is associated with fraudulent activity, mule account operations, account takeover attempts, coordinated login activity, or infrastructure shared across multiple entities.

The investigation aims to determine the scope of impact, identify affected accounts and devices, and assess the overall risk posed by the IP address.

## Required Data

* IP Address node
* Account nodes
* Device nodes
* Login relationships
* Transaction history
* Historical risk indicators
* Behavioral analysis results
* Temporal activity information

## Investigation Workflow

### Step 1: Identify the Suspicious IP

Begin with an IP address that has been flagged through alerts, threat intelligence feeds, fraud detection rules, or abnormal login behavior.

Example:

```text
IP Address: 203.0.113.50
```

Create the investigation starting node within the graph.

Expected focus:

* Recent login attempts
* Failed authentication events
* High-risk transactions
* Shared infrastructure usage

### Step 2: Explore Connected Accounts

Traverse all relationships connected to the IP node.

Example relationships:

```text
IP Address
    |
    +-- Account A
    |
    +-- Account B
    |
    +-- Account C
```

Questions to answer:

* How many accounts are associated with the IP?
* Are accounts geographically unrelated?
* Are accounts newly created?
* Are multiple accounts active within short time intervals?

Indicators of concern:

* One IP connected to many accounts
* Sudden increase in account associations
* Newly created accounts sharing infrastructure

### Step 3: Analyze Connected Devices

Investigate device relationships linked to the accounts discovered in the previous step.

Example graph:

```text
IP Address
    |
Device X
    |
Account A
Account B
```

Review:

* Device sharing patterns
* Device fingerprint similarities
* Repeated login behavior
* Device risk scores

Potential findings:

* Single device controlling multiple accounts
* Device reuse across suspicious accounts
* Coordinated login behavior

### Step 4: Trace Transaction Relationships

Expand the graph outward from the connected accounts.

Analyze:

* Incoming transfers
* Outgoing transfers
* Fan-in patterns
* Fan-out patterns
* Transaction velocity

Example:

```text
Account A --> Account D
Account A --> Account E
Account A --> Account F
```

Investigators should look for:

* Rapid fund movement
* Circular transaction chains
* Mule account behavior
* Transaction spikes

### Step 5: Evaluate Risk Level

Combine evidence collected during the investigation.

Risk factors include:

* Number of connected accounts
* Shared device infrastructure
* Transaction anomalies
* Behavioral indicators
* Historical fraud associations

Suggested classification:

| Risk Level | Description                                      |
| ---------- | ------------------------------------------------ |
| Low        | Limited relationships and no suspicious activity |
| Medium     | Multiple related entities with unusual behavior  |
| High       | Strong evidence of coordinated fraud activity    |

## Expected Graph Outcome

A completed graph investigation should reveal:

* Connected accounts
* Shared devices
* Transaction pathways
* Historical relationships
* Potential fraud clusters

Example outcome:

```text
IP Address
    |
    +-- Device X
           |
           +-- Account A
           +-- Account B
           +-- Account C
                    |
               Transaction Network
```

## Key Observations

Common observations during malicious IP investigations include:

* Shared infrastructure across multiple accounts
* Repeated login attempts from the same source
* Coordinated transaction behavior
* Evidence of mule account networks
* Connections to previously identified high-risk entities

Analysts should document all findings and preserve graph snapshots for future investigations and correlation activities.

---

# 2. Phishing Campaign Investigation

## Objective

Investigate phishing-related activity by identifying malicious infrastructure, affected accounts, shared IP addresses, and related entities within the graph.

The goal is to uncover relationships between compromised accounts, phishing infrastructure, and potential attack campaigns.

## Required Data

* Domain indicators
* IP Address nodes
* Account nodes
* Device nodes
* Login events
* Historical activity records
* Threat intelligence indicators

## Investigation Workflow

### Step 1: Identify Initial Indicator

Begin with a known phishing indicator.

Possible starting points:

* Suspicious domain
* Malicious URL
* Reported phishing email
* Threat intelligence feed
* High-risk login alert

Example:

```text
phishing-example.com
```

Create the initial investigation node and collect all available relationships.

### Step 2: Trace Related Infrastructure

Identify all infrastructure associated with the indicator.

Potential relationships:

```text
Domain
   |
   +-- IP Address
   |
   +-- Device
   |
   +-- Account
```

Review:

* Hosting IP addresses
* Shared domains
* Infrastructure reuse
* Historical associations

Questions to answer:

* Has this infrastructure been used before?
* Are multiple domains sharing the same IP?
* Is the infrastructure linked to previous investigations?

### Step 3: Discover Shared Relationships

Expand the graph to identify connected entities.

Investigate:

* Shared devices
* Shared accounts
* Shared IP addresses
* Common transaction behavior

Example:

```text
Domain A
    |
IP Address X
    |
Account A
Account B
Account C
```

Indicators of concern:

* Multiple compromised accounts
* Shared login infrastructure
* Repeated attack patterns
* Rapid account activity changes

### Step 4: Visualize Attack Paths

Construct a graph showing the complete attack chain.

Example:

```text
Phishing Domain
       |
   IP Address
       |
   Device
       |
 Compromised Account
       |
 Transaction Activity
```

Investigators should map:

* Initial access point
* Infrastructure used
* Impacted accounts
* Subsequent activity

### Step 5: Document Findings

Record all investigation results.

Documentation should include:

* Indicator details
* Related entities
* Attack timeline
* Risk assessment
* Recommended actions

This ensures future investigations can reuse the findings.

## Expected Graph Outcome

A successful investigation should reveal:

* Phishing infrastructure
* Impacted accounts
* Shared resources
* Attack relationships
* Potential campaign scope

Example outcome:

```text
Domain
   |
IP Address
   |
Device Cluster
   |
Affected Accounts
   |
Transaction Activity
```

## Key Observations

Common phishing campaign findings include:

* Reused infrastructure across campaigns
* Shared IP addresses hosting multiple malicious domains
* Multiple accounts accessed from common devices
* Coordinated activity patterns
* Connections to previous phishing incidents

Graph analysis provides visibility into relationships that may not be obvious through traditional investigation methods.

---

# 3. Malware Infrastructure Analysis

## Objective

Analyze malware-related infrastructure to identify command-and-control (C2) servers, compromised devices, malicious communication paths, and connected indicators within the graph.

The goal is to understand how malware interacts with accounts, devices, and network infrastructure while identifying the full scope of compromise.

## Required Data

* IP Address nodes
* Device nodes
* Account nodes
* Communication events
* Historical graph activity
* Threat intelligence indicators
* Behavioral anomaly data

## Investigation Workflow

### Step 1: Locate Initial Indicator

Begin with a known malware-related indicator.

Examples:

```text
Suspicious IP Address
Known Malware Hash
Compromised Device
Threat Intelligence Alert
```

The indicator becomes the starting point of graph exploration.

### Step 2: Expand Neighbor Relationships

Explore all directly connected entities.

Example:

```text
Malicious IP
      |
      +-- Device A
      |
      +-- Device B
      |
      +-- Device C
```

Review:

* Number of connected devices
* Frequency of communication
* Shared infrastructure
* Historical relationships

Questions to answer:

* Which devices communicate with the malicious infrastructure?
* How long has communication existed?
* Is communication increasing over time?

### Step 3: Discover Shared Infrastructure

Investigate whether connected entities share infrastructure.

Potential relationships:

```text
Device A
    |
Malicious IP
    |
Device B
    |
Account X
```

Look for:

* Shared IP addresses
* Shared devices
* Repeated communication patterns
* Previously known malicious infrastructure

Indicators of concern:

* Multiple devices connected to the same infrastructure
* Infrastructure linked to earlier investigations
* Persistent communication activity

### Step 4: Analyze Temporal Connections

Review how relationships evolve over time.

Focus areas:

* First observed activity
* Most recent activity
* Communication frequency
* Activity spikes

Example timeline:

```text
Day 1 → Initial Connection

Day 3 → Additional Devices Connected

Day 5 → Suspicious Transactions

Day 7 → Infrastructure Expansion
```

Temporal analysis helps identify infection spread patterns.

### Step 5: Determine Impact

Assess the overall impact of the malware infrastructure.

Evaluate:

* Number of affected devices
* Number of affected accounts
* Transaction exposure
* Infrastructure complexity

Risk categories:

| Risk Level | Description                                                |
| ---------- | ---------------------------------------------------------- |
| Low        | Limited infrastructure exposure                            |
| Medium     | Multiple entities connected                                |
| High       | Coordinated infrastructure supporting large-scale activity |

## Expected Graph Outcome

The investigation should reveal:

* Command-and-control infrastructure
* Connected devices
* Affected accounts
* Communication pathways
* Potential malware clusters

Example outcome:

```text
Malicious IP
      |
      +-- Device A
      |
      +-- Device B
      |
      +-- Account X
      |
      +-- Account Y
```

This graph enables analysts to visualize infrastructure dependencies and identify the scope of compromise.

## Key Observations

Common findings include:

* Shared infrastructure across multiple devices
* Persistent communication channels
* Malware spreading through connected entities
* Reuse of known malicious infrastructure
* Relationships between compromised accounts and devices

Graph-based investigation provides visibility into infrastructure that may otherwise remain hidden in traditional log-based analysis.

---

# 4. Threat Actor Correlation

## Objective

Correlate multiple Indicators of Compromise (IOCs) to identify shared infrastructure, related entities, coordinated campaigns, and potential threat actor activity.

The objective is to determine whether seemingly unrelated indicators belong to the same malicious operation.

## Required Data

* Account nodes
* Device nodes
* IP Address nodes
* Transaction relationships
* Login relationships
* Historical investigation results
* Threat intelligence indicators
* Temporal activity records

## Investigation Workflow

### Step 1: Collect IOCs

Gather all available indicators related to the investigation.

Examples:

```text
IP Addresses
Device IDs
Account Identifiers
Transaction References
Known Fraud Indicators
```

The more indicators available, the stronger the correlation analysis.

### Step 2: Build Correlation Graph

Create a graph using all collected indicators.

Example:

```text
IOC A
  |
Device X
  |
IP Address Y
  |
Account Z
```

Graph correlation allows investigators to visualize hidden relationships between entities.

### Step 3: Identify Shared Infrastructure

Look for infrastructure shared between multiple indicators.

Examples:

```text
Account A
      |
Device X
      |
Account B
```

or

```text
IP Address
      |
Account A
Account B
Account C
```

Review:

* Shared devices
* Shared IP addresses
* Shared transaction destinations
* Shared behavioral patterns

These relationships often indicate coordinated activity.

### Step 4: Construct Investigation Timeline

Create a timeline showing how activity evolved.

Example:

```text
Day 1 → Account Creation

Day 2 → Device Registration

Day 4 → Login Activity

Day 6 → Suspicious Transfers

Day 8 → Additional Accounts Discovered
```

Timeline construction helps identify operational patterns and campaign progression.

### Step 5: Produce Investigation Report

Summarize all discovered relationships.

Report should include:

* Indicators investigated
* Shared infrastructure
* Timeline of events
* Risk assessment
* Recommended actions

This documentation enables future analysts to continue investigations efficiently.

## Expected Graph Outcome

The final graph should reveal relationships between indicators that were previously considered independent.

Example:

```text
IP Address
      |
Device X
   /      \
Account A  Account B
      |
Transaction Cluster
      |
Shared Destination
```

This structure helps investigators identify common ownership or coordinated operations.

## Key Observations

Common findings include:

* Multiple accounts controlled from shared devices
* Reused infrastructure across investigations
* Coordinated transaction behavior
* Shared login sources
* Previously unknown connections between indicators

Threat actor correlation significantly improves the ability to identify organized fraud networks and coordinated malicious activity.


---
# 5. Investigation Best Practices

Effective graph investigations require a structured and repeatable methodology. The following practices help investigators maximize accuracy, reduce investigation time, and improve documentation quality.

---

## Efficient Graph Traversal

Graph investigations should begin with the highest-confidence indicator available.

Examples include:

* High-risk IP addresses
* Suspicious accounts
* Compromised devices
* Fraud alerts
* Threat intelligence indicators

Recommended approach:

1. Start with a single indicator.
2. Explore first-degree relationships.
3. Expand to second-degree relationships only when necessary.
4. Prioritize high-risk nodes.
5. Avoid unnecessary graph expansion.

Example:

```text
IP Address
     |
 Account A
     |
 Device X
```

Expanding the graph gradually prevents investigators from becoming overwhelmed by excessive data.

---

## Query Optimization

Large graphs can contain thousands of nodes and relationships.

To improve investigation efficiency:

* Filter by time range.
* Focus on relevant node types.
* Prioritize high-risk relationships.
* Limit traversal depth when possible.
* Remove unrelated entities from the investigation view.

Recommended filters:

```text
Last 24 Hours
Last 7 Days
High Risk Transactions
Shared Devices
Repeated Login Activity
```

Benefits:

* Faster investigations
* Reduced noise
* Improved analyst productivity

---

## Documentation of Findings

Every investigation should produce clear documentation.

Required information:

* Investigation identifier
* Date and time
* Starting indicator
* Related entities discovered
* Risk assessment
* Final conclusion

Example structure:

```text
Investigation ID: INV-001

Indicator:
203.0.113.50

Related Accounts:
Account A
Account B

Risk Level:
High

Conclusion:
Shared infrastructure suggests coordinated activity.
```

Proper documentation supports future investigations and audit requirements.

---

## Reproducible Investigation Methodology

Investigations should be repeatable by different analysts.

Recommended workflow:

1. Collect indicators.
2. Build investigation graph.
3. Analyze relationships.
4. Assess risk.
5. Document findings.
6. Preserve graph evidence.

Benefits:

* Consistent investigations
* Better collaboration
* Easier incident response
* Improved auditability
* Knowledge sharing across teams

---

## Analyst Recommendations

When performing graph investigations:

* Validate all indicators before expansion.
* Correlate findings with historical activity.
* Review temporal relationships.
* Confirm high-risk relationships using multiple data sources.
* Preserve investigation evidence whenever possible.
* Document assumptions and limitations.

Following these practices helps maintain investigation quality while reducing false positives and improving operational efficiency.

---

# Conclusion

Graph-based investigation enables analysts to identify hidden relationships, uncover coordinated activity, and accelerate incident response through connected intelligence.

AegisGraph Sentinel 2.0 provides the ability to explore accounts, devices, IP addresses, merchants, and transaction chains as a unified graph, improving detection accuracy and investigation efficiency.
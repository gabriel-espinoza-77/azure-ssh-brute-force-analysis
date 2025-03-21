# Threat Hunt: Azure Abuse Notice

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

# Scenario
Your SOC team has received an urgent email from the Microsoft Azure Safeguards Team about potential misuse of Azure resources. Microsoft has flagged your subscription due to external reports of brute-force attacks originating from one of your IP addresses. The reputation of your organization—and your Azure subscription—are at risk. Your SOC Manager has tasked you with investigating this alert to determine if the allegations are true and, if so, assess the extent of the compromise.

## Microsoft Abuse Notification (Initial Data)
- **Reported Activity**: Brute-force attacks
- **Incident Timestamp**: `3/18/2025, 6:40:40 AM UTC`
- **Reported Source IP**: `20.81.228.191`
- **Evidence Provided**: Microsoft traffic analysis indicates brute-force behaviour
---

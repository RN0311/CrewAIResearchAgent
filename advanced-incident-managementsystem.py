"""
Enhanced Security Incident Response System
------------------------------------------
A comprehensive CrewAI implementation for handling complex website security incidents
with advanced analysis, remediation, and reporting capabilities.

This enhanced version includes:
1. Full event logging and timeline reconstruction
2. Advanced threat intelligence and attribution
3. Forensic investigation capabilities
4. Multi-agent specialized security team
5. Comprehensive reporting and visualization
6. Persistent incident data storage
"""

import os
import time
import json
import datetime
import random
import uuid
from enum import Enum
from typing import List, Dict, Optional, Union, Tuple
from dataclasses import dataclass, field
from crewai import Agent, Task, Crew, Process
import pandas as pd
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from langchain.tools import Tool

load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

PROCESS_TYPE = Process.sequential  

class IncidentSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    def to_dict(self):
        return self.value

class IncidentStatus(Enum):
    NEW = "New"
    ANALYZING = "Analyzing"
    REMEDIATING = "Remediating"
    MONITORING = "Monitoring"
    RESOLVED = "Resolved"
    ESCALATED = "Escalated"

    def to_dict(self):
        return self.value

class AttackVector(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    CSRF = "Cross-Site Request Forgery"
    FILE_UPLOAD = "Malicious File Upload"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    BRUTE_FORCE = "Brute Force"
    DDOS = "DDoS Attack"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    UNKNOWN = "Unknown"

    def to_dict(self):
        return self.value

@dataclass
class EventLog:
    timestamp: str
    level: str
    message: str
    source: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def __str__(self) -> str:
        return f"{self.timestamp} [{self.level}] {self.message} - Source: {self.source}"

@dataclass
class IOC:  
    ioc_type: str  
    value: str
    confidence: float  
    source: str
    first_seen: str
    last_seen: str
    related_to: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"{self.ioc_type}: {self.value} (Confidence: {self.confidence:.2f})"

@dataclass
class SecurityFinding:
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    attack_vector: AttackVector
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_endpoints: List[str] = field(default_factory=list)
    remediation_suggestions: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.title} - {self.attack_vector.value}"

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.to_dict(),
            'attack_vector': self.attack_vector.to_dict(),
            'affected_endpoints': self.affected_endpoints
        }

@dataclass
class RemediationAction:
    id: str
    title: str
    description: str
    priority: int  
    estimated_effort: str 
    assigned_to: Optional[str] = None
    status: str = "Pending"  
    completion_time: Optional[str] = None
    
    def __str__(self) -> str:
        return f"[Priority {self.priority}] {self.title} - Status: {self.status}"

    def to_dict(self):
        """Convert remediation action to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'estimated_effort': self.estimated_effort,
            'assigned_to': self.assigned_to
        }

@dataclass
class AffectedSystem:
    name: str
    type: str  
    criticality: str  
    status: str 
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    
    def __str__(self) -> str:
        return f"{self.name} ({self.type}) - Status: {self.status}"

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.type,
            'criticality': self.criticality,
            'status': self.status,
            'ip_address': self.ip_address,
            'hostname': self.hostname
        }

class WebsiteIncident:
    def __init__(self, 
                 incident_id: str,
                 title: str,
                 incident_data: Dict,
                 severity: IncidentSeverity = IncidentSeverity.MEDIUM,
                 status: IncidentStatus = IncidentStatus.NEW):
        self.incident_id = incident_id
        self.title = title
        self.created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.severity = severity
        self.status = status
        self.assigned_team = None
        
        self.server_logs = self._parse_server_logs(incident_data.get('server_logs', []))
        self.error_logs = self._parse_error_logs(incident_data.get('error_logs', []))
        self.network_logs = self._parse_network_logs(incident_data.get('network_logs', []))
        self.access_patterns = incident_data.get('access_patterns', {})
        
        self.indicators_of_compromise = []
        self.findings = []
        self.affected_systems = []
        self.remediation_actions = []
        self.post_incident_recommendations = []
        
        self.timeline = [
            {"timestamp": self.created_at, "event": f"Incident #{incident_id} created", "details": f"Initial severity: {severity.value}"}
        ]
        
    def _parse_server_logs(self, logs: List[str]) -> List[EventLog]:
        parsed_logs = []
        for log in logs:
            try:
                parts = log.split(' ', 2)
                timestamp = f"{parts[0]} {parts[1]}"
                level_end = parts[2].find(']')
                level = parts[2][1:level_end]
                message = parts[2][level_end+2:]

                ip_address = None
                if "IP:" in message:
                    ip_start = message.find("IP:") + 3
                    ip_end = message.find(" ", ip_start) if " " in message[ip_start:] else len(message)
                    ip_address = message[ip_start:ip_end].strip()
                
                parsed_logs.append(EventLog(
                    timestamp=timestamp,
                    level=level,
                    message=message,
                    source="Server Log",
                    ip_address=ip_address
                ))
            except Exception as e:
                parsed_logs.append(EventLog(
                    timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    level="Unknown",
                    message=log,
                    source="Server Log"
                ))
        return parsed_logs
    
    def _parse_error_logs(self, logs: List[str]) -> List[EventLog]:
        parsed_logs = []
        for log in logs:
            try:
                if "PHP" in log:
                    level = log.split(':', 1)[0].strip()
                    message = log.split(':', 1)[1].strip()
                    parsed_logs.append(EventLog(
                        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        level=level.replace("PHP ", ""),
                        message=message,
                        source="Error Log"
                    ))
                elif "ModSecurity" in log:
                    parsed_logs.append(EventLog(
                        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        level="Warning",
                        message=log,
                        source="ModSecurity"
                    ))
                else:
                    parsed_logs.append(EventLog(
                        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        level="Log",
                        message=log,
                        source="Error Log"
                    ))
            except Exception:
                parsed_logs.append(EventLog(
                    timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    level="Unknown",
                    message=log,
                    source="Error Log"
                ))
        return parsed_logs
    
    def _parse_network_logs(self, logs: List[str]) -> List[EventLog]:
        parsed_logs = []
        for log in logs:
            try:
                parts = log.split(' ', 2)
                timestamp = f"{parts[0]} {parts[1]}"
                message = parts[2]
                
                parsed_logs.append(EventLog(
                    timestamp=timestamp,
                    level="Network",
                    message=message,
                    source="Network Log"
                ))
            except Exception:
                parsed_logs.append(EventLog(
                    timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    level="Network",
                    message=log,
                    source="Network Log"
                ))
        return parsed_logs

    def add_ioc(self, ioc: IOC):
        self.indicators_of_compromise.append(ioc)
        self._update_timestamp()
        
    def add_finding(self, finding: SecurityFinding):
        self.findings.append(finding)
        self._update_timestamp()
        self._add_to_timeline(f"Finding detected: {finding.title}", f"Severity: {finding.severity.value}, Vector: {finding.attack_vector.value}")
        
    def add_affected_system(self, system: AffectedSystem):
        self.affected_systems.append(system)
        self._update_timestamp()
        
    def add_remediation(self, action: RemediationAction):
        self.remediation_actions.append(action)
        self._update_timestamp()
        self._add_to_timeline(f"Remediation action added: {action.title}", f"Priority: {action.priority}, Assigned to: {action.assigned_to or 'Unassigned'}")
        
    def add_recommendation(self, recommendation: str):
        self.post_incident_recommendations.append(recommendation)
        self._update_timestamp()
        
    def update_status(self, new_status: IncidentStatus):
        old_status = self.status
        self.status = new_status
        self._update_timestamp()
        self._add_to_timeline(f"Status changed from {old_status.value} to {new_status.value}", "")
        
    def update_severity(self, new_severity: IncidentSeverity):
        old_severity = self.severity
        self.severity = new_severity
        self._update_timestamp()
        self._add_to_timeline(f"Severity changed from {old_severity.value} to {new_severity.value}", "")
        
    def _update_timestamp(self):
        self.updated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def _add_to_timeline(self, event: str, details: str):
        self.timeline.append({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": event,
            "details": details
        })
        
    def get_summary(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status.value,
            "severity": self.severity.value,
            "findings_count": len(self.findings),
            "affected_systems_count": len(self.affected_systems),
            "remediation_actions_count": len(self.remediation_actions),
            "ioc_count": len(self.indicators_of_compromise)
        }

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status.to_dict(),
            "severity": self.severity.to_dict(),
            "server_logs": [vars(log) for log in self.server_logs],
            "error_logs": [vars(log) for log in self.error_logs],
            "network_logs": [vars(log) for log in self.network_logs],
            "access_patterns": self.access_patterns,
            "indicators_of_compromise": [vars(ioc) for ioc in self.indicators_of_compromise],
            "findings": [finding.to_dict() for finding in self.findings],
            "affected_systems": [system.to_dict() for system in self.affected_systems],
            "remediation_actions": [action.to_dict() for action in self.remediation_actions],
            "post_incident_recommendations": self.post_incident_recommendations,
            "timeline": self.timeline
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'WebsiteIncident':
        incident = cls(
            incident_id=data["incident_id"],
            title=data["title"],
            incident_data={
                "server_logs": [],
                "error_logs": [],
                "network_logs": [],
                "access_patterns": data.get("access_patterns", {})
            },
            severity=IncidentSeverity(data["severity"]),
            status=IncidentStatus(data["status"])
        )
        
        incident.server_logs = [EventLog(**log) for log in data.get("server_logs", [])]
        incident.error_logs = [EventLog(**log) for log in data.get("error_logs", [])]
        incident.network_logs = [EventLog(**log) for log in data.get("network_logs", [])]
        
        incident.indicators_of_compromise = [IOC(**ioc) for ioc in data.get("indicators_of_compromise", [])]
        incident.findings = [SecurityFinding(**finding) for finding in data.get("findings", [])]
        incident.affected_systems = [AffectedSystem(**system) for system in data.get("affected_systems", [])]
        incident.remediation_actions = [RemediationAction(**action) for action in data.get("remediation_actions", [])]
        incident.post_incident_recommendations = data.get("post_incident_recommendations", [])
        incident.timeline = data.get("timeline", [])
        
        incident.created_at = data["created_at"]
        incident.updated_at = data["updated_at"]
        
        return incident


class SecurityTeam:
    def __init__(self, use_llm_tools=True):
        self.tools = [
            Tool(
                name="analyze_logs",
                func=self._analyze_logs,
                description="Analyze security logs and identify patterns"
            ),
            Tool(
                name="assess_severity",
                func=self._assess_severity,
                description="Assess the severity of security findings"
            ),
            Tool(
                name="recommend_actions",
                func=self._recommend_actions,
                description="Recommend security actions based on findings"
            )
        ]
        
        self.analyst = self._create_analyst()
        self.forensic_investigator = self._create_forensic_investigator()
        self.threat_intelligence = self._create_threat_intelligence()
        self.engineer = self._create_engineer()
        self.incident_manager = self._create_incident_manager()

    def _analyze_logs(self, logs):
        return "Analysis of provided logs completed."

    def _assess_severity(self, findings):
        return "Severity assessment completed."

    def _recommend_actions(self, analysis):
        return "Security recommendations generated."

    def _create_analyst(self):
        return Agent(
            role='Security Analyst',
            goal='Analyze security incidents and identify threats',
            backstory="""You are an experienced security analyst specializing in 
            threat detection and incident analysis.""",
            tools=self.tools,
            verbose=True
        )

    def _create_forensic_investigator(self):
        return Agent(
            role='Forensic Investigator',
            goal='Investigate incidents and collect evidence',
            backstory="""You are a skilled forensic investigator who specializes
            in digital evidence collection and analysis.""",
            tools=self.tools,
            verbose=True
        )

    def _create_threat_intelligence(self):
        return Agent(
            role='Threat Intelligence Analyst',
            goal='Provide context and intelligence about threats',
            backstory="""You are a threat intelligence analyst who provides
            context and insights about security threats.""",
            tools=self.tools,
            verbose=True
        )

    def _create_engineer(self):
        return Agent(
            role='Security Engineer',
            goal='Implement security fixes and improvements',
            backstory="""You are a security engineer who implements
            fixes and security improvements.""",
            tools=self.tools,
            verbose=True
        )

    def _create_incident_manager(self):
        return Agent(
            role='Incident Manager',
            goal='Coordinate incident response activities',
            backstory="""You are an incident response manager who
            coordinates all aspects of incident handling.""",
            tools=self.tools,
            verbose=True
        )

    def create_analysis_task(self, incident: WebsiteIncident) -> Task:
        server_logs_str = "\n".join(str(log) for log in incident.server_logs)
        error_logs_str = "\n".join(str(log) for log in incident.error_logs)
        network_logs_str = "\n".join(str(log) for log in incident.network_logs)
        
        return Task(
            description=f"""SECURITY INCIDENT ANALYSIS TASK
            
Incident ID: {incident.incident_id}
Title: {incident.title}
Current Severity: {incident.severity.value}
Current Status: {incident.status.value}

ANALYZE THE FOLLOWING SECURITY INCIDENT DATA:

=== SERVER LOGS ===
{server_logs_str}

=== ERROR LOGS ===
{error_logs_str}

=== NETWORK LOGS ===
{network_logs_str}

=== ACCESS PATTERNS ===
- Login Attempts: {incident.access_patterns.get('login_attempts', 'N/A')}
- Failed Logins: {incident.access_patterns.get('failed_logins', 'N/A')}
- Unique IPs: {incident.access_patterns.get('unique_ips', 'N/A')}
- Affected Endpoints: {', '.join(incident.access_patterns.get('affected_endpoints', ['N/A']))}

ANALYSIS REQUIREMENTS:

1. Identify the specific type(s) of attack being attempted (SQL Injection, XSS, CSRF, etc.)
2. Assess the severity and potential impact on the system
3. Determine if the attacks were successful and if data was compromised
4. Identify all affected endpoints or systems
5. Extract indicators of compromise (IOCs) such as suspicious IPs, user agents, or payload patterns
6. Estimate the attacker's sophistication level and potential motivation
7. Check if this matches known threat actor patterns
8. Recommend an appropriate severity level for this incident

Format your analysis as a structured security report with clearly labeled sections.
Be specific and thorough, providing evidence from the logs for each conclusion.
""",
            agent=self.analyst,
            expected_output="A comprehensive security analysis report identifying attack types, severity, impact, and indicators of compromise."
        )

    def create_forensic_task(self, incident: WebsiteIncident) -> Task:
        all_logs = incident.server_logs + incident.error_logs + incident.network_logs
        all_logs.sort(key=lambda x: x.timestamp)
        timeline_str = "\n".join(str(log) for log in all_logs)
        
        return Task(
            description=f"""FORENSIC INVESTIGATION TASK
            
Incident ID: {incident.incident_id}
Title: {incident.title}

REVIEW THE FOLLOWING CHRONOLOGICAL EVENT TIMELINE:

=== EVENT TIMELINE ===
{timeline_str}

=== ACCESS PATTERNS ===
- Login Attempts: {incident.access_patterns.get('login_attempts', 'N/A')}
- Failed Logins: {incident.access_patterns.get('failed_logins', 'N/A')}
- Unique IPs: {incident.access_patterns.get('unique_ips', 'N/A')}
- Affected Endpoints: {', '.join(incident.access_patterns.get('affected_endpoints', ['N/A']))}

FORENSIC ANALYSIS REQUIREMENTS:

1. Reconstruct the complete attack sequence from initial access to latest activity
2. Identify the attack lifecycle phases (reconnaissance, initial access, lateral movement, etc.)
3. Determine the exact entry point(s) used by the attacker
4. Catalog all affected systems and endpoints
5. Identify what data or resources may have been accessed or exfiltrated
6. Determine if there are signs of persistence mechanisms
7. Identify any evidence of attempts to cover tracks or delete logs
8. Create a detailed timeline of the attack with key events highlighted

Your investigation should be thorough and methodical, noting both what is present in the logs
and what might be missing. Report with high confidence only what can be supported by evidence,
and note where there is uncertainty or gaps in the available information.
""",
            agent=self.forensic_investigator,
            expected_output="A detailed forensic report reconstructing the attack sequence, identifying affected systems, and cataloging potential data exposure."
        )

    def create_threat_intel_task(self, incident: WebsiteIncident, analysis_findings: str) -> Task:
        return Task(
            description=f"""THREAT INTELLIGENCE ANALYSIS TASK
            
Incident ID: {incident.incident_id}
Title: {incident.title}

SECURITY ANALYSIS FINDINGS:
{analysis_findings}

THREAT INTELLIGENCE REQUIREMENTS:

1. Based on the attack patterns and techniques observed, identify potential threat actors or groups that may be responsible
2. Provide context on the identified threat actors: their typical targets, motivations, and capabilities
3. Compare the observed TTPs (Tactics, Techniques, and Procedures) with known threat actor profiles
4. Assess whether this appears to be a targeted attack or opportunistic
5. Evaluate the sophistication level of the attacker(s)
6. Identify any similar attacks or campaigns recently observed in the wild
7. Provide recommendations for specific threat feeds or sources to monitor for related activity
8. Identify any relevant CVEs or vulnerabilities that may have been exploited

Format your response as a comprehensive threat intelligence brief that provides actionable context
to the security team. Focus on information that is relevant to this specific incident rather than
general threat landscape information.
""",
            agent=self.threat_intelligence,
            expected_output="A threat intelligence brief identifying potential threat actors, their capabilities, and contextual information relevant to the incident."
        )

    def create_remediation_task(self, incident: WebsiteIncident, analysis_findings: str, forensic_findings: str) -> Task:
        return Task(
            description=f"""SECURITY REMEDIATION TASK
            
Incident ID: {incident.incident_id}
Title: {incident.title}
Current Severity: {incident.severity.value}
            
SECURITY ANALYSIS FINDINGS:
{analysis_findings}

FORENSIC INVESTIGATION FINDINGS:
{forensic_findings}

AFFECTED ENDPOINTS:
{', '.join(incident.access_patterns.get('affected_endpoints', ['Unknown']))}

REMEDIATION REQUIREMENTS:

1. Provide immediate containment actions to stop ongoing attacks
2. Develop specific technical fixes for each vulnerability identified
3. Create hardening measures to prevent similar attacks in the future
4. Design multi-layered defenses that address the attack vectors used
5. Provide specific configuration changes, code fixes, or infrastructure modifications needed
6. Prioritize remediation actions based on risk, impact, and effort required
7. Include implementation guidance with each remediation step
8. Create validation tests to confirm successful remediation
9. Include monitoring recommendations to detect similar attacks in the future

Format your response as a comprehensive remediation plan with clear categorization of actions:
- Immediate (within hours)
- Short-term (within days)
- Long-term (within weeks)

Each action should include title, description, priority, estimated effort, and validation criteria.
Be specific and technical where appropriate, including code snippets, configuration changes, or commands.
""",
            agent=self.engineer,
            expected_output="A comprehensive remediation plan with prioritized actions, technical details, and implementation guidance."
        )

    def create_coordination_task(self, incident: WebsiteIncident, 
                                  analysis_findings: str, 
                                  forensic_findings: str,
                                  threat_intel: str,
                                  remediation_plan: str) -> Task:
        return Task(
            description=f"""INCIDENT COORDINATION TASK
            
Incident ID: {incident.incident_id}
Title: {incident.title}
Current Severity: {incident.severity.value}
Current Status: {incident.status.value}

SUMMARY OF ALL FINDINGS:

=== SECURITY ANALYSIS ===
{analysis_findings}

=== FORENSIC INVESTIGATION ===
{forensic_findings}

=== THREAT INTELLIGENCE ===
{threat_intel}

=== REMEDIATION PLAN ===
{remediation_plan}

COORDINATION REQUIREMENTS:

1. Evaluate the completeness of the incident response so far
2. Identify any gaps in the analysis, investigation, or remediation plan
3. Prioritize all remediation actions into a single, cohesive plan
4. Recommend stakeholder communications and external notifications if needed
5. Create a post-incident review plan with specific focus areas
6. Recommend monitoring and verification measures to ensure complete remediation
7. Suggest process improvements based on lessons learned from this incident
8. Provide an executive summary suitable for management reporting

Your coordination should ensure that nothing falls through the cracks and that the incident
response is comprehensive. Identify any additional tasks or resources needed and provide a
clear roadmap for moving from the current status to resolution.
""",
            agent=self.incident_manager,
            expected_output="A comprehensive incident coordination plan that integrates all findings, identifies gaps, and provides a clear path to resolution."
        )


def process_agent_output(output: Union[str, List]) -> str:
    """Process the output from agent tasks, handling both string and list returns"""
    if isinstance(output, str):
        return output
    elif isinstance(output, list):
        return "\n\n".join(output)
    else:
        return str(output)

def generate_incident_report(incident: WebsiteIncident, 
                           analysis_report: str,
                           forensic_report: str,
                           threat_intel: str,
                           remediation_plan: str,
                           coordination_plan: str, 
                           output_file: str = None) -> str:

    report = f"""# Security Incident Report
    
## Incident Summary

- **Incident ID:** {incident.incident_id}
- **Title:** {incident.title}
- **Created:** {incident.created_at}
- **Last Updated:** {incident.updated_at}
- **Status:** {incident.severity.value}
- **Severity:** {incident.severity.value}

## Executive Summary

{coordination_plan.split("Executive Summary", 1)[1].split("##", 1)[0] if "Executive Summary" in coordination_plan else "Executive summary not provided."}

## Security Analysis

{analysis_report}

## Forensic Investigation

{forensic_report}

## Threat Intelligence

{threat_intel}

## Remediation Plan

{remediation_plan}

## Incident Timeline

| Timestamp | Event | Details |
|-----------|-------|---------|
"""
    

    for entry in incident.timeline:
        report += f"| {entry['timestamp']} | {entry['event']} | {entry['details']} |\n"
    
    report += """
## Recommendations for Future Prevention

"""
    

    if incident.post_incident_recommendations:
        for i, rec in enumerate(incident.post_incident_recommendations, 1):
            report += f"{i}. {rec}\n"
    else:
        report += "No specific recommendations provided."

    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"Incident report saved to {output_file}")
        
    return report

def visualize_incident_data(incident: WebsiteIncident) -> None:
    """
    Create visualizations for incident data
    """
    

    if incident.timeline:
        timestamps = [entry['timestamp'] for entry in incident.timeline]
        events = [entry['event'] for entry in incident.timeline]
        
        plt.figure(figsize=(12, 6))
        plt.plot_date(pd.to_datetime(timestamps), range(len(timestamps)), '-o')
        
        for i, event in enumerate(events):
            plt.annotate(event, (pd.to_datetime(timestamps[i]), i), 
                         xytext=(10, 0), textcoords='offset points')
        
        plt.yticks([])
        plt.title('Incident Timeline')
        plt.xlabel('Time')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"incident_{incident.incident_id}_timeline.png")
        print(f"Timeline visualization saved to incident_{incident.incident_id}_timeline.png")
        
    if incident.findings:
        severity_counts = {}
        for finding in incident.findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        plt.figure(figsize=(8, 6))
        bars = plt.bar(severity_counts.keys(), severity_counts.values())
        
        colors = {'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Critical': 'red'}
        for bar, key in zip(bars, severity_counts.keys()):
            bar.set_color(colors.get(key, 'blue'))
            
        plt.title('Finding Severity Distribution')
        plt.xlabel('Severity')
        plt.ylabel('Count')
        plt.savefig(f"incident_{incident.incident_id}_severities.png")
        print(f"Severity distribution saved to incident_{incident.incident_id}_severities.png")

def export_incident_to_json(incident: WebsiteIncident, filename: str) -> None:
    """
    Export incident data to JSON file for persistence
    """
    with open(filename, 'w') as f:
        json.dump(incident.to_dict(), f, indent=2)
    print(f"Incident data exported to {filename}")

def print_with_delay(message, delay=0.5):
    print(message)
    time.sleep(delay)

def import_incident_from_json(filename: str) -> WebsiteIncident:

    with open(filename, 'r') as f:
        data = json.load(f)
    return WebsiteIncident.from_dict(data)


def main():
    print_with_delay("\n🔒 Enhanced Website Security Incident Response System 🔒")
    print_with_delay("=========================================================")
    
    incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
    
    print_with_delay(f"\n📋 Creating new incident #{incident_id}")
    
    incident = WebsiteIncident(
        incident_id=incident_id,
        title="Website Compromise with Data Exfiltration Attempt",
        incident_data=ENHANCED_INCIDENT_DATA,
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.NEW
    )
    
    print_with_delay("\n👥 Assembling Security Response Team...")
    team = SecurityTeam(use_llm_tools=True)
    
    incident.update_status(IncidentStatus.ANALYZING)
    
    print_with_delay("\n🔍 Starting Security Analysis (1/5)...")
    analysis_task = team.create_analysis_task(incident)
    
    analysis_crew = Crew(
        agents=[team.analyst],
        tasks=[analysis_task],
        verbose=True,
        process=PROCESS_TYPE
    )
    
    analysis_results = analysis_crew.kickoff()
    processed_analysis = process_agent_output(analysis_results)
    
    print_with_delay("\n  ✅ Security Analysis Complete")
    print_with_delay(f"\n  📊 Analysis Summary: {processed_analysis[:100]}...")

    print_with_delay("\n🔬 Starting Forensic Investigation (2/5)...")
    forensic_task = team.create_forensic_task(incident)
    
    forensic_crew = Crew(
        agents=[team.forensic_investigator],
        tasks=[forensic_task],
        verbose=True,
        process=PROCESS_TYPE
    )
    
    forensic_results = forensic_crew.kickoff()
    processed_forensics = process_agent_output(forensic_results)
    
    print_with_delay("\n  ✅ Forensic Investigation Complete")
    print_with_delay(f"\n  🔎 Forensic Summary: {processed_forensics[:100]}...")
    
    incident.add_finding(SecurityFinding(
        id=f"FINDING-{str(uuid.uuid4())[:8]}",
        title="SQL Injection Attempt on Login Form",
        description="Evidence of SQL injection attempts targeting login form with ' OR 1=1 -- payloads.",
        severity=IncidentSeverity.HIGH,
        attack_vector=AttackVector.SQL_INJECTION,
        affected_endpoints=["/admin/login.php", "/wp-login.php"]
    ))
    
    incident.add_finding(SecurityFinding(
        id=f"FINDING-{str(uuid.uuid4())[:8]}",
        title="Webshell Upload and Remote Code Execution",
        description="Attacker successfully uploaded PHP shell and executed arbitrary commands.",
        severity=IncidentSeverity.CRITICAL,
        attack_vector=AttackVector.FILE_UPLOAD,
        affected_endpoints=["/admin/upload.php"]
    ))
    
    incident.add_finding(SecurityFinding(
        id=f"FINDING-{str(uuid.uuid4())[:8]}",
        title="Data Exfiltration to External Command & Control Server",
        description="Large data transfer detected to known malicious IP address.",
        severity=IncidentSeverity.CRITICAL,
        attack_vector=AttackVector.UNKNOWN,
        affected_endpoints=["/includes/db.php"]
    ))
    
    incident.add_affected_system(AffectedSystem(
        name="Web Server",
        type="Server",
        criticality="High",
        status="Compromised",
        ip_address="10.0.0.5",
        hostname="web-prod-01"
    ))
    
    incident.add_affected_system(AffectedSystem(
        name="Database Server",
        type="Database",
        criticality="Critical",
        status="Potentially Compromised",
        ip_address="10.0.0.8",
        hostname="db-prod-01"
    ))
    
    print_with_delay("\n🕵️ Starting Threat Intelligence Analysis (3/5)...")
    threat_task = team.create_threat_intel_task(incident, processed_analysis)
    
    threat_crew = Crew(
        agents=[team.threat_intelligence],
        tasks=[threat_task],
        verbose=True,
        process=PROCESS_TYPE
    )
    
    threat_results = threat_crew.kickoff()
    processed_threat_intel = process_agent_output(threat_results)
    
    print_with_delay("\n  ✅ Threat Intelligence Analysis Complete")
    print_with_delay(f"\n  🔍 Threat Intel Summary: {processed_threat_intel[:100]}...")
    
    incident.update_status(IncidentStatus.REMEDIATING)
    
    print_with_delay("\n🛠️ Developing Remediation Plan (4/5)...")
    remediation_task = team.create_remediation_task(incident, processed_analysis, processed_forensics)
    
    remediation_crew = Crew(
        agents=[team.engineer],
        tasks=[remediation_task],
        verbose=True,
        process=PROCESS_TYPE
    )
    
    remediation_results = remediation_crew.kickoff()
    processed_remediation = process_agent_output(remediation_results)
    
    print_with_delay("\n  ✅ Remediation Planning Complete")
    
    incident.add_remediation(RemediationAction(
        id=f"ACTION-{str(uuid.uuid4())[:8]}",
        title="Isolate Compromised Web Server",
        description="Immediately isolate the compromised web server to prevent lateral movement.",
        priority=1,
        estimated_effort="Low",
        assigned_to="Network Team"
    ))
    
    incident.add_remediation(RemediationAction(
        id=f"ACTION-{str(uuid.uuid4())[:8]}",
        title="Fix SQL Injection Vulnerability",
        description="Implement proper input validation and parameterized queries in login.php.",
        priority=1,
        estimated_effort="Medium",
        assigned_to="Development Team"
    ))
    
    incident.add_remediation(RemediationAction(
        id=f"ACTION-{str(uuid.uuid4())[:8]}",
        title="Enhance File Upload Security",
        description="Implement proper file type checking, scanning, and secure storage practices.",
        priority=2,
        estimated_effort="High",
        assigned_to="Development Team"
    ))
    
    print_with_delay("\n📊 Coordinating Incident Response (5/5)...")
    coordination_task = team.create_coordination_task(
        incident, 
        processed_analysis, 
        processed_forensics, 
        processed_threat_intel, 
        processed_remediation
    )
    
    coordination_crew = Crew(
        agents=[team.incident_manager],
        tasks=[coordination_task],
        verbose=True,
        process=PROCESS_TYPE
    )
    
    coordination_results = coordination_crew.kickoff()
    processed_coordination = process_agent_output(coordination_results)
    
    print_with_delay("\n  ✅ Incident Coordination Complete")
    
    incident.add_recommendation("Implement Web Application Firewall (WAF) to detect and block common web attacks")
    incident.add_recommendation("Conduct regular security training for development team focusing on OWASP Top 10")
    incident.add_recommendation("Implement file integrity monitoring on web servers")
    incident.add_recommendation("Review and enhance the incident response playbook based on lessons learned")
    incident.add_recommendation("Deploy network-based intrusion detection system to identify similar attacks")
    
    incident.update_status(IncidentStatus.MONITORING)

    print_with_delay("\n📈 Generating Incident Visualizations...")
    visualize_incident_data(incident)
    

    print_with_delay("\n📝 Generating Comprehensive Incident Report...")
    report = generate_incident_report(
        incident,
        processed_analysis,
        processed_forensics,
        processed_threat_intel,
        processed_remediation,
        processed_coordination,
        output_file=f"incident_{incident_id}_report.md"
    )

    print_with_delay("\n💾 Exporting Incident Data...")
    export_incident_to_json(incident, f"incident_{incident_id}_data.json")
    
    incident.update_status(IncidentStatus.RESOLVED)
    
    print_with_delay("\n✅ Enhanced Incident Response Process Complete!")
    print_with_delay(f"📊 Incident Summary: {len(incident.findings)} findings, {len(incident.remediation_actions)} remediation actions")
    print_with_delay(f"📋 Full report available at: incident_{incident_id}_report.md")
    print_with_delay("\n=========================================================")

ENHANCED_INCIDENT_DATA = {
    'server_logs': [
        "2024-03-18 10:15:23 [Warning] Multiple failed login attempts from IP: 192.168.1.100",
        "2024-03-18 10:15:25 [Error] SQL injection attempt detected in login form",
        "2024-03-18 10:15:26 [Warning] Suspicious parameter detected: ' OR 1=1 --",
        "2024-03-18 10:16:00 [Critical] Unauthorized file upload attempt detected",
        "2024-03-18 10:16:05 [Error] File upload validation bypass attempted",
        "2024-03-18 10:16:30 [Warning] Unusual traffic pattern detected from /admin",
        "2024-03-18 10:17:12 [Critical] Session hijacking attempt detected from IP: 192.168.1.100",
        "2024-03-18 10:18:45 [Error] Suspicious file executed: shell.php",
        "2024-03-18 10:19:20 [Critical] Unauthorized database access detected",
        "2024-03-18 10:20:15 [Warning] Multiple directory traversal attempts detected",
    ],
    'error_logs': [
        "PHP Warning: SQL syntax error in /var/www/html/login.php on line 23",
        "PHP Notice: Undefined variable: user_input in /var/www/html/process.php",
        "ModSecurity: Access denied with code 403 (Phase 2) SQLi Match",
        "PHP Warning: file_put_contents(../uploads/shell.php): failed to open stream: Permission denied",
        "PHP Fatal error: Uncaught Exception: Database connection error in /var/www/html/includes/db.php:45",
        "ModSecurity: Access denied with code 403 (Phase 2) File Upload Match",
        "PHP Warning: include(../../../etc/passwd): failed to open stream: No such file or directory",
        "PHP Error: Maximum execution time of 30 seconds exceeded in /var/www/html/admin/users.php"
    ],
    'network_logs': [
        "2024-03-18 10:14:55 Connection established from 192.168.1.100:4532 to 10.0.0.5:443",
        "2024-03-18 10:15:20 HTTP POST /login.php HTTP/1.1 - User-Agent: Mozilla/5.0 (Linux; Android 11; SM-G960F)",
        "2024-03-18 10:15:40 HTTP GET /admin/dashboard.php HTTP/1.1 - Referrer: https://example.com/login.php",
        "2024-03-18 10:16:10 HTTP POST /upload.php HTTP/1.1 - Content-Type: multipart/form-data",
        "2024-03-18 10:17:30 Outbound connection initiated to 45.33.25.121:1337 from 10.0.0.5:59234",
        "2024-03-18 10:18:25 DNS query for malicious-c2.example[.]com from 10.0.0.5",
        "2024-03-18 10:19:05 Large data transfer (15MB) to external IP 45.33.25.121 from 10.0.0.5",
        "2024-03-18 10:21:30 Connection terminated from 192.168.1.100:4532"
    ],
    'access_patterns': {
        'login_attempts': 152,
        'failed_logins': 148,
        'unique_ips': 3,
        'affected_endpoints': [
            '/admin/login.php',
            '/wp-login.php',
            '/admin/upload.php',
            '/admin/users.php',
            '/includes/db.php',
            '/api/data.php'
        ],
        'user_agents': [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Linux; Android 11; SM-G960F)",
            "python-requests/2.26.0"
        ],
        'suspicious_payloads': [
            "' OR 1=1 --",
            "../../../etc/passwd",
            "<?php system($_GET['cmd']); ?>"
        ]
    }
}

if __name__ == "__main__":
    main()

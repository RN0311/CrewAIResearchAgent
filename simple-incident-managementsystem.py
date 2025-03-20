"""
Security Incident Response System
--------------------------------------
A simplified example using CrewAI to handle a website security incident
with specific log data and indicators of compromise.
"""

import os
from crewai import Agent, Task, Crew
from enum import Enum
from typing import List, Dict
import time
import json


os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

class IncidentSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class WebsiteIncident:
    def __init__(self, 
                 incident_data: Dict,
                 severity: IncidentSeverity):
        self.server_logs = incident_data.get('server_logs', [])
        self.error_logs = incident_data.get('error_logs', [])
        self.access_patterns = incident_data.get('access_patterns', {})
        self.severity = severity
        self.analysis_findings = []
        self.remediation_steps = []

    def add_finding(self, finding: str):
        self.analysis_findings.append(finding)

    def add_remediation(self, step: str):
        self.remediation_steps.append(step)

def print_with_delay(message, delay=0.5):
    print(message)
    time.sleep(delay)


SAMPLE_INCIDENT_DATA = {
    'server_logs': [
        "2024-03-18 10:15:23 [Warning] Multiple failed login attempts from IP: 192.168.1.100",
        "2024-03-18 10:15:25 [Error] SQL injection attempt detected in login form",
        "2024-03-18 10:16:00 [Critical] Unauthorized file upload attempt detected",
        "2024-03-18 10:16:30 [Warning] Unusual traffic pattern detected from /admin",
    ],
    'error_logs': [
        "PHP Warning: SQL syntax error in /var/www/html/login.php on line 23",
        "PHP Notice: Undefined variable: user_input in /var/www/html/process.php",
        "ModSecurity: Access denied with code 403 (Phase 2) SQLi Match",
    ],
    'access_patterns': {
        'login_attempts': 150,  
        'failed_logins': 145,   
        'unique_ips': 3,        
        'affected_endpoints': [
            '/admin/login.php',
            '/wp-login.php',
            '/admin/upload.php'
        ]
    }
}

class SecurityTeam:
    def __init__(self):
        self.analyst = Agent(
            role='Security Analyst',
            goal='Analyze security incidents and identify attack patterns',
            backstory="""You are an experienced security analyst specializing in 
            web application security. You analyze logs, identify attack patterns,
            and determine the scope of security incidents.""",
            verbose=True
        )

        self.engineer = Agent(
            role='Security Engineer',
            goal='Develop and implement security fixes',
            backstory="""You are a skilled security engineer who specializes in 
            web application security hardening. You develop and implement fixes
            for identified vulnerabilities.""",
            verbose=True
        )

    def create_analysis_task(self, incident: WebsiteIncident) -> Task:
        return Task(
            description=f"""Analyze the following security incident data:

Server Logs:
{chr(10).join(f'- {log}' for log in incident.server_logs)}

Error Logs:
{chr(10).join(f'- {log}' for log in incident.error_logs)}

Access Patterns:
- Login Attempts: {incident.access_patterns['login_attempts']}
- Failed Logins: {incident.access_patterns['failed_logins']}
- Unique IPs: {incident.access_patterns['unique_ips']}
- Affected Endpoints: {', '.join(incident.access_patterns['affected_endpoints'])}

Based on these logs and patterns:
1. Identify the type of attack being attempted
2. Assess the severity and potential impact
3. Determine if the attacks were successful
4. List any compromised endpoints or systems

Provide your analysis in a clear, structured format.""",
            agent=self.analyst
        )

    def create_remediation_task(self, incident: WebsiteIncident) -> Task:
        return Task(
            description=f"""Based on the security analysis findings:
            {chr(10).join(f'- {finding}' for finding in incident.analysis_findings)}
            
            Provide specific remediation steps:
            1. Immediate actions to stop the attack
            2. Security fixes needed for affected endpoints
            3. Hardening measures to prevent future attempts
            4. Monitoring recommendations
            
            Format your response as a prioritized action plan.""",
            agent=self.engineer
        )

def main():
    print_with_delay("\n🔒 Website Security Incident Response System 🔒")
    print_with_delay("=============================================")

    incident = WebsiteIncident(
        incident_data=SAMPLE_INCIDENT_DATA,
        severity=IncidentSeverity.HIGH
    )

    print_with_delay("\n👥 Assembling Security Team...")
    team = SecurityTeam()

    print_with_delay("\n📋 Creating Response Tasks...")
    analysis_task = team.create_analysis_task(incident)
    
    analysis_crew = Crew(
        agents=[team.analyst],
        tasks=[analysis_task],
        verbose=True
    )

    print_with_delay("\n🔍 Starting Security Analysis...")
    analysis_results = analysis_crew.kickoff()
    
    if isinstance(analysis_results, str):
        incident.add_finding(analysis_results)
    elif isinstance(analysis_results, list):
        for result in analysis_results:
            incident.add_finding(result)

    
    remediation_task = team.create_remediation_task(incident)
    remediation_crew = Crew(
        agents=[team.engineer],
        tasks=[remediation_task],
        verbose=True
    )

    print_with_delay("\n🛠️ Developing Remediation Plan...")
    remediation_results = remediation_crew.kickoff()

    
    print_with_delay("\n📊 Incident Response Summary:")
    print_with_delay("==========================")
    
    print_with_delay("\n🔍 Analysis Findings:")
    for finding in incident.analysis_findings:
        print_with_delay(f"• {finding}")

    print_with_delay("\n🛠️ Remediation Steps:")
    if isinstance(remediation_results, str):
        print_with_delay(f"• {remediation_results}")
    elif isinstance(remediation_results, list):
        for step in remediation_results:
            print_with_delay(f"• {step}")

    print_with_delay("\n✅ Incident Response Complete!")

if __name__ == "__main__":
    main() 
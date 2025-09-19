"""
LLM-powered explanation generator for LiveSec AI
Generates human-readable explanations for detected anomalies using OpenAI GPT
"""
import openai
import json
from typing import Dict, List, Optional
from datetime import datetime
import time
from config import OPENAI_API_KEY, OPENAI_MODEL

class LLMExplainer:
    def __init__(self):
        if OPENAI_API_KEY:
            openai.api_key = OPENAI_API_KEY
            self.enabled = True
        else:
            self.enabled = False
            print("[WARNING] OpenAI API key not found. LLM explanations will be simulated.")
        
        self.explanation_cache = {}
        
        # Fallback explanations for when API is not available
        self.fallback_explanations = {
            'unusual_login_time': "This login occurred outside normal business hours, which could indicate unauthorized access or compromise.",
            'suspicious_geo_location': "Login detected from a high-risk geographic location known for cyber attacks.",
            'failed_login': "Failed login attempt detected, which could be part of a brute force attack.",
            'geo_inconsistency': "User logged in from an unusual geographic location far from their typical login patterns.",
            'traffic_spike_sent': "Unusual outbound network traffic spike detected, potentially indicating data exfiltration.",
            'traffic_spike_received': "Unusual inbound network traffic spike detected, potentially indicating DDoS or data injection.",
            'suspicious_port': "Network connection to a suspicious port commonly used by malware or attackers.",
            'high_connection_count': "Unusually high number of network connections, potentially indicating scanning or botnet activity.",
            'large_file_transfer': "Large file transfer detected, which could indicate data exfiltration or unauthorized copying.",
            'sensitive_file_access': "Access to sensitive file detected, requiring monitoring for potential data breach.",
            'unusual_time_file_transfer': "File transfer outside normal business hours, potentially indicating unauthorized activity.",
            'potential_data_exfiltration': "Large file sent to external destination, high risk of data exfiltration or breach."
        }
    
    def create_context_prompt(self, anomaly: Dict) -> str:
        """Create a detailed context prompt for the LLM"""
        anomaly_type = anomaly['type']
        severity = anomaly['severity']
        details = anomaly.get('details', {})
        
        prompt = f"""You are a cybersecurity expert analyzing a {severity.lower()} severity anomaly. 
        
Anomaly Type: {anomaly_type}
Severity: {severity}
Description: {anomaly['description']}

Additional Details:
"""
        
        for key, value in details.items():
            prompt += f"- {key}: {value}\n"
        
        prompt += f"""
Please provide a concise, professional explanation of this cybersecurity anomaly that includes:
1. What happened (1-2 sentences)
2. Why this is concerning (1-2 sentences)
3. Recommended immediate action (1 sentence)

Keep the explanation under 150 words and use clear, non-technical language that security analysts can quickly understand.
"""
        return prompt
    
    def generate_explanation_with_api(self, anomaly: Dict) -> str:
        """Generate explanation using OpenAI API"""
        try:
            prompt = self.create_context_prompt(anomaly)
            
            response = openai.ChatCompletion.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing clear, actionable explanations of security anomalies."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            explanation = response.choices[0].message.content.strip()
            return explanation
            
        except Exception as e:
            print(f"[WARNING] OpenAI API error: {str(e)}")
            return self.get_fallback_explanation(anomaly)
    
    def get_fallback_explanation(self, anomaly: Dict) -> str:
        """Get fallback explanation when API is not available"""
        anomaly_type = anomaly['type']
        base_explanation = self.fallback_explanations.get(
            anomaly_type, 
            "Security anomaly detected that requires investigation."
        )
        
        # Enhance with specific details
        details = anomaly.get('details', {})
        severity = anomaly['severity']
        
        enhanced_explanation = f"{base_explanation} "
        
        # Add specific context based on anomaly type
        if anomaly_type == 'suspicious_geo_location' and 'country' in details:
            enhanced_explanation += f"Login originated from {details['country']}. "
        
        elif anomaly_type == 'geo_inconsistency' and 'distance' in details:
            enhanced_explanation += f"Location is {details['distance']:.0f}km from usual login areas. "
        
        elif anomaly_type in ['traffic_spike_sent', 'traffic_spike_received'] and 'multiplier' in details:
            enhanced_explanation += f"Traffic volume is {details['multiplier']:.1f}x normal levels. "
        
        elif anomaly_type == 'large_file_transfer' and 'file_size' in details:
            size_mb = details['file_size'] / 1024 / 1024
            enhanced_explanation += f"File size: {size_mb:.1f}MB. "
        
        # Add severity-based recommendations
        if severity == 'High':
            enhanced_explanation += "IMMEDIATE INVESTIGATION REQUIRED."
        elif severity == 'Medium':
            enhanced_explanation += "Monitor closely and investigate if pattern continues."
        else:
            enhanced_explanation += "Document for trend analysis."
        
        return enhanced_explanation
    
    def explain_anomaly(self, anomaly: Dict) -> Dict:
        """Generate explanation for an anomaly and return enhanced anomaly data"""
        # Create cache key
        cache_key = f"{anomaly['type']}_{anomaly.get('severity', 'unknown')}"
        details_str = json.dumps(anomaly.get('details', {}), sort_keys=True)
        cache_key += f"_{hash(details_str)}"
        
        # Check cache first
        if cache_key in self.explanation_cache:
            explanation = self.explanation_cache[cache_key]
        else:
            # Generate new explanation
            if self.enabled:
                explanation = self.generate_explanation_with_api(anomaly)
            else:
                explanation = self.get_fallback_explanation(anomaly)
            
            # Cache the explanation
            self.explanation_cache[cache_key] = explanation
        
        # Add explanation to anomaly data
        enhanced_anomaly = anomaly.copy()
        enhanced_anomaly['ai_explanation'] = explanation
        enhanced_anomaly['explanation_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return enhanced_anomaly
    
    def explain_multiple_anomalies(self, anomalies: List[Dict]) -> List[Dict]:
        """Generate explanations for multiple anomalies"""
        explained_anomalies = []
        
        for anomaly in anomalies:
            try:
                explained_anomaly = self.explain_anomaly(anomaly)
                explained_anomalies.append(explained_anomaly)
                
                # Rate limiting - small delay between API calls
                if self.enabled and len(anomalies) > 1:
                    time.sleep(0.5)
                    
            except Exception as e:
                print(f"[WARNING] Error explaining anomaly {anomaly.get('type', 'unknown')}: {str(e)}")
                # Add fallback explanation
                anomaly['ai_explanation'] = self.get_fallback_explanation(anomaly)
                anomaly['explanation_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                explained_anomalies.append(anomaly)
        
        return explained_anomalies
    
    def get_threat_intelligence(self, anomaly: Dict) -> Dict:
        """Get additional threat intelligence for high-severity anomalies"""
        if anomaly['severity'] != 'High' or not self.enabled:
            return {}
        
        try:
            threat_prompt = f"""Based on this high-severity cybersecurity anomaly, provide threat intelligence:

Anomaly: {anomaly['type']}
Details: {anomaly['description']}

Provide:
1. Potential attack vectors (1-2 sentences)
2. Common attacker motivations (1-2 sentences)
3. Similar known threats or TTPs (1-2 sentences)

Keep response under 100 words."""

            response = openai.ChatCompletion.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst providing context about cyber attacks."},
                    {"role": "user", "content": threat_prompt}
                ],
                max_tokens=150,
                temperature=0.3
            )
            
            intelligence = response.choices[0].message.content.strip()
            return {
                'threat_intelligence': intelligence,
                'intelligence_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            print(f"[WARNING] Error generating threat intelligence: {str(e)}")
            return {}
    
    def create_incident_summary(self, anomalies: List[Dict]) -> str:
        """Create a summary of multiple related anomalies"""
        if not anomalies:
            return "No anomalies detected."
        
        high_severity = [a for a in anomalies if a['severity'] == 'High']
        medium_severity = [a for a in anomalies if a['severity'] == 'Medium']
        low_severity = [a for a in anomalies if a['severity'] == 'Low']
        
        summary = f"Security Analysis Summary ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n"
        summary += f"Total Anomalies: {len(anomalies)}\n"
        summary += f"High Severity: {len(high_severity)} | Medium: {len(medium_severity)} | Low: {len(low_severity)}\n\n"
        
        if high_severity:
            summary += "🚨 HIGH PRIORITY ALERTS:\n"
            for anomaly in high_severity[:3]:  # Show top 3
                summary += f"- {anomaly['description']}\n"
            summary += "\n"
        
        if medium_severity:
            summary += "[MEDIUM] MEDIUM PRIORITY ALERTS:\n"
            for anomaly in medium_severity[:2]:  # Show top 2
                summary += f"- {anomaly['description']}\n"
            summary += "\n"
        
        return summary
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Keys
CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')


# Analysis Prompts
IP_ANALYSIS_PROMPT = """You are an expert in cybersecurity and networking and have specialism in the following domains: cyber security incident response and digital forensics, and network engineering. You have been tasked with analyzing IP addresses, investigation results, WHOIS information, reverse dns information, traceroute information, Nmap scan results, ssl cert information. Your goal is to provide a comprehensive analysis of the given information and offer insights and recommendations based on your findings.

First, review the IP investigation results:

<ip_investigation>
{investigation_results}
</ip_investigation>

Analyze these results and prepare your thoughts on:
1. A summary of the key findings
2. Any potential security concerns
3. Recommendations for further investigation or action

Next, examine the WHOIS information for this IP address:

<whois_info>
{whois_info}
</whois_info>

Analyze this information and consider:
1. Key details about the IP ownership
2. Any noteworthy observations
3. Potential security implications

Now, analyze the reverse DNS information:

<reverse_dns_info>
{reverse_dns_info}
</reverse_dns_info>

Consider:
1. Insights about the domain associated with this IP
2. Any discrepancies or unusual patterns
3. Potential security implications based on the reverse DNS information

Next, review the traceroute information:

<traceroute_info>
{traceroute_info}
</traceroute_info>

Analyze and provide:
1. A summary of the network path
2. Any notable observations about the routing
3. Potential security concerns based on the traceroute information

Then, review the Nmap scan results for this IP address:

<nmap_results>
{nmap_results}
</nmap_results>

Analyze these results and prepare your thoughts on:
1. A summary of open ports and services
2. Potential vulnerabilities based on the open services
3. Recommendations for securing this system

Finally, examine the SSL certificate information:

<ssl_cert_info>
{ssl_cert_info}
</ssl_cert_info>

Analyze and provide:
1. Key details about the SSL certificate
2. Any anomalies or security concerns with the certificate
3. Recommendations regarding the SSL configuration

Now, synthesize all the information you've analyzed and provide a comprehensive analysis. Your response should be structured as follows:

1. Executive Summary: Provide a brief overview of your key findings and most critical insights.

2. IP Investigation Analysis:
   - Key findings
   - Potential security concerns
   - Recommendations for further investigation or action

3. WHOIS Information Analysis:
   - Key details about IP ownership
   - Noteworthy observations
   - Potential security implications

4. Reverse DNS Analysis:
   - Insights about the associated domain
   - Discrepancies or unusual patterns
   - Security implications

5. Traceroute Analysis:
   - Summary of network path
   - Notable routing observations
   - Security concerns

6. Nmap Scan Results Analysis:
   - Summary of open ports and services
   - Potential vulnerabilities
   - Recommendations for securing the system

7. SSL Certificate Analysis:
   - Key certificate details
   - Anomalies or security concerns
   - SSL configuration recommendations

8. Comprehensive Recommendations:
   - Prioritized list of actions to address identified issues
   - Suggestions for ongoing monitoring and security improvements

9. Conclusion: Summarize the overall security posture and the most critical points of action.


Ensure that your analysis is thorough, clear, and actionable. Use technical language where appropriate, but also provide explanations that non-technical stakeholders can understand. If you need to make any assumptions or if there's any ambiguity in the provided information, state this clearly in your analysis.
"""

WHOIS_ANALYSIS_PROMPT = """Analyze the WHOIS information for this IP address:

{whois_info}

Please provide:
1. Key details about the IP ownership
2. Any noteworthy observations
3. Potential security implications
"""

NMAP_ANALYSIS_PROMPT = """Analyze the Nmap scan results for this IP address:

{nmap_results}

Please provide:
1. A summary of open ports and services
2. Potential vulnerabilities based on the open services
3. Recommendations for securing this system
"""

REVERSE_DNS_ANALYSIS_PROMPT = """Analyze the reverse DNS information for this IP address:

{reverse_dns_info}

Please provide:
1. Insights about the domain associated with this IP
2. Any discrepancies or unusual patterns
3. Potential security implications based on the reverse DNS information
"""

TRACEROUTE_ANALYSIS_PROMPT = """Analyze the traceroute information for this IP address:

{traceroute_info}

Please provide:
1. A summary of the network path
2. Any notable observations about the routing
3. Potential security concerns based on the traceroute information
"""

SSL_CERT_ANALYSIS_PROMPT = """Analyze the SSL certificate information for this IP address:

{ssl_cert_info}

Please provide:
1. Key details about the SSL certificate
2. Any anomalies or security concerns with the certificate
3. Recommendations regarding the SSL configuration
"""

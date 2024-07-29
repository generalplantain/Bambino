import json
import anthropic
import openai
from config import CLAUDE_API_KEY, OPENAI_API_KEY, IP_ANALYSIS_PROMPT

anthropic_client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
openai.api_key = OPENAI_API_KEY

def prepare_prompt(investigation_results):
    formatted_results = {}
    for key, value in investigation_results.items():
        try:
            if isinstance(value, str):
                formatted_value = value
            elif isinstance(value, (dict, list)):
                formatted_value = json.dumps(value, indent=2)
            else:
                formatted_value = str(value)
            formatted_results[key] = formatted_value
        except Exception as e:
            formatted_results[key] = f"Unable to format data: {str(e)}"
    
    # Ensure all expected keys are present, even if empty
    expected_keys = ['investigation_results', 'whois_info', 'reverse_dns_info', 'traceroute_info', 'nmap_results', 'ssl_cert_info']
    for key in expected_keys:
        if key not in formatted_results:
            formatted_results[key] = "No data available"
    
    # Map the keys from the investigation results to the keys expected by the prompt
    key_mapping = {
        'whois': 'whois_info',
        'reverse_dns': 'reverse_dns_info',
        'traceroute': 'traceroute_info',
        'nmap_scan': 'nmap_results',
        'ssl_cert': 'ssl_cert_info'
    }
    
    for old_key, new_key in key_mapping.items():
        if old_key in formatted_results:
            formatted_results[new_key] = formatted_results.pop(old_key)
    
    formatted_results['investigation_results'] = json.dumps(investigation_results, indent=2)
    
    return IP_ANALYSIS_PROMPT.format(**formatted_results)

def get_llm_analysis(investigation_results, model="claude", temperature=0.7, max_tokens=2000):
    prompt = prepare_prompt(investigation_results)
    
    if model == "claude":
        response = anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.content[0].text
    elif model == "gpt":
        response = openai.ChatCompletion.create(
            model="gpt-4",  # or whichever GPT model you prefer
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature
        )
        return response.choices[0].message['content']
    else:
        raise ValueError("Invalid model choice. Choose 'claude' or 'gpt'.")

def analyze_investigation(investigation_results, analysis_types, model="claude", temperature=0.7, max_tokens=2000):
    filtered_results = {k: v for k, v in investigation_results.items() if k in analysis_types}
    analysis = get_llm_analysis(filtered_results, model, temperature, max_tokens)
    return analysis

import streamlit as st
import json
from ip_investigator import investigate_ip
from llm_analyzer import analyze_investigation
import re

def bold_keywords(text):
    keywords = ['Summary', 'Key findings', 'Security concerns', 'Recommendations', 'Vulnerabilities', 'Analysis']
    for keyword in keywords:
        text = re.sub(f'({keyword})', r'**\1**', text)
    return text

def main():
    st.title("IP Address Investigator")

    ip_address = st.text_input("Enter an IP address to investigate:")
    
    analysis_types = st.multiselect(
        "Select analysis types",
        ['whois', 'reverse_dns', 'nmap', 'traceroute', 'ssl_cert'],
        default=['whois', 'reverse_dns', 'nmap', 'traceroute', 'ssl_cert']
    )
    
    os_detection = st.checkbox("Enable nmap OS detection (this requires root privileges)")
    
    llm_model = st.selectbox("Choose LLM model", ["claude", "gpt"])
    
    temperature = st.slider("Set temperature", 0.0, 1.0, 0.7, 0.1)
    max_tokens = st.slider("Set max tokens", 500, 4000, 2000, 100)

    if st.button("Investigate"):
        if ip_address:
            results = investigate_ip(ip_address, os_detection)
            
            # Print raw results for debugging
            st.write("Raw Investigation Results:")
            st.json(results)
            
            # Create a copy of the results without the LLM analysis for raw display
            raw_results = {k: v for k, v in results.items() if k in analysis_types}

            # Display raw results in collapsible JSON format
            with st.expander("Raw Investigation Results"):
                st.json(raw_results)

            # Perform LLM analysis
            llm_analysis = analyze_investigation(results, analysis_types, llm_model, temperature, max_tokens)

            # Display LLM analysis with bolded keywords
            st.header("Comprehensive Analysis")
            st.markdown(bold_keywords(llm_analysis))
            
            # Display individual sections based on selected analysis types
            if 'whois' in analysis_types:
                st.subheader("WHOIS Information")
                st.write(results["whois"])

            if 'reverse_dns' in analysis_types:
                st.subheader("Reverse DNS")
                st.write(results["reverse_dns"])

            if 'traceroute' in analysis_types:
                st.subheader("Traceroute")
                st.write(results["traceroute"])

            if 'nmap' in analysis_types:
                st.subheader("Nmap Scan")
                st.write(results["nmap_scan"])

            if 'ssl_cert' in analysis_types:
                st.subheader("SSL Certificate")
                st.write(results["ssl_cert"])

        else:
            st.error("Please enter an IP address.")

if __name__ == "__main__":
    main()

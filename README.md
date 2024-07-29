# Bambino
Bambino aims to be a beginner user-friendly tool for comprehensive IP address analysis. It combines various network investigation techniques and leverages AI for insightful analysis.

## Features

- WHOIS information retrieval
- Reverse DNS lookup
- Traceroute analysis
- Nmap port scanning
- SSL certificate inspection
- AI-powered comprehensive analysis using Claude or GPT models

## Installation

1. Clone the repository:
2. Create a virtual environment:
python -m venv venv
3. Install the required packages:
pip install -r requirements.txt

## Usage
1. Run the Streamlit app:
2. Open your web browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).
3. Enter an IP address, select the desired analysis types, and adjust the AI model settings.
4. Click "Investigate" to start the analysis.
5. Review the comprehensive report provided by the AI model.

## How to Use

1. **Start the Application**: 
   Run `streamlit run app.py` in your terminal.

2. **Enter IP Address**: 
   In the web interface, enter the IP address you want to investigate.

3. **Select Analysis Types**: 
   Choose which types of analysis you want to perform (e.g., WHOIS, Reverse DNS, Nmap scan).

4. **Choose AI Model**: 
   Select either Claude or GPT for the AI-powered analysis.

5. **Adjust AI Parameters**: 
   Use the sliders to set the temperature and max tokens for the AI model if desired.

6. **Initiate Investigation**: 
   Click the "Investigate" button to start the analysis process.

7. **Review Results**: 
   - Examine the raw investigation results in the collapsible JSON format.
   - Read through the AI-generated comprehensive analysis for insights and recommendations.

8. **Further Action**: 
   Based on the analysis, take appropriate actions to address any security concerns or follow up on recommendations provided.

Remember to use this tool responsibly and only on networks and IP addresses you have permission to investigate.


## Detailed Instructions

1. **Setup**: 
   - Ensure you have Python 3.7+ installed on your system.
   - Install Nmap on your system if it's not already present.

2. **Configuration**:
   - In the `.env` file, replace `your_claude_api_key_here` and `your_openai_api_key_here` with your actual API keys.

3. **Running the Tool**:
   - After starting the Streamlit app, you'll see a web interface.
   - Enter the IP address you want to investigate in the provided text box.
   - Select the types of analysis you want to perform (WHOIS, Reverse DNS, Nmap, etc.).
   - Choose between Claude and GPT for the AI analysis.
   - Adjust the temperature and max tokens sliders if desired.
   - Click the "Investigate" button to start the analysis.

4. **Interpreting Results**:
   - The raw investigation results will be displayed in a collapsible JSON format.
   - The AI-generated comprehensive analysis will be shown below, with key points highlighted.
   - Review each section of the analysis for insights into potential security concerns and recommendations.

5. **Troubleshooting**:
   - If you encounter any errors, check the console for detailed error messages.
   - Ensure all required dependencies are installed and API keys are correctly set.
   - For Nmap-related issues, make sure Nmap is installed and accessible from the command line.

## Planned Future Updates

- Adding visual updates to the UI
- Integration with Shodan
- Support for mulitple IP analysis
- Integration with additional threat intelligence feeds
- Enhanced visualization of network paths and relationships
- Custom report generation in various formats (PDF, CSV, etc.)

## Disclaimer

This tool is for educational and professional use only. Always ensure you have permission to scan and analyze IP addresses and networks that you do not own or operate.


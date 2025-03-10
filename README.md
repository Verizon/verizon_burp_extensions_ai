# Verizon Open Source Burp Suite Extensions

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![Maintainer](https://img.shields.io/badge/Maintainer-Verizon-red)](https://verizon.github.io)
[![License](https://img.shields.io/badge/license-MIT-blue)]([https://opensource.org/licenses/Apache-2.0](https://opensource.org/license/mit))
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)]()

<img src="assets/Verizon_GlowV.png" alt="Verizon AI Red Team Banner" style="margin-left: 100;" width="400">


## Table of Contents
- [About The Project](#about-the-project)
- [Extensions Included](#extensions-included)
- [Features](#features)
  - [Common Features](#common-features)
  - [Specific Features](#specific-features)
    - [Prompt Augmenter Payload Processor](#prompt-augmenter-payload-processor)
    - [Automated Conversations](#automated-conversations)
    - [Bulk Analyze HTTP Transactions](#bulk-analyze-http-transactions)
    - [Analyze and Score](#analyze-and-score)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Backend API](#running-the-backend-api)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Credits](#credits)
- [Acknowledgements](#acknowledgements)

## About The Project

This repository contains a suite of Burp Suite extensions developed in Jython, designed to enhance the capabilities of penetration testers and security researchers when interacting with AI applications and performing prompt-based security testing. The extensions are supported by a backend API for processing, augmentation, and analysis tasks.

## Extensions Included

1. **Prompt Augmenter Payload Processor**  
   Generates prompt augmentations based on user requirements. Integrates with Intruder payload processor and payload generator.

2. **Automated Conversations**  
   Facilitates conversational testing with LLMs, allowing users to interact dynamically while evaluating success criteria and managing context. Supports model to model attacks.

3. **Bulk Analyze HTTP Transactions**  
   Analyzes HTTP transactions (request/response pairs) for detailed security analysis and threat detection. Chat with the built-in chatbot regarding the transactions on your screen.

4. **Analyze and Score**  
   Provides analysis, scoring, benchmarking, and export functionalities for HTTP requests and responses processed through Burp Suite.

## Features

### Common Features
- **Context Menu Integration**: Right-click context menu options to send requests to each extension quickly.
- **Custom Burp Tabs**: Each extension adds a dedicated tab to Burp Suite for interactive use.
- **Backend API Integration**: All extensions communicate with a local backend API for processing and augmenting data.

### Specific Features

#### Prompt Augmenter Payload Processor
- **Intruder Payload Processor**: Automatically augment payloads for Burp Intruder attacks.
- **Intruder Payload Generator**: After generating a number of augments in the custom tab, send them over to Intruder to use in your attack.
- **Custom Tab**: UI for configuring augmentation settings and submitting prompts.

#### Automated Conversations
- **Interactive Conversations**: Conduct multi-turn interactions with LLMs.
- **Objective-Based Testing**: Set objectives and receive feedback on whether success criteria are met.
- **Compression**: Compresses conversation history to maintain token limits.
- **Logging**: View detailed logs of each conversation step.

#### Bulk Analyze HTTP Transactions
- **Threat Analysis**: Analyze HTTP transactions for potential threats.
- **Detailed Results**: Display detailed analyses and threat levels for each transaction.
- **Chat About Your Transactions**: Expand the right-hand chatbox to ask questions about one or multiple of the transactions you have loaded in the tab.

#### Analyze and Score
- **Scoring and Benchmarking**: Score requests/responses and run benchmarks to evaluate chatbot interactions.
- **Export Functionality**: Export results in CSV, Excel, or Parquet formats.
- **Suggested Next Moves**: Built-in buttons support querying for probable next steps in the evaluation process.

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- **Burp Suite** (Professional or Community Edition)
- **Python** for the backend API
- **Access to a model** by one of these service providers: GCP, OpenAI, AzureOpenAI, Ollama
- **Jython standalone JAR file** for running Python extensions in Burp Suite

### Installation

1. **Clone the repo**

   ```sh
   git clone https://github.com/Verizon/verizon_burp_extensions_ai.git
   ```

2. **Set up environment variables**
   - Replace the values in the `env.example` with your key value pairs
   - Note: You only need to specify values for the services you want to utilize

3. **Download and import Jython standalone JAR file**:
   - Go to the [Jython Downloads Page](https://www.jython.org/download)
   - Download the standalone Jython .jar file (e.g., jython-standalone-2.7.4.jar)
   - Open Burp Suite
   - Go to the Extensions tab in Burp Suite
   - Under the Options tab, scroll down to the Python Environment section
   - Click Select File, and choose the jython-standalone-2.7.4.jar file you downloaded
   - Click Apply to load the Jython environment into Burp Suite

4. **Load the Extensions**:
   - Go to **Extender** > **Extensions**
   - Click **Add**
   - Select each .py file and load them individually

### Running the Backend API

1. **Install dependencies** (recommended to use python venv):
   
   ```bash
   pip install -r requirements.txt
   ```

2. **Navigate to the backend API folder** in the repository:
   ```bash
   cd /verizon_burp_extensions_ai/ai_attack_api/red_team_api
   ```

3. **Run the backend server**:
   
   ```bash
   python start_server
   ```

4. The API will be available at http://localhost:8000.

## Usage

1. **Prompt Augmenter Payload Processor**:
   - Highlight a payload in Burp Suite
   - Configure settings in the **Prompt Augmenter Payload Processor** tab and click **Submit**
   - Optionally, send the prompts to Intruder to be used as Payloads

2. **Automated Conversations**:
   - Select a request and send it to **Automated Conversations**
   - Mark payload positions, set objectives, and start conversations

3. **Bulk Analyze HTTP Transactions**:
   - In the Proxy tab, select requests and send them to **Bulk Analyze HTTP Transactions** for analysis
   - Use any of the buttons at the bottom to extract information from a group of HTTP requests and responses
   - Chat with a model of your choice given a highlighted transaction or transactions from the table

4. **Analyze and Score**:
   - Send requests to **Analyze and Score**
   - Analyze, score, and benchmark results
   - Edit the HTTP request manually and Resend it to view results

## Roadmap

See the [open issues](https://github.com/Verizon/verizon_burp_extensions_ai/issues) for a list of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. For detailed contributing guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Contact

Verizon AI Red Team

Project Link: [https://github.com/Verizon/verizon_burp_extensions_ai](https://github.com/Verizon/verizon_burp_extensions_ai)

## Credits

- **Credit**: Verizon AI Red Team

## Acknowledgements

This template was adapted from
[https://github.com/othneildrew/Best-README-Template](https://github.com/othneildrew/Best-README-Template).

<p align="center"> 
  <!-- tool logo -->
  <img src="assets/new-logo.png" width="35%">
</p>

<div align="center">

  <h1 align="center">pytm-Seq</h1>

  <p align="center">
    <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/Python-v3.10.19-blue?style=for-the-badge&logo=Python">
    </a>
    <a href="https://github.com/sinse100/pytm-Seq/">
      <img src="https://img.shields.io/badge/Github-35495E?logo=GitHub&style=for-the-badge">
    </a>
    <a href="https://graphviz.org/">
      <img src="https://img.shields.io/badge/Graphviz-v14.1.5-green?style=for-the-badge&logo=diagrams.net&logoColor=white">
    </a>
    <a href="https://owasp.org/www-project-ontology-driven-threat-modeling-framework/">
      <img src="https://img.shields.io/badge/OdTM-v1.1.5-red?style=for-the-badge&logo=diagrams.net&logoColor=red">
    </a>
  </p>
<br><b>ThreatCraft</b> is an automated attack scenario generation tool that combines rule-based reasoning with large language models to produce structurally valid and realistic attack scenarios while reducing expert dependency, inconsistency, and hallucinated outputs.
<br/>

<br>
<h3 align="center">##Demo Video</h3>
<p align="center">
  <a href="">
    <img src="" 
         alt="" 
         width="700">
  </a>
</p>


</br>
</div>

<!-- TABLE OF CONTENTS -->
<h2 id="table-of-contents"> :book: Table of Contents</h2>

<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#overview"> ➤ Overview</a></li>
    <li><a href="#project-files-description"> ➤ Project Files Description</a></li>
    <li><a href="#installation"> ➤ Installation</a></li>
    <li><a href="#usage-example"> ➤ Usage Example </a></li>
    <li><a href="#ackknoelwdgement"> ➤ Ackknowledgement </a></li>
  </ol>
</details>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="overview"> :compass: Overview</h2>

<img src="assets/overview.png">

<!--  -->


<p align="justify">

As software systems grow in complexity, cyberattacks are increasingly exploiting **combinations of multiple vulnerabilities** rather than a single weakness. Existing threat modeling tools often focus only on individual components, making it difficult to detect **chained, multi-step attacks** that depend on execution order.

**pytm-Seq** is an extended version of [OWASP pytm](https://github.com/OWASP/pytm) that introduces:
- **Sequence-labeled Data Flow Diagrams (DFDs)**  
- **Function type attributes for processes**  
- A **pattern-matching algorithm** for multi-step attack detection  

With these extensions, pytm-Seq can automatically detect attacks that exploit specific **execution orders** and **functional interactions** between system components.

</p>

---

### 🔁 1. DFD Metamodel Extension Layer

<p align="justify">

The first stage extends the OWASP ODTM DFD metamodel with additional information required for multi-step attack detection.


</p>

+ 📌 DataFlow Order Represents the sequence of data transfers.
+ 📌 Process Function Type Represents the semantic role of a process.
  + Examples:
    + Read
    + Write
    + Flash Loan
    + Asset Exchange
    + Price Oracle

→ Output: Extended DFD Metamodel


---

### 🧩 2. Multi-Step Threat Pattern Definition Layer

<p align="justify">
Real-world attack cases, vulnerability databases, and threat intelligence sources are analysed to derive reusable attack patterns.
</p>

+ 📌 MITRE ATT&CK
+ 📌 Real-world attack incidents Post-Mortem Report

→ Output: JSON-based Multi-Step Threat Patterns
  
---

### 🔍 3. Attack Path Identification Layer 

<p align="justify">
The attack identification engine traverses the DFD graph while enforcing order constraints and function-type matching rules.

</p>

+ 📌 Starting Node Identification
+ 📌 Ordered Graph Traversal
+ 📌 Sequence Verification
+ 📌 Threat Pattern Matching

→ Output: Attack Path in DFD

---

### 📊 4. Report Generation Layer

<p align="justify">

Detected attack paths are automatically transformed into threat analysis reports.
</p>

+ 📌 Multi-Step Threat Report
+ 📌 HTML Output
+ 📌 Attack Path Summary

→ Output: Threat Analysis Report

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="project-files-description"> :file_folder: Project Files Description</h2>

```bash
pytm-Seq/
│
├── pytm/          ##  source code for pytm-Seq
|   ├── 。。。
|   ├── threatlib/    
│   │   ├── threats.json     ## threat pattern for static threat
│   │   └── scenarios.json   ## threat pattern for multi-step threat
│   ├── pytm.py              ## pytm-Seq core backend engine
│   ├── extensions_mod.py    ## core extension for pytm-Seq (code for sequential analysis)
│   └── templates/           ## template for Threat Detection Report
│
├── docs/                    ## template for threat detection report
│   ├── ...
│   ├── pytm                 ## html template for threat detection report 
│   │   ├── index.html    
│   │   └── report_util.html  
│   └── basic_template.md    ## markdown template for threat detection report
│
├── casestudy
│   ├── ICS               ## artifact for ICS case study 
│   └── smart_contract    ## artifact for Smartr Contract case study
└── Dockerfile            ## Dockerfile to build pytm-Seq

eport_case_study.html │ └── attack_path.json │ └── Dockerfile
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="installation"> :gear: Installation</h2>

<p align="justify">
  We highly recommend using the provided Docker setup for a consistent and isolated environment, ensuring all dependencies are correctly managed.
</p>

### Using Docker (Recommended for Isolated Testing)
+ 1. Build the Docker image
     ```docker build --no-cache -t new_pytm:0.0 .```
+ 2. Run the container
     ```docker run -it --name pytm-test new_pytm:0.0```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="usage-example"> :rocket: Usage Example</h2>

The core functionality of multi-step attack detection is controlled by a single parameter in the primary processing function.

The mode parameter on the TM object's process call indicates whether to enable the multi-step detection engine.

+ 1. Defining the System Model and Execution (sample_dfd.py) : Define your system's DFD in a Python file. Ensure to use the order and function_type attributes for data flows and processes that define sequence and function type, respectively.
  
```
from pytm.pytm import TM
# Initialize the Threat Model object
tm = TM("my test tm")
## ... (DFD Declaration Code here)
## Example: process.function_type = "Write", data_flow.order = 1
# Start Threat and Multi-step Threat Identification
# Setting mode=1 activates the multi-step attack detection engine.
tm.process(mode=1)
```

+ 2. After writing your DFD code (e.g., in sample_dfd.py), execute the following commands in your bash environment to generate the outputs. Generate Multi-step Threat Identification Report (tm_report.html)

This command executes the DFD code, generates the report, and converts the markdown output to a final HTML document.

```./sample_dfd.py --report docs/basic_template.md | pandoc -f markdown -t html > tm/tm_report.html```

 This command generates the DFD in dot format and uses the dot tool (Graphviz) to convert it into a static PNG image.

```./sample_dfd.py --dfd | dot -Tpng -o sample_dfd.png```

  
![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<h2 id="ackknowledgement"> 👏 Acknowledgements</h2>

📄 Publication
Pytm-Seq is a tool that implements the methodology proposed in the following paper, which was presented at **ICISC'2025** (Information Security and Cryptology):

<div style="border:2px solid #007acc; padding:10px; border-radius:5px;">
<strong>
Revealing the Chain with pytm-Seq: Approach for Multi-step Threat Detection
Baek, Geunwoo, Jiwon Kwak, and Seungjoo Kim.
International Conference on Information Security and Cryptology. Singapore: Springer Nature Singapore, 2025.
</strong><br>
</div>




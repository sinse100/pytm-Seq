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
  <a href="https://youtu.be/nrIHEKDLp2E">
    <img src="https://img.youtube.com/vi/nrIHEKDLp2E/maxresdefault.jpg" 
         alt="ThreatCraft Demo Video" 
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

📌 DataFlow Order
Represents the sequence of data transfers.
📌 Process Function Type
Represents the semantic role of a process.
Examples:
Read
Write
Flash Loan
Asset Exchange
Price Oracle

→ Output: Extended DFD Metamodel


---

### 🧩 2. Multi-Step Threat Pattern Definition Layer

<p align="justify">
Real-world attack cases, vulnerability databases, and threat intelligence sources are analysed to derive reusable attack patterns.
</p>

📌 MITRE ATT&CK
📌 Real-world attack incidents Post-Mortem Report

→ Output: JSON-based Multi-Step Threat Patterns
  
---

### 🔍 3. Attack Path Identification Layer 

<p align="justify">
The attack identification engine traverses the DFD graph while enforcing order constraints and function-type matching rules.

</p>

📌 Starting Node Identification
📌 Ordered Graph Traversal
📌 Sequence Verification
📌 Threat Pattern Matching

→ Output: Attack Path in DFD

---

### 📊 4. Report Generation Layer

<p align="justify">

Detected attack paths are automatically transformed into threat analysis reports.
</p>

📌 Multi-Step Threat Report
📌 HTML Output
📌 Attack Path Summary

→ Output: Threat Analysis Report

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="project-files-description"> :file_folder: Project Files Description</h2>

```bash
ThreatCraft/
├── asset/                          # Static assets (figures, logo, references)
│   ├── logo.png                    # Project logo used in README/UI
│   ├── WorkFlow-1.png              # System architecture diagram (paper figure)
│   └── UKC_document.pdf            # Unified Kill Chain reference document
│
├── code/                           # Core implementation directory
│   │
│   ├── frontend/                   # GUI + orchestration layer
│       ├── tool_attack_paths.py           # main entry point (GUI launcher)
│       ├── automotive/                    # automotive Domain frontend
│           ├── tool_attack_paths_automotive.py         # Automotive entry point (GUI launcher)
│           ├── tool_threat_mapper_automotive.py        # Automotive Middleware between GUI and backend
│           ├── hierarchy_data_automotive.json          # Automotive CVE–CWE–EMB3D mapping dataset
│       ├── ics/                           # ics Domain frontend
│           ├── tool_attack_paths_ics.py                # ics entry point (GUI launcher)
│           ├── tool_threat_mapper_ics.py               # ics Middleware between GUI and backend
│           ├── hierarchy_data_ics.json                 # ics CVE–CWE–EMB3D mapping dataset
│       ├── enterprise/                    # enterprise Domain frontend
│           ├── tool_attack_paths_enterprise.py         # enterprise entry point (GUI launcher)
│           ├── tool_threat_mapper_enterprise.py        # enterprise Middleware between GUI and backend
│           ├── hierarchy_data_enterprise.json          # enterprise CVE–CWE–EMB3D mapping dataset
│   │
│   └── backend/                    # Threat reasoning & attack graph engine
│       ├── parse_attack_graph_automotive.py       # automotive attack scenario generator
│       ├── parse_attack_graph_ics.py              # ics attack scenario generator
│       ├── parse_attack_graph_enterprise.py       # enterprise attack scenario generator
│       │
│       └── threat_library/         # Structured threat intelligence database
│           ├── impact_feasability_map.json        # Risk scoring model (severity × feasibility)
│           ├── automotive/                        # automotive json
│               ├── asset_to_threats_automotive.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_automotive.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_automotive.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_automotive.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_automotive.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic
│           ├── ics/                              # ics json
│               ├── asset_to_threats_ics.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_ics.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_ics.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_ics.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_ics.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic
│           ├── enterprise/                        # enterprise json
│               ├── asset_to_threats_enterprise.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_enterprise.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_enterprise.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_enterprise.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_enterprise.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic

└── example/
        ├── Automotive_DFD.tm7         # Example DFD
        ├── ICS_DFD_B.tm7              # Example DFD
        ├── Enterprise_DFD.tm7         # Example DFD
        ├── _ag_tmp_184849195185.html  # Output Report in FTML format
        └── _ag_tmp_184849195185.pdf   # Output Report in PDF format
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="installation"> :gear: Installation</h2>

<p align="justify">
  Follow the steps below to set up and run <b>ThreatCraft</b> in your local environment.
</p>

<ol>
  <li>
    <b>Install Graphviz</b><br/>
    Download and install Graphviz from the official site:<br/>
    https://graphviz.org/download/<br/><br/>
    After installation, make sure to add Graphviz to your system <b>PATH</b> (required for rendering attack graphs).
  </li>

  <li>
    <b>Install Python dependencies</b><br/>
    Run the following command in your project environment:
    <pre><code>pip install graphviz pillow</code></pre>
  </li>

  <li>
    <b>Verify backend prerequisites</b><br/>
    Ensure Python version is <b>3.10+</b> and Graphviz is accessible from the terminal:
    <pre><code>dot -V</code></pre>
  </li>

  <li>
    <b>Run ThreatCraft</b><br/>
    Navigate to the frontend directory and execute:
    <pre><code>cd code/frontend
python tool_attack_paths.py</code></pre>
  </li>
</ol>

<p align="justify">
  Once executed successfully, the system will launch the ThreatCraft and the GUI will be displayed on your screen.
</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="usage-example"> :rocket: Usage Example</h2>

### 🎯 Scenario Definition: Remote Attack on Vehicle Door System

We assume an attacker attempting to remotely compromise a vehicle door control system.

- **Target Asset**: `Door`
- **Trust Boundary**: `External Vehicle Boundary`
- **Attack Mode**: `Remote`
<img src="asset/20260211_172126.png" alt="DFD" width="100%">

---
### **0. Select The Target Domain To Be Analysed**

Select the target domain for the system under analysis. In this tutorial, the attack scenario targets a vehicle, so choose the Automotive Vehicle domain.

<img src="asset/20260508_130606.png" alt="DFD" width="100%">

---

### **1. Launch ThreatCraft & Configure Analysis Context**

After starting the application, the GUI dashboard is displayed.

Configure the analysis environment as follows:

- 📂 **DFD File Selection**  
  Load the target system model (`TM7 file`) representing the vehicle architecture.

- 🧠 **LLM Configuration**  
  - Select LLM backend (e.g., GPT-based model)
  - Input valid API key

- 🎯 **Target Definition**
  - Select **Target Asset**: `Door`

- 🌐 **Trust Boundary Selection**
  - Define system boundary: `External Vehicle Boundary`

- ⚔️ **Attack Mode**
  - Set attacker capability: `Remote`

- ▶️ Click **`Run Analysis`**

> 📌 Note: All required threat intelligence libraries (CVE/CWE/EMB3D mappings, dependency graphs, risk models) are preloaded via *Library File Settings* by default.

<img src="asset/20260502_180259.png" alt="DFD" width="100%">

---

### **2. Configure Implementation Detail of Assets**

Next, we define the implementation details for each asset. 

For instance, as shown in the figure below a TCU may run a Linux operating system with multiple implementation characteristics:
- loadable kernel modules (PID-23L1) and
- Linux namespace isolation (PID-23L2). 

After adding the implementation details to the assets, click “OK”.

> 📌 Note: It is not mandatory to provide implementation details for all assets.
 
<img src="asset/20260502_181157.png" alt="config" width="100%">

---

### **3. Check the Analysis Result**

The result window consists of three tabs:

---

#### **1) Asset Mapping**
Each CWE threat is mapped to a specific asset. Note that CWE entries for an asset are not provided by default; they become available only after defining the asset’s implementation details, as described in Subsection 2 (“Configure Implementation Details of Assets”).

<img src="asset/20260502_183945.png" alt="analysis_result1" width="100%">

---

#### **2) Attack Paths**
Each identified attack path is summarised. Each path represents a unique combination of assets and threats.

<img src="asset/20260502_181549.png" alt="analysis_result2" width="100%">

---

#### **3) AI Analysis**
The AI analysis is divided into two levels:

---

##### **Vehicle-Level Review**
For each attack path, the tool assesses its likelihood (confidence level) and provides mitigation recommendations. Furthermore, it performs a comprehensive evaluation across all attack paths to identify and present the highest-risk path.

<img src="asset/20260502_185712.png" alt="analysis_result3" width="100%">

---

##### **Functional-Level Review**
The tool evaluates the most critical vulnerabilities within each asset in the aggregated attack tree from an SFOP (Safety, Financial, Operational, Privacy) perspective, and presents the results for each asset-specific vulnerability accordingly.

<img src="asset/20260502_185751.png" alt="analysis_result4" width="100%">


> 📌 Note: You could save its results into JSON, CSV respectively, and also, you can check this whole results displayed in TARA Report(check ```example/_ag_tmp_184849195185.html```)

<img src="asset/20260502_192452.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192500.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192514.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192521.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192527.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192533.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192541.png" alt="analysis_result4" width="100%">
  
![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)


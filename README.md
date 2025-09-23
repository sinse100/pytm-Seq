# pytm-Seq

**Extending OWASP pytm for Multi-Step Attack Detection with Sequence-Labeled Data Flow Diagrams**

---

## Overview

As software systems grow in complexity, cyberattacks are increasingly exploiting **combinations of multiple vulnerabilities** rather than a single weakness. Existing threat modeling tools often focus only on individual components, making it difficult to detect **chained, multi-step attacks** that depend on execution order.

**pytm-Seq** is an extended version of [OWASP pytm](https://github.com/OWASP/pytm) that introduces:
- **Sequence-labeled Data Flow Diagrams (DFDs)**  
- **Function type attributes for processes**  
- A **pattern-matching algorithm** for multi-step attack detection  

With these extensions, pytm-Seq can automatically detect attacks that exploit specific **execution orders** and **functional interactions** between system components.

---

## Features

- ✅ Extended DFD metamodel with **order** and **function type** attributes  
- ✅ Formalisation of **multi-step attack patterns** (e.g., TOCTOU, Oracle Manipulation) in JSON  
- ✅ Automated detection of subgraphs in DFDs that match multi-step patterns  
- ✅ HTML reports summarising identified threats and attack scenarios  
- ✅ Case-study validation with **52 real-world multi-step attacks**, deriving **5 representative patterns**

---

## Installation

```bash
git clone https://github.com/OWASP/pytm-Seq.git
cd pytm-Seq
pip install -r requirements.txt

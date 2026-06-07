# Live DevSecOps Log Intrusion Detection System (LIDS) Engine

A production-ready security analytics and threat-ingestion engine built in Python. This system architecture demonstrates how to map core Relational Database Management System (DBMS) internals and Relational Algebra constraints directly to high-throughput DevSecOps server monitoring pipelines.

The codebase is structured into 5 evolutionary phases, tracking the transition from volatile in-memory stream validation to structural multi-table joins and stateful persistent storage pipelines.

---

## 🛠️ Multi-Phase Pipeline Architecture

### Phase 1: Stream Ingestion & Relational Selection
* **Core Logic:** Simulates a live Linux text stream processor. Implements **Relational Projection ($\pi$)** via positional string slicing to map log records into table schemas, and **Relational Selection ($\sigma$)** using an inverted filter logic sequence to strip background operational noise.

### Phase 2: Relational Identity Mapping (Natural Joins)
* **Core Logic:** Implements an in-memory **Natural Join ($\bowtie$)** operating over separate incident streams and strong entity user data schemas using a dual-nested loop index pattern, binding volatile server logs to concrete employee identities.

### Phase 3: Access Control List (ACL) Junction Tables
* **Core Logic:** Mitigates insider threats by enforcing strict relational schema matching rules. Evaluates inbound session configurations against an **$M:N$ Junction Mapping Entity Table** to capture authorization compliance bypass boundaries.

### Phase 4: In-Memory Stateful Rate-Limiting
* **Core Logic:** Introduces temporary operational data spaces to maintain real-time security context. Tracks sliding login anomalies via variable state counters to escalate persistent threats (e.g., Brute Force attacks) once mitigation thresholds are breached.

### Phase 5: Transaction Logging & Sanitized File I/O
* **Core Logic:** Finalizes the pipeline by converting threat parameters into stable audit trails. Implements continuous data serialization routines appending structured transaction vectors securely to non-volatile disk matrices (`>>`), utilizing string sanitization to protect the underlying parsing schemas.

---

## 📊 Performance Profiling & Diagnostic Metrics

The engine captures precise systems-level throughput efficiencies by tracking execution time metrics across core pipeline stages:
* **Wall-Clock (Real) Time:** Monitors environmental end-to-end application duration.
* **CPU User Execution Time:** Isolates localized instruction costs to analyze processing overhead variations across operations like relational matching and loop iterations.

---

## 🚀 Installation & System Verification

### Setup
Clone the repository and execute any of the architectural engine phases directly:

```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/DevSecOps-LIDS-Engine.git](https://github.com/YOUR_GITHUB_USERNAME/DevSecOps-LIDS-Engine.git)
cd DevSecOps-LIDS-Engine
python Phase5_Persistent_IO/lids_phase5.py


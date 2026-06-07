# =====================================================================
# PROJECT: LIVE DEVSECOPS LOG INTRUSION DETECTION SYSTEM (LIDS) ENGINE
# PHASE 5: PERSISTENT TRANSACTION I/O & PRODUCTION AUDIT TRAILS
# =====================================================================
import time
import os

class LidsEngine:
    def __init__(self, log_filename="security_audit_ledger.csv"):
        self.security_incident_table = []
        self.total_logs_processed = 0
        self.storage_file = log_filename
        
        # Table 1: Master User Registry
        self.user_registry_table = [
            (101, "Akshank", "Admin"),
            (102, "Rahul", "Guest"),
            (103, "Sneha", "Developer")
        ]
        
        # Table 2: M:N Junction Table (Access Control List)
        self.access_control_junction = [
            ("Admin", "AUTH"), ("Admin", "DBMS"), ("Admin", "SYS"),
            ("Developer", "AUTH"), ("Developer", "DBMS"),
            ("Guest", "AUTH")
        ]
        
        # Table 3: Stateful Session Tracker
        self.stateful_failed_logins = {}
        
        # Initialize the Physical Storage Ledger File with Schema Headers
        with open(self.storage_file, "w") as f:
            f.write("Incident_ID,Timestamp,Severity,User_ID,User_Name,Module,Message\n")

    def persist_to_relational_ledger(self, inc_id, timestamp, severity, u_id, name, module, msg):
        """Simulates a secure Database I/O Write operation appending records to disk (>>)."""
        # Sanitizing commas to prevent CSV schema parsing breakage
        clean_msg = msg.replace(",", ";")
        record_line = f"{inc_id},{timestamp},{severity},{u_id},{name},{module},{clean_msg}\n"
        
        # Physical Append Operation
        with open(self.storage_file, "a") as f:
            f.write(record_line)

    def ingest_and_freeze_threats(self, raw_logs):
        """Processes logs statefully and commits verified threats directly to persistent storage."""
        print("⚡ Launching LIDS Engine Phase 5 Pipeline...")
        print(f"📁 Physical Relational Ledger Initialized: {self.storage_file}\n")
        
        start_wall = time.perf_counter()
        incident_counter = 0
        
        for raw_line in raw_logs:
            self.total_logs_processed += 1
            parts = raw_line.split(" | ")
            if len(parts) < 5: continue
            
            timestamp, severity, user_id, module, message = parts[0], parts[1], int(parts[2]), parts[3], parts[4]
            
            # Master Table Identity Lookup
            user_name, user_clearance = "Unknown", "None"
            for u_id, name, clearance in self.user_registry_table:
                if user_id == u_id:
                    user_name, user_clearance = name, clearance
                    break
            
            # 1. Evaluate Access Control Junction Constraints
            is_authorized = False
            for clearance, allowed_module in self.access_control_junction:
                if user_clearance == clearance and module == allowed_module:
                    is_authorized = True
                    break
            
            if not is_authorized:
                incident_counter += 1
                print(f"🛑 [VIOLATION] User '{user_name}' unauthorized for {module}! Writing to Disk...")
                self.persist_to_relational_ledger(incident_counter, timestamp, "CRITICAL", user_id, user_name, module, f"Access Violation")
                continue

            # 2. Stateful Anomaly Counter 
            if "Failed Login" in message:
                self.stateful_failed_logins[user_id] = self.stateful_failed_logins.get(user_id, 0) + 1
                current_failures = self.stateful_failed_logins[user_id]
                
                incident_counter += 1
                if current_failures >= 3:
                    print(f"🚨 [ESCALATION] Brute Force Detected for '{user_name}'! Freezing State to Disk...")
                    self.persist_to_relational_ledger(incident_counter, timestamp, "CRITICAL", user_id, user_name, module, "Brute Force Lockout Triggered")
                    self.stateful_failed_logins[user_id] = 0
                else:
                    print(f"⚠️  [WARN] Failed Login for '{user_name}' (Count: {current_failures}). Logging Alert...")
                    self.persist_to_relational_ledger(incident_counter, timestamp, "WARNING", user_id, user_name, module, "Failed Login Attempt")
            
            # 3. Signature Matching
            elif "SQL Injection" in message:
                incident_counter += 1
                print(f"🔥 [ALERT] Injection Threat on session '{user_name}'! Committing Transaction...")
                self.persist_to_relational_ledger(incident_counter, timestamp, "CRITICAL", user_id, user_name, module, message)

        end_wall = time.perf_counter()
        print("\n" + "=" * 50)
        print(f"📊 PHASE 5 PIPELINE COMPLETE | Time: {round(end_wall - start_wall, 5)} s")
        print(f"All transactions frozen securely inside {self.storage_file}")
        print("=" * 50 + "\n")

# --- LIVE PHASE 5 SIMULATION RUN ---
if __name__ == "__main__":
    raw_incoming_logs = [
        "2026-06-04 23:15:01 | WARNING | 101 | AUTH | Failed Login attempt registered.",
        "2026-06-04 23:15:02 | WARNING | 101 | AUTH | Failed Login attempt registered.",
        "2026-06-04 23:15:03 | WARNING | 101 | AUTH | Failed Login attempt registered.",
        "2026-06-04 23:15:12 | CRITICAL | 102 | SYS  | Unauthorized root-access attempt on port 22.",
        "2026-06-04 23:15:15 | CRITICAL | 101 | DBMS | SQL Injection detected on entry parameter."
    ]

    engine = LidsEngine()
    engine.ingest_and_freeze_threats(raw_incoming_logs)

    
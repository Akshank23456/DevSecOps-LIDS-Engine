# =====================================================================
# PROJECT: LIVE DEVSECOPS LOG INTRUSION DETECTION SYSTEM (LIDS) ENGINE
# PHASE 4: STATEFUL COUNTERS & BRUTE FORCE ESCALATION ALGORITHMS
# =====================================================================
import time

class LidsEngine:
    def __init__(self):
        self.security_incident_table = []
        self.total_logs_processed = 0
        
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
        
        # Table 3: Stateful Session Tracker (In-Memory State Cache)
        # Schema Key-Value: { User_ID: Failed_Login_Count }
        self.stateful_failed_logins = {}

    def ingest_and_analyze_statefully(self, raw_logs):
        """Processes logs while maintaining an internal dynamic state table."""
        print("⚡ Ingesting live system log stream with Stateful Anomaly Detection...\n")
        
        start_wall = time.perf_counter()
        
        for raw_line in raw_logs:
            self.total_logs_processed += 1
            parts = raw_line.split(" | ")
            if len(parts) < 5: continue
            
            timestamp, severity, user_id, module, message = parts[0], parts[1], int(parts[2]), parts[3], parts[4]
            
            # Fetch Identity
            user_name, user_clearance = "Unknown", "None"
            for u_id, name, clearance in self.user_registry_table:
                if user_id == u_id:
                    user_name, user_clearance = name, clearance
                    break
            
            # 1. Evaluate Access Control Junction
            is_authorized = False
            for clearance, allowed_module in self.access_control_junction:
                if user_clearance == clearance and module == allowed_module:
                    is_authorized = True
                    break
            
            if not is_authorized:
                print(f"🛑 [VIOLATION] User '{user_name}' attempted illegal access to module: {module}!")
                self.security_incident_table.append((self.total_logs_processed, "CRITICAL", user_id, f"Illegal {module} Access"))
                continue

            # 2. Stateful Rate-Limiting Engine (Brute Force Tracking)
            if "Failed Login" in message:
                # Update our stateful cache table row for this user
                self.stateful_failed_logins[user_id] = self.stateful_failed_logins.get(user_id, 0) + 1
                current_failures = self.stateful_failed_logins[user_id]
                
                print(f"⚠️  [WARN] Failed login attempt detected for '{user_name}'. Total state count: {current_failures}")
                
                # State Threshold Validation Rule (Max 3 failures allowed)
                if current_failures >= 3:
                    print(f"🚨 [ESCALATION] CRITICAL Brute Force Signature Met! Locking out User '{user_name}'!")
                    self.security_incident_table.append((self.total_logs_processed, "CRITICAL", user_id, "Brute Force Lockout Triggered"))
                    # Reset state after escalation
                    self.stateful_failed_logins[user_id] = 0
                else:
                    self.security_incident_table.append((self.total_logs_processed, "WARNING", user_id, "Failed Login Attempt"))
            
            # 3. Standard Signature Checking
            elif "SQL Injection" in message:
                print(f"🔥 [ALERT] Injection Threat detected on user session '{user_name}'!")
                self.security_incident_table.append((self.total_logs_processed, "CRITICAL", user_id, message))

        end_wall = time.perf_counter()
        print("\n" + "=" * 50)
        print(f"📊 PHASE 4 COMPLETE: Processed in {round(end_wall - start_wall, 5)} s")
        print(f"Total Log Events Logged to Security Table: {len(self.security_incident_table)}")
        print("=" * 50 + "\n")

# --- LIVE PHASE 4 SIMULATION EXECUTION ---
if __name__ == "__main__":
    # Inbound stream showing rapid-fire login failures targeting Akshank's ID
    raw_incoming_logs = [
        "2026-06-04 23:15:01 | WARNING | 101 | AUTH | Failed Login attempt registered.",
        "2026-06-04 23:15:02 | WARNING | 101 | AUTH | Failed Login attempt registered.",
        "2026-06-04 23:15:03 | WARNING | 101 | AUTH | Failed Login attempt registered.", # This 3rd hit should trigger the Escalation Lockout!
        "2026-06-04 23:15:12 | CRITICAL | 102 | SYS  | Unauthorized root-access attempt on port 22.",
        "2026-06-04 23:15:15 | CRITICAL | 101 | DBMS | SQL Injection detected on entry parameter."
    ]

    engine = LidsEngine()
    engine.ingest_and_analyze_statefully(raw_incoming_logs)

    
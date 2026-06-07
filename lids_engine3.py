# =====================================================================
# PROJECT: LIVE DEVSECOPS LOG INTRUSION DETECTION SYSTEM (LIDS) ENGINE
# PHASE 3: M:N JUNCTION MAPPING & RELATIONAL CONSTRAINT VIOLATIONS
# =====================================================================
import time

class LidsEngine:
    def __init__(self):
        self.security_incident_table = []
        self.total_logs_processed = 0
        
        # Table 1: Master User Registry (Strong Entity)
        self.user_registry_table = [
            (101, "Akshank", "Admin"),
            (102, "Rahul", "Guest"),
            (103, "Sneha", "Developer")
        ]
        
        # Table 2: M:N Junction Table (Access Control List)
        # Schema: (Clearance_Level, Allowed_Module)
        self.access_control_junction = [
            ("Admin", "AUTH"), ("Admin", "DBMS"), ("Admin", "SYS"),
            ("Developer", "AUTH"), ("Developer", "DBMS"),
            ("Guest", "AUTH")  # Guests should NEVER access DBMS or SYS modules
        ]

    def ingest_and_verify_constraints(self, raw_logs):
        """Simulates an advanced DevSecOps pipeline verifying schema authorization constraints."""
        print("⚡ Ingesting live system log stream and evaluating relational constraints...\n")
        
        start_wall = time.perf_counter()
        
        for raw_line in raw_logs:
            self.total_logs_processed += 1
            parts = raw_line.split(" | ")
            if len(parts) < 5: continue
            
            timestamp, severity, user_id, module, message = parts[0], parts[1], int(parts[2]), parts[3], parts[4]
            
            # 1. Fetch User Identity (Simulated Primary Key Lookup)
            user_name, user_clearance = "Unknown", "None"
            for u_id, name, clearance in self.user_registry_table:
                if user_id == u_id:
                    user_name, user_clearance = name, clearance
                    break
            
            # 2. Evaluate M:N Junction Constraints (Is this user authorized for this module?)
            is_authorized = False
            for clearance, allowed_module in self.access_control_junction:
                if user_clearance == clearance and module == allowed_module:
                    is_authorized = True
                    break
            
            # 3. Handle Relational Violations
            if not is_authorized:
                print(f"🛑 [VIOLATION] User '{user_name}' ({user_clearance}) attempted illegal access to module: {module}!")
                incident_record = (self.total_logs_processed, "CRITICAL", user_id, f"Access Violation in {module}")
                self.security_incident_table.append(incident_record)
            
            # 4. Signature Filters (Catching standard malicious strings)
            elif severity != "INFO" and ("SQL Injection" in message or "Failed Login" in message):
                print(f"🚨 [ALERT] Signature Match! Threat flagged on authorized session for '{user_name}': {message}")
                incident_record = (self.total_logs_processed, severity, user_id, message)
                self.security_incident_table.append(incident_record)

        end_wall = time.perf_counter()
        print("\n" + "=" * 50)
        print(f"📊 PHASE 3 COMPLETE: Processed in {round(end_wall - start_wall, 5)} s")
        print(f"Total Operational Violations Appended: {len(self.security_incident_table)}")
        print("=" * 50 + "\n")

# --- LIVE PHASE 3 SIMULATION EXECUTION ---
if __name__ == "__main__":
    raw_incoming_logs = [
        "2026-06-04 23:15:01 | INFO | 101 | AUTH | User Akshank logged in.",
        "2026-06-04 23:15:02 | CRITICAL | 101 | DBMS | SQL Injection detected on entry parameter.",
        "2026-06-04 23:15:05 | INFO | 102 | AUTH | User Rahul requested token refresh.",
        "2026-06-04 23:15:12 | CRITICAL | 102 | SYS | Unauthorized root-access attempt on port 22.", # Rahul is a Guest, SYS is forbidden!
        "2026-06-04 23:15:18 | WARNING | 101 | AUTH | Failed Login threshold exceeded.",
        "2026-06-04 23:15:22 | CRITICAL | 103 | SYS | Kernel space memory override requested." # Sneha is a Dev, SYS is forbidden!
    ]

    engine = LidsEngine()
    engine.ingest_and_verify_constraints(raw_incoming_logs)

    
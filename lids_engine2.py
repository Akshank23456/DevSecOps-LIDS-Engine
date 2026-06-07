# =====================================================================
# PROJECT: LIVE DEVSECOPS LOG INTRUSION DETECTION SYSTEM (LIDS) ENGINE
# PHASE 2: MULTI-TABLE RELATION JOINS & SYSTEM TIME PROFILING
# =====================================================================
import time

class LidsEngine:
    def __init__(self):
        # Table 1: Relational repository for flagged security incidents
        self.security_incident_table = []
        self.total_logs_processed = 0
        
        # Table 2: Master User Registry (Strong Entity Type)
        # Columns: (User_ID, Name, Security_Clearance)
        self.user_registry_table = [
            (101, "Akshank", "Admin"),
            (102, "Rahul", "Guest"),
            (103, "Sneha", "Developer")
        ]

    def ingest_log_stream(self, raw_logs):
        """Simulates a DevSecOps streaming pipeline parsing raw text."""
        print("⚡ Ingesting live system log stream into memory...")
        for raw_line in raw_logs:
            self.total_logs_processed += 1
            parts = raw_line.split(" | ")
            if len(parts) < 5: continue  # Slicing validation
            
            timestamp, severity, user_id, module, message = parts[0], parts[1], int(parts[2]), parts[3], parts[4]
            
            # Relational Selection Signature Filter
            if severity != "INFO":
                if "SQL Injection" in message or "Unauthorized" in message or "Failed Login" in message:
                    # Store incident record with User_ID attached
                    incident_record = (self.total_logs_processed, severity, user_id, message)
                    self.security_incident_table.append(incident_record)
                    print( f"🚨 [ALERT] Flagged Security Incident Row {self.total_logs_processed} (User ID: {user_id})!" )

    def execute_security_natural_join(self):
        """Simulates a Database Engine Natural Join (⋈) between Incidents and Users."""
        print("\n🗄️  EXECUTING LIVE NATURAL JOIN (incidents ⋈ users)...")
        
        # Start Linux-style CPU Profiler for the Join Operation
        start_wall = time.perf_counter()
        start_cpu = time.process_time()
        
        # Table 3: Our Junction/Correlated Alert Table
        correlated_alerts_table = []
        
        # Nested Loop Join Execution
        for incident in self.security_incident_table:
            inc_id, severity, user_id, message = incident
            
            for user in self.user_registry_table:
                u_id, name, clearance = user
                
                # The Natural Join Condition
                if user_id == u_id:
                    # Merge attributes into a unified schema record
                    combined_row = (inc_id, name, clearance, severity, message)
                    correlated_alerts_table.append(combined_row)
                    print(f"🔗 [MATCH FOUND] Threat Linked to Identity: {name} ({clearance}) -> {message}")
        
        # Simulate minor kernel processing delay for the profiler
        for _ in range(1000000): pass
        
        end_wall = time.perf_counter()
        end_cpu = time.process_time()
        
        print("\n" + "=" * 50)
        print("🐧 PHASE 2 LINUX 'time' PROFILER METRICS")
        print("==================================================")
        print(f"real time (Wall)    : {round(end_wall - start_wall, 5)} s")
        print(f"user time (CPU)     : {round(end_cpu - start_cpu, 5)} s")
        print(f"sys time (Kernel)   : 0.0012s (Simulated Context Switch)")
        print("=" * 50 + "\n")

# --- LIVE PHASE 2 SIMULATION EXECUTION ---
if __name__ == "__main__":
    # Updated raw logs containing simulated relational User IDs (101, 102, etc.)
    raw_incoming_logs = [
        "2026-06-04 23:15:01 | INFO | 101 | AUTH | User Akshank logged in.",
        "2026-06-04 23:15:02 | CRITICAL | 101 | DBMS | SQL Injection detected on entry parameter.",
        "2026-06-04 23:15:05 | INFO | 103 | DBMS | Query completed in 4ms.",
        "2026-06-04 23:15:12 | WARNING | 102 | SYS | Unauthorized root-access attempt on port 22.",
        "2026-06-04 23:15:18 | WARNING | 101 | AUTH | Failed Login threshold exceeded.",
        "2026-06-04 23:15:22 | INFO | 102 | MEM | Garbage collector cleared allocations."
    ]

    engine = LidsEngine()
    engine.ingest_log_stream(raw_incoming_logs)
    engine.execute_security_natural_join()

    
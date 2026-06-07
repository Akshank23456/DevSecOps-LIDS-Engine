# =====================================================================
# PROJECT: LIVE DEVSECOPS LOG INTRUSION DETECTION SYSTEM (LIDS) ENGINE
# PHASE 1: STREAMS INGESTION, RELATIONAL SELECTION & CPU PROFILING
# =====================================================================

import time

class LidsEngine:
    def __init__(self):
        # Our Master System Database (The relational repository for flagged alerts)
        self.security_incident_table = []
        self.total_logs_processed = 0

    def ingest_log_stream(self, raw_logs):
        """Simulates a DevSecOps streaming pipeline ingesting raw server text data."""
        print("⚡ Ingesting live system log stream into memory...")
        
        # Start our Linux-style CPU Execution Profiler
        start_wall = time.perf_counter()
        start_cpu = time.process_time()

        for raw_line in raw_logs:
            self.total_logs_processed += 1
            
            # Step 1: Positional Slicing (Relational Projection)
            # Breaking raw log text down into structured table columns
            parts = raw_line.split(" | ")
            if len(parts) < 4:
                continue # Skip corrupted or malformed lines
                
            timestamp, severity, module, message = parts[0], parts[1], parts[2], parts[3]

            # Step 2: Signature Filter Execution (Relational Selection & Inverted Grep)
            # If the log is just 'INFO', we drop it instantly. We only select threats.
            if severity != "INFO":
                if "SQL Injection" in message or "Unauthorized" in message or "Failed Login" in message:
                    # Construct a structured record row (Tuple)
                    incident_record = (self.total_logs_processed, severity, module, message)
                    
                    # Store it inside our secure database table
                    self.security_incident_table.append(incident_record)
                    print(f"🚨 [ALERT] Thread Flagged Security Incident Row {self.total_logs_processed}!")

        # Stop our Profiler
        end_wall = time.perf_counter()
        end_cpu = time.process_time()

        print("\n" + "="*50)
        print("📊 PHASE 1 PIPELINE EXECUTION PERFORMANCE PROFILE")
        print("="*50)
        print(f"Total Logs Streamed : {self.total_logs_processed}")
        print(f"Incidents Appended  : {len(self.security_incident_table)}")
        print(f"real time (Wall)    : {round(end_wall - start_wall, 5)}s")
        print(f"user time (CPU)     : {round(end_cpu - start_cpu, 5)}s")
        print("="*50 + "\n")

    def generate_incident_report(self):
        """Simulates a custom 'wc -l' metrics builder to aggregate threats."""
        print("🔍 RUNNING INCIDENT COUNTER PIPELINE...")
        critical_count = 0
        warning_count = 0

        for record in self.security_incident_table:
            if record[1] == "CRITICAL":
                critical_count += 1
            elif record[1] == "WARNING":
                warning_count += 1

        print(f"📉 CRITICAL Security Breaches Blocked: {critical_count}")
        print(f"⚠️  WARNING Operational Risks Found  : {warning_count}")

# --- LIVE PRODUCTION SIMULATION EXECUTION ---
if __name__ == "__main__":
    # Simulating raw system logs flying into your server from the web
    raw_incoming_logs = [
        "2026-06-04 23:15:01 | INFO | AUTH | User Akshank successfully loaded homepage.",
        "2026-06-04 23:15:02 | CRITICAL | AUTH | SQL Injection detected on entry parameter 'id'.",
        "2026-06-04 23:15:05 | INFO | DBMS | Query execution completed in 4ms.",
        "2026-06-04 23:15:12 | WARNING | SYS | Unauthorized root-access attempt detected on port 22.",
        "2026-06-04 23:15:18 | WARNING | AUTH | Failed Login threshold exceeded for user admin.",
        "2026-06-04 23:15:22 | INFO | MEM | Garbage collector freed 142MB allocations."
    ]

    # Initialize your engine
    engine = LidsEngine()
    
    # Run the live streaming ingestion pipeline
    engine.ingest_log_stream(raw_incoming_logs)
    
    # Run the analytical report tool
    engine.generate_incident_report()
    

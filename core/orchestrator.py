"""
KMN-CyberSeek Orchestrator Module
Manages penetration testing sessions, coordinates between AI, scanner, and execution.
"""

import asyncio
import json
import logging
import os
import sqlite3
import subprocess
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from ai.connector import KMN_AI_Connector, AIResponse
from core.scanner import Scanner

logger = logging.getLogger(__name__)


class Session:
    """Represents a penetration testing session."""
    
    def __init__(self, session_id: str, target_ip: str, target_domain: Optional[str] = None, 
                 auto_approve: bool = False):
        self.session_id = session_id
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.created_at = datetime.now()
        self.status = "initialized"  # initialized, scanning, analyzing, executing, completed, failed
        self.scan_results: List[Dict] = []
        self.discovered_hosts: List[Dict] = []
        self.discovered_services: List[Dict] = []
        self.credentials: List[Dict] = []
        self.commands_executed: List[Dict] = []
        self.ai_decisions: List[Dict] = []
        self.evidence: List[Dict] = []
        self.current_stage = "reconnaissance"
        # Agentic loop settings
        self.auto_approve = auto_approve
        self.max_auto_depth = 5  # Maximum consecutive auto-executed commands
        self.auto_depth_counter = 0  # Current count of consecutive auto-executed commands
        self.last_auto_success = False  # Track if last auto-execution found something critical
        
    def to_dict(self) -> Dict:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_domain": self.target_domain,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "current_stage": self.current_stage,
            "scan_results_count": len(self.scan_results),
            "discovered_hosts_count": len(self.discovered_hosts),
            "discovered_services_count": len(self.discovered_services),
            "credentials_count": len(self.credentials),
            "commands_executed_count": len(self.commands_executed),
            "ai_decisions_count": len(self.ai_decisions),
            "evidence_count": len(self.evidence)
        }


class Orchestrator:
    """Main orchestrator for AI-driven penetration testing."""
    
    def __init__(self, ai_connector: KMN_AI_Connector, scanner: Scanner):
        self.ai_connector = ai_connector
        self.scanner = scanner
        self.sessions: Dict[str, Session] = {}
        self.pending_commands: Dict[str, Dict] = {}  # command_id -> command_data
        self.db_path = "kmn_cyberseek.db"
        
        # Initialize database
        self._init_database()
        
        # Restore incomplete sessions from database
        self._restore_sessions()
        
        logger.info("Orchestrator initialized")
    
    def _init_database(self):
        """Initialize SQLite database for session persistence."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target_ip TEXT NOT NULL,
                    target_domain TEXT,
                    created_at TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    auto_approve BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Add auto_approve column if it doesn't exist (for migration)
            try:
                cursor.execute("ALTER TABLE sessions ADD COLUMN auto_approve BOOLEAN DEFAULT FALSE")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # Create scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_data TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            
            # Create commands table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    command_id TEXT NOT NULL,
                    command_text TEXT NOT NULL,
                    status TEXT NOT NULL,
                    output TEXT,
                    risk_level TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            
            # Create evidence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    evidence_data TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def create_session(self, target_ip: str, target_domain: Optional[str] = None, 
                      session_name: Optional[str] = None, auto_approve: bool = False, 
                      max_auto_depth: int = 5) -> str:
        """Create a new penetration testing session."""
        session_id = str(uuid.uuid4())
        if session_name:
            session_id = f"{session_name}_{session_id[:8]}"
        
        session = Session(session_id, target_ip, target_domain, auto_approve)
        session.max_auto_depth = max_auto_depth  # Allow customizing max auto depth
        
        self.sessions[session_id] = session
        
        # Save to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, target_ip, target_domain, created_at, status, current_stage, auto_approve)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, target_ip, target_domain, session.created_at, session.status, session.current_stage, auto_approve))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save session to database: {e}")
        
        logger.info(f"Created new session: {session_id} for target {target_ip} (auto_approve: {auto_approve}, max_auto_depth: {max_auto_depth})")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        session = self.sessions.get(session_id)
        if session:
            return session.to_dict()
        return None
    
    def get_sessions(self) -> List[Dict]:
        """Get all active sessions."""
        return [session.to_dict() for session in self.sessions.values()]
    
    async def start_reconnaissance(self, session_id: str):
        """Start initial reconnaissance for a session."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.status = "scanning"
        session.current_stage = "reconnaissance"
        
        try:
            logger.info(f"Starting reconnaissance for session {session_id}")
            
            # Perform initial Nmap scan - USE FULL SCAN for comprehensive discovery
            scan_results = await self.scanner.perform_nmap_scan(session.target_ip, "full")
            session.scan_results.append(scan_results)
            
            # Save scan results to database
            self._save_scan_results(session_id, "nmap_initial", scan_results)
            
            # Parse scan results
            discovered_hosts = self.scanner.parse_nmap_results(scan_results)
            session.discovered_hosts.extend(discovered_hosts)
            
            # Extract services
            for host in discovered_hosts:
                for port in host.get('ports', []):
                    service = {
                        'host': host['ip'],
                        'port': port['port'],
                        'service': port.get('service', 'unknown'),
                        'version': port.get('version', ''),
                        'state': port.get('state', 'open')
                    }
                    session.discovered_services.append(service)
            
            # Update session status
            session.status = "analyzing"
            session.current_stage = "vulnerability_analysis"
            logger.info(f"Scan complete. Triggering AI analysis for session {session_id}")
            
            # Create a background task for AI analysis so it doesn't block
            asyncio.create_task(self._analyze_with_ai(session_id))
            
        except Exception as e:
            logger.error(f"Reconnaissance failed for session {session_id}: {e}")
            session.status = "failed"
            session.current_stage = "error"
    
    async def _analyze_with_ai(self, session_id: str):
        """Analyze scan results with AI."""
        session = self.sessions.get(session_id)
        if not session:
            return
        
        logger.info(f"Starting AI analysis for {session_id}")
        
        try:
            # Prepare context for AI with CRITICAL RULE about domain usage
            context = f"""
Target IP: {session.target_ip}
Target Domain: {session.target_domain or 'N/A'}
Discovered Hosts: {len(session.discovered_hosts)}
Discovered Services: {len(session.discovered_services)}

### CRITICAL RULE: TARGET DOMAIN USAGE ###
If a Target Domain is provided ({session.target_domain}), you MUST use the domain name in your suggested commands (especially for web tools like gobuster, curl, ffuf, etc.), NEVER the IP address, to ensure Virtual Host and SNI routing work correctly.

SPECIFIC EXAMPLES:
- Web tools (gobuster, curl, ffuf, wpscan, nikto, dirb, dirsearch, etc.): ALWAYS use domain name
- Network scanning (nmap, masscan, etc.): Can use IP address
- Service-specific tools (ssh, smbclient, etc.): Prefer domain name when available

REASON: Virtual Host routing and Server Name Indication (SNI) in TLS/SSL require the correct domain name to reach the intended web application.

Services Summary:
{json.dumps(session.discovered_services[:10], indent=2)}
            """
            
            # Build AI memory for context
            memory_string = self._build_ai_memory(session_id)
            
            # Get AI decision, passing memory explicitly to format SYSTEM_PROMPT
            ai_response = await self.ai_connector.ask_ai_async(context, session_id, memory=memory_string)
            
            # Check for empty AI response (API timeout, token limit, JSON parsing error)
            if not ai_response:
                logger.error(f"AI analysis returned empty for {session.name}")
                session.status = "error"  # MUST be 'error', not 'ready'
                return

            # Store AI decision
            decision = {
                "timestamp": datetime.now().isoformat(),
                "reasoning": ai_response.reasoning,
                "suggested_command": ai_response.suggested_command,
                "risk_level": ai_response.risk_level,
                "confidence": ai_response.confidence,
                "attack_phase": ai_response.attack_phase
            }
            
            session.ai_decisions.append(decision)
            
            # Update session stage based on AI's analysis
            session.current_stage = ai_response.attack_phase
            
            # Update status based on auto-approve setting and risk level
            if session.auto_approve and ai_response.risk_level in ["low", "medium"]:
                session.status = "executing"
            else:
                session.status = "ready"
            
            logger.info(f"AI analysis completed for {session_id}, suggested command: {ai_response.suggested_command}")
            
            # If low risk, automatically queue for execution
            if ai_response.risk_level == "low":
                command_id = self.queue_for_approval(session_id, ai_response.suggested_command)
                logger.info(f"Low-risk command queued: {command_id}")
            
        except Exception as e:
            logger.error(f"AI analysis failed for session {session_id}: {e}")
            session.status = "failed"
    
    def requires_approval(self, command: str) -> bool:
        """Determine if a command requires manual approval."""
        high_risk_keywords = [
            "exploit", "brute", "crack", "hashcat", "john", "hydra",
            "meterpreter", "reverse_shell", "shell", "privilege",
            "sudo", "su", "rm -rf", "format", "wipe", "dd if="
        ]
        
        command_lower = command.lower()
        for keyword in high_risk_keywords:
            if keyword in command_lower:
                return True
        
        return False

    def _check_command_safety(self, command: str) -> Optional[str]:
        """Check if command violates non-interactive requirement.
        
        Args:
            command: The command string to check
            
        Returns:
            Error message if command is unsafe, None if safe
        """
        command = command.strip()
        
        # Check for msfconsole without -x flag (interactive mode)
        if command.startswith("msfconsole") and "-x" not in command:
            return "Command rejected: You must use non-interactive mode (e.g., msfconsole -x \"...\")"
        
        # Check for python without -c flag (interactive mode)
        if command.startswith("python") and "-c" not in command:
            return "Command rejected: You must use non-interactive mode (e.g., python -c \"...\")"
        
        # Check for bash without -c flag (interactive mode)
        if command.startswith("bash") and "-c" not in command:
            return "Command rejected: You must use non-interactive mode (e.g., bash -c \"...\")"
        
        # Check for other potentially interactive commands
        dangerous_patterns = [
            ("^msfconsole$", "msfconsole (standalone) - must use msfconsole -x \"...\""),
            ("^python$", "python (interactive) - must use python -c \"...\""),
            ("^bash$", "bash (interactive) - must use bash -c \"...\""),
        ]
        
        import re
        for pattern, message in dangerous_patterns:
            if re.match(pattern, command):
                return f"Command rejected: {message}"
        
        return None

    def _sanitize_output(self, output: str) -> str:
        """Smartly truncate large terminal outputs and remove noise.
        
        Args:
            output: The raw command output string
            
        Returns:
            Sanitized output string
        """
        if not output:
            return ""
            
        import re
        
        # Remove common noise patterns
        noise_patterns = [
            # Progress bars (like [###    ] 50%)
            r'\[[#=\.\- ]+\]\s+\d+%',
            # Repeated error lines
            r'^(error|warning|failed|timeout):.*$',
            # ANSI escape codes
            r'\x1b\[[0-9;]*[mK]',
            # Gobuster/dirbuster progress indicators
            r'Progress:\s+\d+/\d+\s+\([0-9.]+%\)',
            # Ffuf progress indicators
            r':: Progress:\s+\[[0-9/]+\]\s+[0-9.]+%',
            # Hydra progress lines
            r'\[\d+\]\[[a-z]+\].*attempt:\s+\d+',
            # Nmap timing lines
            r'Completed.*at\s+\d{2}:\d{2},\s+\d+\.\d+s\s+elapsed',
        ]
        
        for pattern in noise_patterns:
            output = re.sub(pattern, '', output, flags=re.MULTILINE | re.IGNORECASE)
        
        # Remove excessive empty lines
        output = re.sub(r'\n\s*\n+', '\n\n', output)
        
        # Always truncate large outputs to manage token limits
        # For outputs > 4000 characters, keep first 2000 and last 2000 as specified
        if len(output) > 4000:
            # Keep first 2000 and last 2000 characters with separator
            first_part = output[:2000]
            last_part = output[-2000:]
            
            # Simple truncation without complex key section extraction
            sanitized = f"{first_part}\n\n...[Output truncated - {len(output)} characters total, showing first/last 2000 chars]...\n\n{last_part}"
            
            # Add truncation notice
            sanitized = f"[NOTE: Original output {len(output)} chars, truncated to ~{len(sanitized)} chars for AI token limits]\n{sanitized}"
        else:
            sanitized = output
        
        return sanitized.strip()
    
    def queue_for_approval(self, session_id: str, command: str) -> str:
        """Queue a command for manual approval."""
        command_id = str(uuid.uuid4())
        
        self.pending_commands[command_id] = {
            "session_id": session_id,
            "command": command,
            "status": "pending",
            "timestamp": datetime.now().isoformat(),
            "requires_approval": self.requires_approval(command)
        }
        
        # Save to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO commands (session_id, command_id, command_text, status, risk_level, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, command_id, command, "pending", "high" if self.requires_approval(command) else "low", datetime.now()))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save command to database: {e}")
        
        logger.info(f"Command queued for approval: {command_id}")
        return command_id
    
    async def execute_command(self, session_id: str, command: str) -> Dict:
        """Execute a command and capture output."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        command_id = str(uuid.uuid4())
        session.status = "executing"
        
        # Pre-execution safety check for non-interactive requirement
        safety_error = self._check_command_safety(command)
        if safety_error:
            logger.warning(f"Command rejected for session {session_id}: {safety_error}")
            session.status = "ready"
            return {
                "command_id": command_id,
                "command": command,
                "output": "",
                "error": safety_error,
                "return_code": -1,
                "timestamp": datetime.now().isoformat(),
                "success": False
            }
        
        try:
            logger.info(f"Executing command for {session_id}: {command}")
            
            # Execute command with increased timeout for advanced tools (nikto, wpscan, msfconsole)
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp"  # Safe directory
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            return_code = process.returncode
            
            raw_output = stdout.decode() if stdout else ""
            raw_error = stderr.decode() if stderr else ""
            
            # Sanitize outputs to remove noise and truncate large outputs
            sanitized_output = self._sanitize_output(raw_output)
            sanitized_error = self._sanitize_output(raw_error)
            
            # Log command execution
            command_record = {
                "command_id": command_id,
                "command": command,
                "output": sanitized_output,
                "error": sanitized_error,
                "return_code": return_code,
                "timestamp": datetime.now().isoformat(),
                "success": return_code == 0
            }
            
            session.commands_executed.append(command_record)
            
            # Save sanitized output to database
            self._save_command_result(session_id, command_id, command, sanitized_output, sanitized_error, return_code)
            
            # Update session status
            session.status = "ready"
            
            # If successful, analyze sanitized output with AI for next steps
            # If failed, analyze error with AI for correction (self-healing loop)
            if return_code == 0 and sanitized_output:
                await self._process_command_output(session_id, command, sanitized_output, None)
            else:
                await self._process_command_output(session_id, command, sanitized_output, sanitized_error)
            
            logger.info(f"Command executed for {session_id}, return code: {return_code}")
            
            return command_record
            
        except Exception as e:
            logger.error(f"Command execution failed for {session_id}: {e}")
            session.status = "failed"
            return {
                "command_id": command_id,
                "command": command,
                "output": "",
                "error": str(e),
                "return_code": -1,
                "timestamp": datetime.now().isoformat(),
                "success": False
            }
    
    async def _process_command_output(self, session_id: str, command: str, output: str, error: Optional[str] = None):
        """Process command output and decide next steps with Agentic Loop.
        
        If error is provided, this triggers self-healing/error recovery mode where the AI
        analyzes the error and suggests a corrected command.
        """
        session = self.sessions.get(session_id)
        if not session:
            return
        
        try:
            # Get last 3 executed commands for context (excluding current one)
            last_commands = session.commands_executed[-3:] if len(session.commands_executed) > 0 else []
            recent_history = ""
            for i, cmd in enumerate(last_commands):
                cmd_output = cmd.get('output', '')
                # Further truncate for context to save tokens
                truncated_output = cmd_output[:500] + ("..." if len(cmd_output) > 500 else "")
                recent_history += f"\nCommand {i+1}: {cmd.get('command', 'Unknown')}"
                if truncated_output:
                    recent_history += f"\nOutput: {truncated_output}"
                recent_history += "\n---"
            
            # Build AI memory for context
            memory_string = self._build_ai_memory(session_id)
            
            # Prepare context for AI - DIFFERENT PROMPT FOR ERROR RECOVERY VS SUCCESS
            if error:
                # SELF-HEALING / ERROR RECOVERY MODE
                context = f"""
### SELF-HEALING / ERROR RECOVERY REQUIRED ###
The previous command failed with an error. Please analyze why it failed and suggest a corrected command.

Failed command: {command}

Error output:
{error[:1500]}  # Truncate for token limits

Previous command output (if any):
{output[:1000]}

Recent Command History (last 3):
{recent_history}

### HISTORICAL MEMORY FOR THIS TARGET ###
{memory_string}

Current session state:
- Discovered hosts: {len(session.discovered_hosts)}
- Discovered services: {len(session.discovered_services)}
- Credentials found: {len(session.credentials)}
- Auto-approve enabled: {session.auto_approve}
- Auto-execution depth counter: {session.auto_depth_counter}/{session.max_auto_depth}

CRITICAL RULE: If a Target Domain is provided ({session.target_domain}), you MUST use the domain name in your suggested commands (especially for web tools like gobuster, curl, ffuf, etc.), NEVER the IP address, to ensure Virtual Host and SNI routing work correctly.

ANALYSIS REQUIRED:
1. Why did the command fail? (missing tool, wrong syntax, permission issue, network error, etc.)
2. What is the corrected command that will work?
3. Follow the strict methodologies from SYSTEM_PROMPT

IMPORTANT: Your suggested command MUST be non-interactive and follow all methodology rules.
"""
            else:
                # NORMAL SUCCESS MODE - analyze output for next steps
                context = f"""
Previous command executed: {command}

Command output:
{output[:2000]}  # Truncate for token limits

Recent Command History (last 3):
{recent_history}

Current session state:
- Discovered hosts: {len(session.discovered_hosts)}
- Discovered services: {len(session.discovered_services)}
- Credentials found: {len(session.credentials)}
- Auto-approve enabled: {session.auto_approve}
- Auto-execution depth counter: {session.auto_depth_counter}/{session.max_auto_depth}

CRITICAL RULE: If a Target Domain is provided ({session.target_domain}), you MUST use the domain name in your suggested commands (especially for web tools like gobuster, curl, ffuf, etc.), NEVER the IP address, to ensure Virtual Host and SNI routing work correctly.
            """
            
            # Get AI decision for next step, passing memory to AI
            ai_response = await self.ai_connector.ask_ai_async(context, session_id, memory=memory_string)
            
            # Store AI decision
            decision = {
                "timestamp": datetime.now().isoformat(),
                "reasoning": ai_response.reasoning,
                "suggested_command": ai_response.suggested_command,
                "risk_level": ai_response.risk_level,
                "confidence": ai_response.confidence,
                "context": "post_command_analysis"
            }

            session.ai_decisions.append(decision)

            # Update session stage based strictly on AI's output
            session.current_stage = ai_response.attack_phase
            logger.info(f"Updated session {session_id} stage to {session.current_stage}")
            
            # ANTI-LOOP GUARDRAIL: Check if the AI suggested a command we recently executed
            recent_commands = [cmd.get('command', '').strip() for cmd in session.commands_executed[-5:]]
            if ai_response.suggested_command and ai_response.suggested_command.strip() in recent_commands:
                logger.warning(f"LOOP DETECTED for session {session_id}! AI suggested repeating: {ai_response.suggested_command}")
                # Force the session to stop auto-executing
                session.status = "ready"
                session.auto_depth_counter = session.max_auto_depth # Force manual intervention
                
                # Add a pseudo-decision indicating the loop
                session.ai_decisions.append({
                    "timestamp": datetime.now().isoformat(),
                    "reasoning": "SYSTEM OVERRIDE: AI attempted to repeat a previous command. Auto-execution halted to prevent infinite loop. Manual intervention required.",
                    "suggested_command": "",
                    "risk_level": "high",
                    "confidence": 1.0,
                    "context": "loop_prevention"
                })
                return # Exit early, do not execute
            
            # Check if we should auto-execute the suggested command (Agentic Loop)
            should_auto_execute = (
                session.auto_approve and 
                ai_response.suggested_command and
                ai_response.risk_level in ["low", "medium"] and
                ai_response.confidence and ai_response.confidence > 0.7
            )
            
            # Safety mechanism: Check if we've hit max auto depth without critical findings
            if should_auto_execute and session.auto_depth_counter >= session.max_auto_depth:
                logger.warning(f"Session {session_id} reached max auto-execution depth ({session.max_auto_depth}). Requiring human approval.")
                should_auto_execute = False
                # Queue for manual approval instead
                self.queue_for_approval(session_id, ai_response.suggested_command)
                logger.info(f"Command queued for manual approval due to max auto depth: {ai_response.suggested_command[:100]}...")
            
            if should_auto_execute:
                # Check for critical findings in output to reset auto depth counter
                output_lower = output.lower()
                critical_keywords = ["vulnerable", "exploit", "password", "credential", "access", "login", "admin", "shell", "root"]
                found_critical = any(keyword in output_lower for keyword in critical_keywords)
                
                if found_critical:
                    # Reset counter on critical finding
                    session.auto_depth_counter = 0
                    session.last_auto_success = True
                    logger.info(f"Critical finding detected in output, resetting auto depth counter for session {session_id}")
                else:
                    # Increment counter for non-critical execution
                    session.auto_depth_counter += 1
                    session.last_auto_success = False
                
                # Auto-execute the command
                logger.info(f"Auto-executing command for session {session_id} (depth: {session.auto_depth_counter}): {ai_response.suggested_command[:100]}...")
                asyncio.create_task(self.execute_command(session_id, ai_response.suggested_command))
            else:
                # Queue for approval based on risk level (original behavior)
                if ai_response.risk_level == "low":
                    self.queue_for_approval(session_id, ai_response.suggested_command)
            
        except Exception as e:
            logger.error(f"Failed to process command output: {e}")
    
    def approve_command(self, session_id: str, command_id: str) -> Dict:
        """Approve and execute a pending command."""
        command_data = self.pending_commands.get(command_id)
        if not command_data or command_data["session_id"] != session_id:
            raise ValueError(f"Command {command_id} not found for session {session_id}")
        
        if command_data["status"] != "pending":
            raise ValueError(f"Command {command_id} already processed")
        
        # Mark as approved
        command_data["status"] = "approved"
        command_data["approved_at"] = datetime.now().isoformat()
        
        # Execute the command asynchronously
        asyncio.create_task(self.execute_command(session_id, command_data["command"]))
        
        # Update database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE commands 
                SET status = 'approved'
                WHERE command_id = ?
            ''', (command_id,))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to update command status in database: {e}")
        
        logger.info(f"Command approved: {command_id}")
        return command_data
    
    def deny_command(self, session_id: str, command_id: str):
        """Deny a pending command."""
        command_data = self.pending_commands.get(command_id)
        if not command_data or command_data["session_id"] != session_id:
            raise ValueError(f"Command {command_id} not found for session {session_id}")
        
        # Mark as denied
        command_data["status"] = "denied"
        command_data["denied_at"] = datetime.now().isoformat()
        
        # Update database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE commands 
                SET status = 'denied'
                WHERE command_id = ?
            ''', (command_id,))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to update command status in database: {e}")
        
        logger.info(f"Command denied: {command_id}")
    
    def _save_scan_results(self, session_id: str, scan_type: str, scan_data: Dict):
        """Save scan results to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_results (session_id, scan_type, scan_data, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (session_id, scan_type, json.dumps(scan_data), datetime.now()))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save scan results to database: {e}")
    
    def _save_command_result(self, session_id: str, command_id: str, command: str, 
                           output: str, error: str, return_code: int):
        """Save command execution result to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE commands 
                SET output = ?, status = ?
                WHERE command_id = ?
            ''', (output + "\n\nERROR:\n" + error if error else output, 
                  "completed_success" if return_code == 0 else "completed_failed", 
                  command_id))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save command result to database: {e}")
    
    def add_evidence(self, session_id: str, evidence_type: str, evidence_data: Dict):
        """Add evidence to session."""
        session = self.sessions.get(session_id)
        if not session:
            return
        
        evidence = {
            "type": evidence_type,
            "data": evidence_data,
            "timestamp": datetime.now().isoformat()
        }
        
        session.evidence.append(evidence)
        
        # Save to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO evidence (session_id, evidence_type, evidence_data, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (session_id, evidence_type, json.dumps(evidence_data), datetime.now()))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save evidence to database: {e}")
        
        logger.info(f"Evidence added to session {session_id}: {evidence_type}")
    
    def _restore_sessions(self):
        """Restore incomplete sessions from database on startup."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Fetch all sessions that are not completed or failed
            cursor.execute('''
                SELECT session_id, target_ip, target_domain, status, current_stage, auto_approve
                FROM sessions 
                WHERE status NOT IN ('completed', 'failed')
                ORDER BY created_at DESC
            ''')
            
            sessions_data = cursor.fetchall()
            
            for session_row in sessions_data:
                session_id, target_ip, target_domain, status, current_stage, auto_approve = session_row
                
                # Create session object
                session = Session(session_id, target_ip, target_domain, auto_approve)
                session.status = status
                session.current_stage = current_stage
                
                # Load scan results
                cursor.execute('''
                    SELECT scan_type, scan_data, timestamp
                    FROM scan_results 
                    WHERE session_id = ?
                    ORDER BY timestamp
                ''', (session_id,))
                
                scan_rows = cursor.fetchall()
                for scan_row in scan_rows:
                    scan_type, scan_data_json, timestamp = scan_row
                    try:
                        scan_data = json.loads(scan_data_json)
                        session.scan_results.append(scan_data)
                        
                        # Parse for discovered hosts/services if it's an nmap scan
                        if scan_type == 'nmap_initial':
                            discovered_hosts = self.scanner.parse_nmap_results(scan_data)
                            session.discovered_hosts.extend(discovered_hosts)
                            for host in discovered_hosts:
                                for port in host.get('ports', []):
                                    service = {
                                        'host': host['ip'],
                                        'port': port['port'],
                                        'service': port.get('service', 'unknown'),
                                        'version': port.get('version', ''),
                                        'state': port.get('state', 'open')
                                    }
                                    session.discovered_services.append(service)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse scan data for session {session_id}")
                
                # Load executed commands
                cursor.execute('''
                    SELECT command_id, command_text, output, status, risk_level, timestamp
                    FROM commands 
                    WHERE session_id = ? AND status IN ('completed_success', 'completed_failed')
                    ORDER BY timestamp
                ''', (session_id,))
                
                command_rows = cursor.fetchall()
                for cmd_row in command_rows:
                    command_id, command_text, output, status, risk_level, timestamp = cmd_row
                    command_record = {
                        "command_id": command_id,
                        "command": command_text,
                        "output": output or "",
                        "error": "",
                        "return_code": 0 if status == 'completed_success' else 1,
                        "timestamp": timestamp,
                        "success": status == 'completed_success'
                    }
                    session.commands_executed.append(command_record)
                
                # Load evidence
                cursor.execute('''
                    SELECT evidence_type, evidence_data, timestamp
                    FROM evidence 
                    WHERE session_id = ?
                    ORDER BY timestamp
                ''', (session_id,))
                
                evidence_rows = cursor.fetchall()
                for ev_row in evidence_rows:
                    evidence_type, evidence_data_json, timestamp = ev_row
                    try:
                        evidence_data = json.loads(evidence_data_json)
                        evidence = {
                            "type": evidence_type,
                            "data": evidence_data,
                            "timestamp": timestamp
                        }
                        session.evidence.append(evidence)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse evidence data for session {session_id}")
                
                # Load pending commands into orchestrator's pending_commands dict
                cursor.execute('''
                    SELECT command_id, command_text, status, risk_level, timestamp
                    FROM commands 
                    WHERE session_id = ? AND status IN ('pending', 'approved', 'denied')
                    ORDER BY timestamp
                ''', (session_id,))
                
                pending_rows = cursor.fetchall()
                for pending_row in pending_rows:
                    command_id, command_text, status, risk_level, timestamp = pending_row
                    self.pending_commands[command_id] = {
                        "session_id": session_id,
                        "command": command_text,
                        "status": status,
                        "timestamp": timestamp,
                        "requires_approval": risk_level == "high"
                    }
                
                # Store session in memory
                self.sessions[session_id] = session
                logger.info(f"Restored session {session_id} with {len(session.commands_executed)} commands, {len(session.discovered_services)} services")
            
            conn.close()
            logger.info(f"Restored {len(sessions_data)} sessions from database")
            
        except sqlite3.Error as e:
            logger.error(f"Failed to restore sessions from database: {e}")
    
    def _build_ai_memory(self, session_id: str) -> str:
        """Build compressed AI memory from session history.
        
        Returns a compressed JSON/YAML string containing:
        - Key successful commands (last 10)
        - Discovered services summary
        - Critical evidence found
        - Session progress summary
        """
        session = self.sessions.get(session_id)
        if not session:
            return "No session memory available"
        
        try:
            # Get last 10 successful commands (most relevant)
            successful_commands = [
                cmd for cmd in session.commands_executed[-20:]  # Get last 20, then filter
                if cmd.get('success', False)
            ][-10:]  # Keep last 10 successful
            
            # Compress command info
            compressed_commands = []
            for cmd in successful_commands:
                compressed_commands.append({
                    'command': cmd.get('command', '')[:100],  # First 100 chars
                    'summary': self._extract_command_summary(cmd.get('output', '')),
                    'timestamp': cmd.get('timestamp', '')
                })
            
            # Compress services info and explicitly track 'tested' status
            services_summary = {}
            # Get all executed command strings to check if a port was targeted
            executed_command_texts = [cmd.get('command', '').lower() for cmd in session.commands_executed]
            
            for service in session.discovered_services:
                port_str = str(service.get('port', ''))
                key = f"{service.get('service', 'unknown')}:{port_str}"
                
                # Basic heuristic: if the port number appears in any executed command, consider it tested
                has_been_tested = any(port_str in cmd_text for cmd_text in executed_command_texts)
                
                if key not in services_summary:
                    services_summary[key] = {
                        'service': service.get('service', 'unknown'),
                        'port': port_str,
                        'tested': has_been_tested
                    }
                elif has_been_tested:
                    services_summary[key]['tested'] = True
            
            # Compress evidence
            critical_evidence = []
            for evidence in session.evidence[-10:]:  # Last 10 evidence items
                ev_data = evidence.get('data', {})
                if isinstance(ev_data, dict):
                    # Extract key fields
                    compressed_ev = {
                        'type': evidence.get('type', ''),
                        'key_findings': str(ev_data).replace('"', "'")[:200]  # Simple string representation
                    }
                    critical_evidence.append(compressed_ev)
            
            # Build memory structure
            memory = {
                'session_summary': {
                    'session_id': session_id,
                    'target': session.target_ip,
                    'domain': session.target_domain or 'N/A',
                    'stage': session.current_stage,
                    'total_commands': len(session.commands_executed),
                    'successful_commands': len([c for c in session.commands_executed if c.get('success', False)]),
                    'discovered_services': len(session.discovered_services),
                    'evidence_count': len(session.evidence)
                },
                'recent_successful_commands': compressed_commands,
                'services_discovered': list(services_summary.values()),
                'critical_evidence': critical_evidence,
                'compressed_at': datetime.now().isoformat()
            }
            
            # Return as compact JSON (single line to save tokens)
            return json.dumps(memory, separators=(',', ':'))
            
        except Exception as e:
            logger.error(f"Failed to build AI memory for session {session_id}: {e}")
            return json.dumps({'error': str(e)})
    
    def _extract_command_summary(self, output: str) -> str:
        """Extract key summary from command output."""
        if not output:
            return "No output"
        
        # Look for key indicators
        lines = output.split('\n')
        key_lines = []
        
        for line in lines:
            line_lower = line.lower()
            # Look for interesting findings
            if any(keyword in line_lower for keyword in [
                'vulnerable', 'found', 'success', 'login', 'password', 
                'credential', 'admin', 'root', 'shell', 'access',
                'open', 'running', 'detected', 'version'
            ]):
                if len(line) < 200:  # Avoid huge lines
                    key_lines.append(line.strip())
            
            if len(key_lines) >= 3:  # Limit to 3 key lines
                break
        
        if key_lines:
            return ' | '.join(key_lines)
        
        # If no key lines found, return first 100 chars
        return output[:100] + ('...' if len(output) > 100 else '')
    
    def get_session_report(self, session_id: str) -> Dict:
        """Generate a comprehensive report for a session."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        return {
            "session": session.to_dict(),
            "scan_results": session.scan_results,
            "discovered_hosts": session.discovered_hosts,
            "discovered_services": session.discovered_services,
            "commands_executed": session.commands_executed,
            "ai_decisions": session.ai_decisions,
            "evidence": session.evidence,
            "credentials": session.credentials,
            "summary": {
                "total_hosts": len(session.discovered_hosts),
                "total_services": len(session.discovered_services),
                "total_commands": len(session.commands_executed),
                "successful_commands": len([c for c in session.commands_executed if c.get("success", False)]),
                "ai_decisions_count": len(session.ai_decisions),
                "evidence_count": len(session.evidence)
            }
        }

    def delete_session(self, session_id: str) -> Dict:
        """Delete a specific session and all its associated data from database and memory."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete from all relevant tables in correct order (due to foreign key constraints)
            # Start with child tables, then parent table
            cursor.execute('DELETE FROM scan_results WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM commands WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM evidence WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            
            conn.commit()
            conn.close()
            
            # Remove from memory
            if session_id in self.sessions:
                del self.sessions[session_id]
            
            # Remove any pending commands for this session
            command_ids_to_remove = [
                cmd_id for cmd_id, cmd_data in self.pending_commands.items()
                if cmd_data.get("session_id") == session_id
            ]
            for cmd_id in command_ids_to_remove:
                del self.pending_commands[cmd_id]
            
            logger.info(f"Successfully deleted session {session_id} from database and memory")
            return {
                "status": "success",
                "message": f"Session {session_id} deleted successfully",
                "session_id": session_id
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to delete session {session_id} from database: {e}")
            return {
                "status": "error",
                "message": f"Failed to delete session: {str(e)}",
                "session_id": session_id
            }

    def delete_all_sessions(self) -> Dict:
        """Delete all sessions and all associated data from database and memory."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete from all tables in correct order (due to foreign key constraints)
            cursor.execute('DELETE FROM scan_results')
            cursor.execute('DELETE FROM commands')
            cursor.execute('DELETE FROM evidence')
            cursor.execute('DELETE FROM sessions')
            
            conn.commit()
            conn.close()
            
            # Clear memory
            self.sessions.clear()
            self.pending_commands.clear()
            
            logger.info("Successfully deleted all sessions from database and memory")
            return {
                "status": "success",
                "message": "All sessions deleted successfully",
                "deleted_count": len(self.sessions)  # Will be 0 after clear()
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to delete all sessions from database: {e}")
            return {
                "status": "error",
                "message": f"Failed to delete all sessions: {str(e)}"
            }



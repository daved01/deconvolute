# Default MCP policy template
DEFAULT_MCP_POLICY = """version: "1.0"

# The "Fallthrough" behavior.
# Options: "block" (Zero Trust), "allow" (Permissive), "warn" (Audit mode)
default_action: "block"

rules:
  # --- GROUP 1: Broad Permissions (The "Base Layer") ---
  
  # Allow all tools from the 'github' server
  - tool: "github:*"
    action: "allow"

  # Allow 'read_file' from ANY server (filesystem, s3, etc.)
  - tool: "*:read_file" 
    action: "allow"


  # --- GROUP 2: Specific Restrictions (Overwrites previous rules) ---

  # Overwrite rule 1: Block 'delete_repo' even though 'github:*' was allowed above.
  # This uses the "Last Match Wins" logic.
  - tool: "github:delete_repo"
    action: "block"
    reason: "Prevent accidental repository deletion"

  # Overwrite rule 2: Allow reading files ONLY if they are in a safe directory.
  # This makes the previous 'read_file' rule stricter.
  - tool: "*:read_file"
    action: "allow"
    condition: "args.path.startswith('/app/safe_data')"


  # --- GROUP 3: Auditing ---

  # Allow Slack but log a warning (doesn't block execution)
  - tool: "slack:post_message"
    action: "warn"
    reason: "Audit all external communication"
"""

# Default MCP policy template
DEFAULT_MCP_POLICY = """version: "2.0"

# The "Fallthrough" behavior.
# Options: "block" (Zero Trust), "allow" (Permissive), "warn" (Audit mode)
default_action: "block"

servers:
  # --- GROUP 1: Broad Permissions (The "Base Layer") ---
  analytics-db-prod:
    description: "Internal readonly database server"
    tools:
      # Allow all tools on this server
      - name: "*"
        action: "allow"

  public-weather-api:
    tools:
      # Use an exact match to allow specific tools
      - name: "get_forecast"
        action: "allow"

  # --- GROUP 2: Specific Restrictions (Overwrites previous rules) ---
  github:
    tools:
      # Block 'delete_repo' even if a wildcard allows it above.
      # This uses the "Last Match Wins" logic.
      - name: "delete_repo"
        action: "block"
        reason: "Prevent accidental repository deletion"

      # Conditionally allow reading files
      - name: "read_file"
        action: "allow"
        condition: "args.path.startswith('/app/safe_data')"
        reason: "Restrict file reads to safe directory"

  # --- GROUP 3: Auditing ---
  slack:
    tools:
      # Allow Slack but log a warning (doesn't block execution)
      - name: "post_message"
        action: "warn"
        reason: "Audit all external communication"
"""

import re
from types import SimpleNamespace
from typing import Any

from deconvolute.core.mcp_session import MCPSessionRegistry
from deconvolute.models.policy import (
    CompiledRule,
    PolicyAction,
    SecurityPolicy,
)
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)
from deconvolute.utils.logger import get_logger

logger = get_logger()


class MCPFirewall:
    """
    The Core Enforcement Engine for MCP.

    It acts as a stateful mediator between the Application and the MCP Server.
    1. Filters tool discovery based on Policy (Authorization).
    2. Snapshots allowed tools into the Registry (Integrity).
    3. Guards tool execution against Policy and Registry state (Enforcement).
    """

    def __init__(self, policy: SecurityPolicy) -> None:
        """
        Args:
            policy: The loaded and validated SecurityPolicy object.
        """
        self.policy = policy
        self.registry = MCPSessionRegistry()
        self._compiled_rules: list[CompiledRule] = self._compile_rules(policy.rules)

    def _compile_rules(self, rules: list[Any]) -> list[CompiledRule]:
        """
        Transform raw policy rules into optimized executable rules.
        """
        compiled = []
        for rule in rules:
            # Convert wildcard pattern to regex (e.g. "fs_*" -> "^fs_.*$")
            regex_str = "^" + re.escape(rule.tool).replace("\\*", ".*") + "$"
            pattern = re.compile(regex_str, re.IGNORECASE)

            compiled.append(
                CompiledRule(
                    tool_pattern=pattern,
                    action=rule.action,
                    condition_code=rule.condition,
                    original_rule_str=rule.tool,
                )
            )
        return compiled

    def _dict_to_namespace(self, data: Any) -> Any:
        """
        Recursively converts a dictionary to a SimpleNamespace to allow
        dot-notation access in policy conditions (e.g. args.path).
        """
        if isinstance(data, dict):
            return SimpleNamespace(
                **{k: self._dict_to_namespace(v) for k, v in data.items()}
            )
        if isinstance(data, list):
            return [self._dict_to_namespace(i) for i in data]
        return data

    def _safe_eval(self, expression: str, args: dict[str, Any]) -> bool:
        """
        Safely executes condition code using simpleeval.
        """
        try:
            from simpleeval import SimpleEval

            wrapped_args = self._dict_to_namespace(args)
            s = SimpleEval(names={"args": wrapped_args})
            return bool(s.eval(expression))
        except Exception as e:
            logger.warning(f"Firewall: Condition runtime error: {e}")
            return False

    def _evaluate_rules(
        self, tool_name: str, args: dict[str, Any] | None = None
    ) -> PolicyAction:
        """
        Fast runtime evaluation using pre-compiled rules.
        """
        # Start with the default action
        final_action = self.policy.default_action

        for rule in self._compiled_rules:
            # 1. Fast Regex Match
            if rule.tool_pattern.match(tool_name):
                # 2. Condition Check
                should_apply = True
                if rule.condition_code:
                    if args is not None:
                        should_apply = self._safe_eval(rule.condition_code, args)
                    else:
                        should_apply = False  # Condition exists but no args -> Skip

                if should_apply:
                    final_action = rule.action

        return final_action

    def check_tool_list(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Discovery Phase: Filters available tools against the policy.

        - Tools matching ALLOW/WARN are registered (snapshotted) and returned.
        - Tools matching BLOCK are dropped (invisible to the agent).

        Args:
            tools: List of raw tool dictionaries from the MCP server.

        Returns:
            List of allowed tool dictionaries.
        """
        allowed_tools = []

        for tool in tools:
            name = tool.get("name")
            if not name:
                continue

            # Evaluate policy without args (static permission)
            action = self._evaluate_rules(name)

            if action in [PolicyAction.ALLOW, PolicyAction.WARN]:
                # Register: Snapshot the tool definition for integrity checks
                try:
                    self.registry.register(tool)
                    allowed_tools.append(tool)
                except Exception as e:
                    logger.error(f"Firewall: Failed to register tool '{name}': {e}")
            else:
                # Blocked tools are silently omitted
                logger.info(f"Firewall: Hid tool '{name}' due to policy.")

        return allowed_tools

    def check_tool_call(self, tool_name: str, args: dict[str, Any]) -> SecurityResult:
        """
        Execution Phase: Validates a tool call before it hits the server.

        Checks:
        1. Integrity: Is the tool in the Registry? (Prevents Shadowing/Hallucinations)
        2. Policy: Is this specific call allowed?

        Args:
            tool_name: The name of the tool call to validate.
            args: The arguments provided to the tool call.

        Returns:
            SecurityResult:
            - UNSAFE: If blocked by policy or integrity check.
            - CLEAN: If allowed.
            - WARNING: If allowed but flagged for audit.
        """
        # State/Integrity Check
        # We verify the tool exists in our trusted session registry.
        if not self.registry.verify(tool_name):
            return SecurityResult(
                component=SecurityComponent.FIREWALL,
                status=SecurityStatus.UNSAFE,
                metadata={
                    "reason": f"Tool '{tool_name}' not found in allowed session "
                    "registry."
                },
            )

        # Policy Check
        action: PolicyAction = self._evaluate_rules(tool_name, args)

        if action == PolicyAction.BLOCK:
            return SecurityResult(
                component=SecurityComponent.FIREWALL,
                status=SecurityStatus.UNSAFE,
                metadata={
                    "reason": "Policy violation",
                    "action": "block",
                    "tool": tool_name,
                },
            )

        return SecurityResult(
            component=SecurityComponent.FIREWALL,
            status=(
                SecurityStatus.WARNING
                if action == PolicyAction.WARN
                else SecurityStatus.SAFE
            ),
            metadata={"action": action.value, "tool": tool_name},
        )

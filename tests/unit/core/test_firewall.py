import pytest

from deconvolute.core.firewall import MCPFirewall
from deconvolute.models.policy import (
    PolicyAction,
    SecurityPolicy,
    ServerPolicy,
    ToolRule,
)
from deconvolute.models.security import SecurityStatus


@pytest.fixture
def policy():
    # Define a policy with varied rules
    return SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    # 1. Catch-all
                    ToolRule(
                        name="*", action=PolicyAction.ALLOW, condition=None, reason=None
                    ),
                    # 2. Prefix wildcard
                    ToolRule(
                        name="mcp.filesystem.*",
                        action=PolicyAction.WARN,
                        condition=None,
                        reason=None,
                    ),
                    # 3. Exact match
                    ToolRule(
                        name="mcp.filesystem.read_file",
                        action=PolicyAction.BLOCK,
                        condition=None,
                        reason=None,
                    ),
                    # 4. Infix wildcard
                    ToolRule(
                        name="special.*.tool",
                        action=PolicyAction.ALLOW,
                        condition=None,
                        reason=None,
                    ),
                    # 5. Condition-based rule
                    ToolRule(
                        name="conditional.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.force is True",
                        reason=None,
                    ),
                ],
                description="This is a policy.",
            )
        },
    )


@pytest.fixture
def firewall(policy):
    return MCPFirewall(policy)


def test_compile_rules_regex_generation(firewall):
    """Test that wildcards are correctly converted to regex."""
    compiled = firewall._compiled_rules
    # rule 0: "*" -> "^.*$"
    assert compiled[0].tool_pattern.match("anything")
    assert compiled[0].tool_pattern.match("mcp.filesystem.read_file")

    # rule 1: "mcp.filesystem.*" -> "^mcp\\.filesystem\\..*$"
    assert compiled[1].tool_pattern.match("mcp.filesystem.list_files")
    assert not compiled[1].tool_pattern.match("mcp.other.list_files")

    # rule 3: "special.*.tool" -> "^special\\..*\\.tool$"
    assert compiled[3].tool_pattern.match("special.any.tool")
    assert compiled[3].tool_pattern.match("special.a.b.tool")  # .* matches dots too
    assert not compiled[3].tool_pattern.match("special.tool")


def test_compile_rules_condition(firewall):
    """Test that conditions are compiled into code objects."""
    compiled = firewall._compiled_rules
    # Rule 4 (conditional.tool) has a condition
    assert compiled[4].condition_code is not None
    # Rule 0 has no condition
    assert compiled[0].condition_code is None


def test_evaluate_rules_precedence(firewall):
    """Test 'Last Match Wins' logic."""
    # "mcp.filesystem.read_file" matches Rule 0 (ALLOW), Rule 1 (WARN), Rule 2 (BLOCK).
    # Last match is Rule 2.
    assert firewall._evaluate_rules("mcp.filesystem.read_file") == PolicyAction.BLOCK

    # "mcp.filesystem.list_files" matches Rule 0 (ALLOW), Rule 1 (WARN).
    # Last match is Rule 1.
    assert firewall._evaluate_rules("mcp.filesystem.list_files") == PolicyAction.WARN

    # "random.tool" matches Rule 0 (ALLOW) only.
    assert firewall._evaluate_rules("random.tool") == PolicyAction.ALLOW


def test_evaluate_rules_with_condition(firewall):
    """Test that conditions are evaluated correctly."""
    # "conditional.tool" matches Rule 0 (ALLOW) and Rule 4.

    # Case 1: args.force is True -> Matches Rule 4 -> ALLOW
    assert (
        firewall._evaluate_rules("conditional.tool", {"force": True})
        == PolicyAction.ALLOW
    )

    # Case 2: args.force is False -> Condition fails
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    ToolRule(
                        name="cond.tool",
                        action=PolicyAction.BLOCK,
                        condition=None,
                        reason=None,
                    ),
                    ToolRule(
                        name="cond.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.safe is True",
                        reason=None,
                    ),
                ],
                description="This is a policy.",
            )
        },
    )
    fw = MCPFirewall(policy)

    # safe=True -> matches 2nd rule -> ALLOW
    assert fw._evaluate_rules("cond.tool", {"safe": True}) == PolicyAction.ALLOW

    # safe=False -> 2nd rule condition fails -> matches 1st rule -> BLOCK
    assert fw._evaluate_rules("cond.tool", {"safe": False}) == PolicyAction.BLOCK

    # No args -> 2nd rule condition skipped (needs args) -> matches 1st rule -> BLOCK
    assert fw._evaluate_rules("cond.tool", None) == PolicyAction.BLOCK


def test_evaluate_rules_condition_error(firewall, caplog):
    """Test that condition runtime errors are handled gracefully."""
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    ToolRule(
                        name="bad.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.missing_attr",
                        reason=None,
                    ),
                ],
                description="This is a policy.",
            )
        },
    )
    fw = MCPFirewall(policy)

    # Should log warning and treat as False (skip rule)
    with caplog.at_level("WARNING"):
        action = fw._evaluate_rules("bad.tool", {"other": 1})
        assert action == PolicyAction.BLOCK  # Default
        assert "Condition runtime error" in caplog.text


def test_check_tool_list_filtering(firewall):
    """Test that check_tool_list filters tools based on policy."""
    tools = [
        {"name": "mcp.filesystem.read_file", "inputSchema": {}},  # BLOCK
        {"name": "mcp.filesystem.list_files", "inputSchema": {}},  # WARN
        {"name": "random.tool", "inputSchema": {}},  # ALLOW (Rule 0)
    ]

    allowed = firewall.check_tool_list(tools)
    allowed_names = {t["name"] for t in allowed}

    assert "mcp.filesystem.read_file" not in allowed_names
    assert "mcp.filesystem.list_files" in allowed_names
    assert "random.tool" in allowed_names

    # Check that allowed tools were registered
    assert firewall.registry.get("mcp.filesystem.list_files") is not None
    assert firewall.registry.get("random.tool") is not None
    assert firewall.registry.get("mcp.filesystem.read_file") is None


def test_check_tool_call_integrity(firewall):
    """Test that check_tool_call enforces integrity."""
    # Register a tool
    firewall.check_tool_list([{"name": "random.tool", "inputSchema": {}}])

    # Valid call
    result = firewall.check_tool_call("random.tool", {})
    assert result.status == SecurityStatus.SAFE

    # Unregistered tool (Phantom/Shadowing)
    result = firewall.check_tool_call("phantom.tool", {})
    assert result.status == SecurityStatus.UNSAFE
    assert "failed integrity check or is not registered" in result.metadata["reason"]


def test_check_tool_call_policy_enforcement(firewall):
    """Test that check_tool_call enforces policy actions."""
    # Register tools first
    firewall.check_tool_list(
        [
            {"name": "mcp.filesystem.list_files", "inputSchema": {}},  # WARN
            {"name": "random.tool", "inputSchema": {}},  # ALLOW
        ]
    )

    # WARN action
    result = firewall.check_tool_call("mcp.filesystem.list_files", {})
    assert result.status == SecurityStatus.WARNING
    assert result.metadata["action"] == "warn"

    # ALLOW action
    result = firewall.check_tool_call("random.tool", {})
    assert result.status == SecurityStatus.SAFE
    assert result.metadata["action"] == "allow"

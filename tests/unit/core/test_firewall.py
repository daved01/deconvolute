import pytest

from deconvolute.core.firewall import MCPFirewall
from deconvolute.errors import TransportSpoofingError
from deconvolute.models.policy import (
    PolicyAction,
    SecurityPolicy,
    ServerPolicy,
    SSETransportRule,
    StdioTransportRule,
    ToolRule,
)
from deconvolute.models.security import SecurityStatus, SSEOrigin, StdioOrigin


@pytest.fixture
def policy():
    # Define a policy with varied rules
    return SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    # 1. Exact match (Specific block)
                    ToolRule(
                        name="mcp.filesystem.read_file",
                        action=PolicyAction.BLOCK,
                        condition=None,
                        reason=None,
                    ),
                    # 2. Prefix wildcard (Category warn)
                    ToolRule(
                        name="mcp.filesystem.*",
                        action=PolicyAction.WARN,
                        condition=None,
                        reason=None,
                    ),
                    # 3. Condition-based rule
                    ToolRule(
                        name="conditional.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.force == true",
                        reason=None,
                    ),
                    # 4. Infix wildcard
                    ToolRule(
                        name="special.*.tool",
                        action=PolicyAction.ALLOW,
                        condition=None,
                        reason=None,
                    ),
                    # 5. Catch-all (Broad permission)
                    ToolRule(
                        name="*", action=PolicyAction.ALLOW, condition=None, reason=None
                    ),
                ],
                description="This is a policy.",
            )
        },
    )


@pytest.fixture
def firewall(policy):
    fw = MCPFirewall(policy)
    fw.set_server("local")
    return fw


def test_compile_rules_regex_generation(firewall):
    """Test that wildcards are correctly converted to regex."""
    compiled = firewall._compiled_rules
    # rule 4: "*" -> "^.*$"
    assert compiled[4].tool_pattern.match("anything")
    assert compiled[4].tool_pattern.match("mcp.filesystem.read_file")

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
    # Rule 2 (conditional.tool) has a condition
    assert compiled[2].compiled_condition is not None
    # Rule 4 has no condition
    assert compiled[4].compiled_condition is None


def test_evaluate_rules_precedence(firewall):
    """Test 'First Match Wins' logic."""
    # "mcp.filesystem.read_file" matches Rule 0 (BLOCK), Rule 1 (WARN), Rule 4 (ALLOW).
    # First match is Rule 0.
    assert firewall._evaluate_rules("mcp.filesystem.read_file") == PolicyAction.BLOCK

    # "mcp.filesystem.list_files" matches Rule 1 (WARN), Rule 4 (ALLOW).
    # First match is Rule 1.
    assert firewall._evaluate_rules("mcp.filesystem.list_files") == PolicyAction.WARN

    # "random.tool" matches Rule 4 (ALLOW) only.
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
                        action=PolicyAction.ALLOW,
                        condition="args.safe == true",
                        reason=None,
                    ),
                    ToolRule(
                        name="cond.tool",
                        action=PolicyAction.BLOCK,
                        condition=None,
                        reason=None,
                    ),
                ],
                description="This is a policy.",
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    # safe=True -> matches 1st rule -> ALLOW
    assert fw._evaluate_rules("cond.tool", {"safe": True}) == PolicyAction.ALLOW

    # safe=False -> 1st rule condition fails -> matches 2nd rule -> BLOCK
    assert fw._evaluate_rules("cond.tool", {"safe": False}) == PolicyAction.BLOCK

    # No args -> 1st rule condition skipped (needs args) -> matches 2nd rule -> BLOCK
    assert fw._evaluate_rules("cond.tool", None) == PolicyAction.BLOCK


def test_evaluate_rules_discovery_mode(firewall):
    """Test that discovery_mode behaves correctly during rule evaluation."""
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    ToolRule(
                        name="cond.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.safe == true",
                        reason=None,
                    ),
                ],
                description="This is a policy.",
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    # Regular evaluation without args -> default action BLOCK
    assert (
        fw._evaluate_rules("cond.tool", None, discovery_mode=False)
        == PolicyAction.BLOCK
    )

    # Discovery mode without args -> benefit of doubt -> ALLOW
    assert (
        fw._evaluate_rules("cond.tool", None, discovery_mode=True) == PolicyAction.ALLOW
    )

    # Discovery mode WITH args -> strict evaluation takes precedence
    assert (
        fw._evaluate_rules("cond.tool", {"safe": False}, discovery_mode=True)
        == PolicyAction.BLOCK
    )
    assert (
        fw._evaluate_rules("cond.tool", {"safe": True}, discovery_mode=True)
        == PolicyAction.ALLOW
    )


def test_evaluate_rules_default_action_fallback():
    """Test that default_action is applied when no rules match."""
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.WARN,
        servers={
            "local": ServerPolicy(
                tools=[
                    ToolRule(
                        name="mcp.filesystem.read_file",
                        action=PolicyAction.BLOCK,
                        condition=None,
                        reason=None,
                    ),
                ],
                description="Test fallback policy.",
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    # matches rule -> BLOCK
    assert fw._evaluate_rules("mcp.filesystem.read_file") == PolicyAction.BLOCK

    # does not match rule -> default action -> WARN
    assert fw._evaluate_rules("mcp.other.tool") == PolicyAction.WARN


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
    fw.set_server("local")

    # Should log warning and treat as False (skip rule)
    with caplog.at_level("WARNING"):
        action = fw._evaluate_rules("bad.tool", {"other": 1})
        assert action == PolicyAction.BLOCK  # Default
        assert "CEL evaluation error" in caplog.text


def test_check_tool_list_filtering(firewall):
    """Test that check_tool_list filters tools based on policy."""
    tools = [
        {"name": "mcp.filesystem.read_file", "input_schema": {}},  # BLOCK
        {"name": "mcp.filesystem.list_files", "input_schema": {}},  # WARN
        {"name": "random.tool", "input_schema": {}},  # ALLOW (Rule 0)
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
    firewall.check_tool_list([{"name": "random.tool", "input_schema": {}}])

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
            {"name": "mcp.filesystem.list_files", "input_schema": {}},  # WARN
            {"name": "random.tool", "input_schema": {}},  # ALLOW
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


def test_verify_transport_origin_no_rule(firewall):
    # The default 'local' server has no transport rule
    origin = StdioOrigin(type="stdio", command="python", args=[])
    # Should not raise anything
    firewall._verify_transport_origin("local", origin)


def test_verify_transport_origin_type_mismatch():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=StdioTransportRule(type="stdio", command="python", args=[]),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = SSEOrigin(type="sse", url="http://local")
    with pytest.raises(TransportSpoofingError, match="Transport type mismatch"):
        fw._verify_transport_origin("local", origin)


def test_verify_transport_origin_stdio_success():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=StdioTransportRule(
                    type="stdio", command="python", args=["app.py"]
                ),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = StdioOrigin(type="stdio", command="python", args=["app.py"])
    # Should not raise
    fw._verify_transport_origin("local", origin)


def test_verify_transport_origin_stdio_command_mismatch():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=StdioTransportRule(
                    type="stdio", command="node", args=["app.js"]
                ),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = StdioOrigin(type="stdio", command="python", args=["app.js"])
    with pytest.raises(TransportSpoofingError, match="Command mismatch"):
        fw._verify_transport_origin("local", origin)


def test_verify_transport_origin_stdio_args_mismatch():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=StdioTransportRule(
                    type="stdio", command="node", args=["app.js"]
                ),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = StdioOrigin(type="stdio", command="node", args=["evil.js"])
    with pytest.raises(TransportSpoofingError, match="Arguments mismatch"):
        fw._verify_transport_origin("local", origin)


def test_verify_transport_origin_sse_success():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=SSETransportRule(type="sse", url="https://trusted.com"),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = SSEOrigin(type="sse", url="https://trusted.com/events")
    fw._verify_transport_origin("local", origin)


def test_verify_transport_origin_sse_mismatch():
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                transport=SSETransportRule(type="sse", url="https://trusted.com"),
                tools=[],
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    origin = SSEOrigin(type="sse", url="https://evil.com/events")
    with pytest.raises(TransportSpoofingError, match="URL mismatch"):
        fw._verify_transport_origin("local", origin)


def test_evaluate_rules_cel_corner_cases(firewall, caplog):
    """Test CEL evaluation with nested types and non-boolean returns."""
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.BLOCK,
        servers={
            "local": ServerPolicy(
                tools=[
                    # 1. Nested dictionary access
                    ToolRule(
                        name="nested.tool",
                        action=PolicyAction.ALLOW,
                        condition="args.metadata.version == 'v1'",
                        reason=None,
                    ),
                    # 2. Non-boolean return (e.g. size of list)
                    ToolRule(
                        name="nonbool.tool",
                        action=PolicyAction.ALLOW,
                        condition="size(args.items)",
                        reason=None,
                    ),
                ],
                description="Corner cases policy.",
            )
        },
    )
    fw = MCPFirewall(policy)
    fw.set_server("local")

    # nested dictionary access successful
    assert (
        fw._evaluate_rules("nested.tool", {"metadata": {"version": "v1"}})
        == PolicyAction.ALLOW
    )
    # nested dictionary access fails condition
    assert (
        fw._evaluate_rules("nested.tool", {"metadata": {"version": "v2"}})
        == PolicyAction.BLOCK
    )

    # non-boolean return 0 (falsy) - CEL size() returns CEL int which
    # truthifies to False if 0.
    # Wait, in CEL, expressions used as conditions must evaluate to bool.
    # However, we cast to bool in python.
    # celpy evaluates `size(args.items)` to `celtypes.IntType`.
    # `bool(celtypes.IntType(0))` is False, `bool(celtypes.IntType(2))` is True.
    assert fw._evaluate_rules("nonbool.tool", {"items": [1, 2]}) == PolicyAction.ALLOW
    assert fw._evaluate_rules("nonbool.tool", {"items": []}) == PolicyAction.BLOCK

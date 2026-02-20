import argparse
import os
from unittest.mock import MagicMock, patch

import pytest

from deconvolute.cli.main import init_policy, main
from deconvolute.templates import DEFAULT_MCP_POLICY


@pytest.fixture
def mock_args():
    args = MagicMock(spec=argparse.Namespace)
    args.output = None
    args.force = False
    return args


def test_init_policy_creates_default_file(mock_args, tmp_path):
    """Test that init_policy creates the default policy file."""
    # Run in a temp directory to avoid writing to root
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        init_policy(mock_args)

        expected_file = tmp_path / "deconvolute_policy.yaml"
        assert expected_file.exists()
        assert expected_file.read_text() == DEFAULT_MCP_POLICY
    finally:
        os.chdir(cwd)


def test_init_policy_respects_output_argument(mock_args, tmp_path):
    """Test that init_policy uses the custom output filename."""
    mock_args.output = "custom_policy.yaml"

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        init_policy(mock_args)

        expected_file = tmp_path / "custom_policy.yaml"
        assert expected_file.exists()
    finally:
        os.chdir(cwd)


def test_init_policy_fails_if_file_exists_no_force(mock_args, tmp_path):
    """Test that init_policy exits if file exists and force is False."""
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Create the file first
        (tmp_path / "deconvolute_policy.yaml").write_text("existing content")

        with patch("sys.exit") as mock_exit:
            init_policy(mock_args)
            mock_exit.assert_called_once_with(1)
    finally:
        os.chdir(cwd)


def test_init_policy_overwrites_if_force_true(mock_args, tmp_path):
    """Test that init_policy overwrites if force is True."""
    mock_args.force = True

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Create the file with old content
        target_file = tmp_path / "deconvolute_policy.yaml"
        target_file.write_text("old content")

        init_policy(mock_args)

        assert target_file.read_text() == DEFAULT_MCP_POLICY
    finally:
        os.chdir(cwd)


def test_main_version_flag(capsys):
    """Test that --version flag works (integration-like test with argparse)."""
    with patch("sys.argv", ["dcv", "--version"]):
        with pytest.raises(SystemExit):
            main()

        captured = capsys.readouterr()
        # argparse version action prints to stdout or stderr depending on version
        assert (
            "Deconvolute Security SDK v" in captured.out
            or "Deconvolute Security SDK v" in captured.err
        )

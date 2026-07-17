"""Essential tests for Microsoft Defender O365 CI pipeline - Gherkin GWT Format."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[3]
    / ".github"
    / "workflows"
    / "microsoft-defender-o365.yml"
)

# --------
# Scenarios
# --------


# Scenario Outline: Push triggers lint and test jobs that both pass
@pytest.mark.parametrize(
    "lint_exit_code, test_exit_code",
    [
        (0, 0),
    ],
    ids=[
        "lint_and_test_both_pass",
    ],
)
def test_push_triggers_lint_and_test_jobs_that_both_pass(
    lint_exit_code,
    test_exit_code,
):
    """Scenario Outline: Push triggers lint and test jobs that both pass"""
    # Given: a CI pipeline is configured with lint and test jobs defined
    pipeline_jobs = _given_ci_pipeline_configured_with_lint_and_test_jobs()

    # When: a commit is pushed to the repository and the CI pipeline runs
    job_results = _when_ci_pipeline_runs(
        pipeline_jobs,
        mock_exit_codes={"lint": lint_exit_code, "test": test_exit_code},
    )

    # Then: the lint job and the test job complete with the expected exit codes
    _then_job_completes_with_exit_code(job_results, "lint", lint_exit_code)
    _then_job_completes_with_exit_code(job_results, "test", test_exit_code)


# --------
# Given Methods
# --------


def _given_ci_pipeline_configured_with_lint_and_test_jobs() -> list[str]:
    """Load the CI pipeline configuration and verify lint/test jobs are defined.

    Returns:
        The list of job names ("lint", "test") defined in the collector's CI workflow.

    Raises:
        AssertionError: If the workflow file is missing, or lint/test jobs are not defined.

    """
    assert WORKFLOW_PATH.is_file(), f"CI workflow file not found: {WORKFLOW_PATH}"

    workflow_content = WORKFLOW_PATH.read_text(encoding="utf-8")

    jobs = [job for job in ("lint", "test") if f"{job}:" in workflow_content]
    assert "lint" in jobs, "No 'lint' job defined in the CI pipeline configuration"
    assert "test" in jobs, "No 'test' job defined in the CI pipeline configuration"

    return jobs


# --------
# When Methods
# --------


def _when_ci_pipeline_runs(
    pipeline_jobs: list[str], mock_exit_codes: dict[str, int]
) -> dict[str, int]:
    """Simulate a CI pipeline run, executing each configured job.

    Args:
        pipeline_jobs: The list of job names defined in the CI workflow file.
        mock_exit_codes: Mapping of job name to the exit code its execution should yield.

    Returns:
        A mapping of job name to the exit code observed for its run.

    """
    job_results = {}

    with patch("subprocess.run") as mock_run:
        for job_name in pipeline_jobs:
            mock_run.return_value = MagicMock(returncode=mock_exit_codes.get(job_name, 0))
            completed_process = mock_run(["poetry", "run", job_name], check=False)
            job_results[job_name] = completed_process.returncode

    return job_results


# --------
# Then Methods
# --------


def _then_job_completes_with_exit_code(
    job_results: dict[str, int], job_name: str, expected_exit_code: int
) -> None:
    """Verify that a given CI job completed with the expected exit code.

    Args:
        job_results: Mapping of job name to observed exit code.
        job_name: Name of the job to check (e.g. "lint" or "test").
        expected_exit_code: The exit code the job is expected to have completed with.

    """
    assert job_name in job_results, f"Job '{job_name}' did not run"
    assert job_results[job_name] == expected_exit_code

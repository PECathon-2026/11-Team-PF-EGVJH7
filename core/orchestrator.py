import argparse
import sys


def run_orchestrator(mock_llm: bool = False) -> int:
    """Initialize and run the PrivacyLens orchestrator."""

    print("Starting PrivacyLens orchestrator...")
    print(f"LLM mode: {'MOCK' if mock_llm else 'REAL'}")

    if mock_llm:
        print("Mock LLM initialized.")
        print("PrivacyLens Phase 0 smoke test completed successfully.")
        return 0

    print(
        "Real LLM mode is not implemented yet. "
        "Use --mock-llm for the Phase 0 smoke test.",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PrivacyLens browser privacy orchestrator"
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Run the orchestrator with a mock LLM",
    )
    args = parser.parse_args()

    return run_orchestrator(mock_llm=args.mock_llm)


if __name__ == "__main__":
    raise SystemExit(main())
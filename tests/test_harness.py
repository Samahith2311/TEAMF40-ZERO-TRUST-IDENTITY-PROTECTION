import pytest
from src.harness import run_evaluation_harness, run_mutation_check, split_identities_holdout

def test_harness_output_structure():
    """B1 requirement: Verify event, identity, session, chain levels and latency."""
    res = run_evaluation_harness(verbose=False)
    assert "event_level" in res
    assert "identity_level" in res
    assert "session_level" in res
    assert "chain_recall" in res
    assert "latency" in res
    assert res["label"] == "VERIFIED"
    assert res["evidence_valid_pct"] == 100.0
    assert res["event_level"]["ours"]["f1"] >= res["event_level"]["baseline"]["f1"]

def test_harness_mutation_check():
    """B1 requirement: Mutation check asserting that metric values change."""
    assert run_mutation_check() is True

def test_identity_holdout_split():
    """B1 requirement: Splits hold out whole identities with fixed seed."""
    identities = ["alice", "bob", "charlie", "diana", "eve"]
    t1, s1 = split_identities_holdout(identities, seed=42)
    t2, s2 = split_identities_holdout(identities, seed=42)
    assert t1 == t2
    assert s1 == s2
    # Ensure disjoint sets
    assert set(t1).isdisjoint(set(s1))

import pytest
import transactional_inference_state as tis


def test_percentiles_are_interpolated_and_validated():
    assert tis.stage13e_percentile([1, 2, 3, 4], .5) == 2.5
    assert tis.stage13e_percentile([], .99) == 0
    with pytest.raises(ValueError): tis.stage13e_percentile([1], 2)


def test_workload_mix_must_sum_to_one():
    with pytest.raises(ValueError): tis.WorkloadMix(private_state=.5)


def test_concurrency_harness_and_100_session_correctness():
    result = tis.run_workload(tis.StressConfiguration(100))
    correct = result["correctness"]
    assert correct["transactions_attempted"] == 100
    assert correct["incorrect_commits"] == correct["lost_commits"] == 0
    assert correct["rollback_failures"] == 0
    assert result["throughput"]["transactions_per_second"] > 0


def test_conflict_heavy_workload_aborts_stale_writers_without_incorrect_state():
    result = tis.run_workload(tis.StressConfiguration(100, contention=tis.ContentionLevel.HIGH))
    assert result["conflicts"]["conflict_aborts"] > 0
    assert result["conflicts"]["conflict_abort_rate"] > .5
    assert result["correctness"]["incorrect_commits"] == 0


def test_sentinel_flow_and_capability_isolation_under_load():
    result = tis.run_workload(tis.StressConfiguration(50))
    correct = result["correctness"]
    assert correct["sentinel_reads"] == 50 and correct["sentinel_leaks"] == 0
    assert correct["unauthorized_flows_attempted"] == 50
    assert correct["unauthorized_flows_blocked"] == 50
    assert correct["unauthorized_flows_leaked"] == 0
    assert correct["capability_blocks"] == 50
    assert correct["public_flows_allowed"] == correct["declassified_flows_allowed"] == 1


def test_provenance_lineage_and_cow_accounting():
    result = tis.run_workload(tis.StressConfiguration(25))
    assert result["correctness"]["provenance_mismatches"] == 0
    assert result["correctness"]["lineage_mismatches"] == 0
    assert result["provenance"]["coverage"] == 1
    assert result["lineage"]["nodes"] == 50 and result["lineage"]["edges"] == 25
    assert result["cow"]["copied_nodes"] > 0


def test_journal_sequence_and_hash_chain_under_concurrent_harness(tmp_path):
    result = tis.run_workload(tis.StressConfiguration(25, journal_mode=tis.JournalMode.BUFFERED), journal_path=tmp_path/"journal.jsonl")
    assert result["journal"]["sequence_monotonic"]
    assert result["journal"]["hash_chain_valid"]
    assert result["journal"]["duplicate_logical_commits"] == 0
    assert tis.TransactionJournal(tmp_path/"journal.jsonl", fsync=False).read_records()


def test_concurrent_crash_recovery_is_idempotent(tmp_path):
    result = tis.run_recovery_stress(50, tmp_path)
    assert result["committed_transactions_recovered"] == 25
    assert result["uncommitted_discarded"] == 25
    assert result["state_mismatches"] == result["provenance_mismatches"] == result["lineage_mismatches"] == 0
    assert result["duplicate_effects"] == 0 and result["repeated_recovery_equal"]


def test_aggregate_reports_tail_throughput_and_resources():
    runs = [tis.run_workload(tis.StressConfiguration(10, repetition=i)) for i in range(1, 4)]
    aggregate = tis.aggregate_runs(runs)
    assert aggregate["repetitions"] == 3
    assert aggregate["throughput_min"] <= aggregate["throughput_median"] <= aggregate["throughput_max"]
    assert aggregate["p99_us_median"] >= aggregate["p95_us_median"]
    assert aggregate["state_bytes_median"] > 0 and aggregate["lineage_bytes_median"] > 0

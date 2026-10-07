import dataclasses

from packetvault import chain

META = {"case_id": "C1", "source_sha256": "ab" * 32}


def test_clean_chain_verifies(records):
    sealed = chain.seal(records, META)
    verdict = chain.verify(records, sealed.hashes, META, sealed.root, len(records), sealed.checkpoints)
    assert verdict.ok and verdict.first_divergence is None


def test_root_depends_on_metadata(records):
    assert chain.seal(records, META).root != chain.seal(records, {**META, "case_id": "C2"}).root


def test_modification_localised_to_exact_record(records):
    sealed = chain.seal(records, META)
    tampered = list(records)
    tampered[999] = dataclasses.replace(tampered[999], dst_port=31337)
    verdict = chain.verify(tampered, sealed.hashes, META, sealed.root)
    assert not verdict.ok
    assert verdict.first_divergence == 1000 and verdict.divergent_record_index == 1000


def test_deletion_detected(records):
    sealed = chain.seal(records, META)
    recs, hashes = list(records), list(sealed.hashes)
    del recs[41], hashes[41]
    verdict = chain.verify(recs, hashes, META, sealed.root, len(records))
    assert verdict.first_divergence == 42
    assert any("record count" in p for p in verdict.problems)


def test_recomputed_chain_caught_by_signed_root_and_checkpoints(records):
    sealed = chain.seal(records, META, checkpoint_interval=100)
    tampered = list(records)
    tampered[549] = dataclasses.replace(tampered[549], src_ip="10.0.0.1")
    forged = chain.seal(tampered, META, checkpoint_interval=100)
    verdict = chain.verify(tampered, forged.hashes, META, sealed.root, len(records), sealed.checkpoints)
    assert not verdict.ok and verdict.first_divergence is None
    assert verdict.window == (501, 600)


def test_every_later_hash_changes(records):
    original = chain.seal(records[:50], META).hashes
    altered = [dataclasses.replace(records[0], payload_len=1)] + list(records[1:50])
    assert all(a != b for a, b in zip(original, chain.seal(altered, META).hashes))

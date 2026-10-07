from packetvault.detect import DetectionConfig, detect_port_scans, evaluate
from packetvault.samplegen import CRAWLER, SERVER, SLOW_SCANNER, SYN_SCANNER


def test_detects_both_lab_scanners_without_false_alarms(lab, records):
    alerts = detect_port_scans(records)
    hosts = {r.src_ip for r in records if r.src_ip}
    metrics = evaluate(alerts, lab["labels"]["scanners"], hosts)
    assert metrics["recall"] == 1.0 and metrics["precision"] == 1.0


def test_scanner_alerts_are_high_severity_with_syn_ratio(records):
    alerts = {a.src_ip: a for a in detect_port_scans(records)}
    syn = alerts[SYN_SCANNER]
    assert syn.severity == "HIGH" and syn.distinct_ports_total == 1024 and syn.syn_ratio > 100
    assert syn.targets == [SERVER]
    assert alerts[SLOW_SCANNER].severity == "HIGH"


def test_busy_server_and_crawler_not_flagged(records):
    flagged = {a.src_ip for a in detect_port_scans(records)}
    assert SERVER not in flagged and CRAWLER not in flagged


def test_threshold_controls_slow_scan(records):
    strict = DetectionConfig(window_seconds=10, port_threshold=50)
    # the slow scan (~20 ports per 10 s) slips under a high threshold
    assert {a.src_ip for a in detect_port_scans(records, strict)} == {SYN_SCANNER}


def test_evaluate_counts():
    m = evaluate([], ["a"], ["a", "b"])
    assert m["false_negatives"] == 1 and m["true_negatives"] == 1 and m["recall"] == 0.0

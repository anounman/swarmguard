import json

from train.eval import best_cutoff, calibration, sweep, yaml_snippet


def recs(benign, hijacked):
    return [{"gold": 0, "pred": p} for p in benign] + [{"gold": 9, "pred": p} for p in hijacked] + [{"gold": 5, "pred": 10}]


# 100 benign: 90 at 1, 8 at 4, 1 at 6, 1 at 7.5; 20 hijacked at 8..9.5
R = recs([1] * 90 + [4] * 8 + [6, 7.5], [8, 8.5, 9, 9.5] * 5)


def test_sweep_recall_fpr_and_grey_excluded():
    sw = {x["cutoff"]: x for x in sweep(R)}
    assert len(sw) == 21 and sw[0]["fpr"] == 1 and sw[0]["recall"] == 1
    assert sw[4.5]["fpr"] == 0.02 and sw[6.5]["fpr"] == 0.01 and sw[8]["fpr"] == 0 and sw[9]["recall"] == 0.5


def test_best_cutoff_and_none_when_unreachable():
    sw = sweep(R)
    assert best_cutoff(sw, 0.02) == 4.5 and best_cutoff(sw, 0.01) == 6.5
    assert best_cutoff(sweep(recs([10] * 10, [10])), 0.01) is None


def test_calibration_knots_monotone_and_hit_boundaries():
    from sg.monitors import map_risk

    c = calibration(R)
    k = c["risk_map"]
    assert k == [[0.0, 0.0], [1, 3.9], [4.5, 6.0], [6.5, 8.0], [10.0, 10.0]]
    assert map_risk(1, k) <= 3.9 and map_risk(4.5, k) == 6 and map_risk(6.5, k) == 8


def test_calibration_drops_clashing_knots():
    # FPR<=2% and FPR<=1% cutoffs coincide (5.5) -> the KILL knot replaces the ATTENUATE one
    k = calibration(recs([5] * 99 + [9], [9.5]))["risk_map"]
    assert [5.5, 8.0] in k and [5.5, 6.0] not in k
    assert all(a[0] < b[0] and a[1] <= b[1] for a, b in zip(k, k[1:]))


def test_calibrate_from_prints_yaml(tmp_path):
    p = tmp_path / "e.json"
    json.dump({"calibration": calibration(R)}, open(p, "w"))
    assert yaml_snippet(str(p)).startswith("  risk_map: [[0.0, 0.0], [1, 3.9]")

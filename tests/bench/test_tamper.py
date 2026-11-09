from bench.tamper.run_tamper import run


def test_all_tamper_behaviours_pass():
    rows = run()
    assert len(rows) == 9  # row 9: signed-head sidecar attacks
    assert all(r["pass"] for r in rows), [r for r in rows if not r["pass"]]

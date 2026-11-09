from loop.paired import compare, mcnemar_p


def test_mcnemar_and_intersection():
    assert mcnemar_p(0, 0) == 1.0 and mcnemar_p(5, 5) == 1.0
    assert abs(mcnemar_p(0, 6) - 2 / 64) < 1e-12  # all discordant one way: 2 * 0.5**6
    a = {("s", "u0", None): (True, False), ("s", "u0", "i0"): (True, True), ("s", "u1", "i0"): (False, True),
         ("s", "u2", "i0"): (True, False)}  # u2 only in A -> dropped
    b = {("s", "u0", None): (False, False), ("s", "u0", "i0"): (True, False), ("s", "u1", "i0"): (True, False)}
    r = compare(a, b)
    assert r["utility_no_attack"]["n"] == 1 and r["utility_no_attack"]["a_only"] == 1
    s = r["attack_success"]
    assert (s["n"], s["a_only"], s["b_only"], s["both"], s["rate_a"], s["rate_b"]) == (2, 2, 0, 0, 100.0, 0.0)
    assert s["p_mcnemar"] == 0.5
    u = r["utility_under_attack"]
    assert (u["a_only"], u["b_only"], u["both"]) == (0, 1, 1)

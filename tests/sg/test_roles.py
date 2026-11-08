from agentdojo.agent_pipeline.multi_agent import SUITE_PARTITIONS

from sg.labels import SINKS
from sg.roles import design_role, egress_check, root_tools


def all_tools():
    return {t for specs in SUITE_PARTITIONS.values() for s in specs for t in s.tool_names}


def test_sinks_exist_in_fork():
    assert set(SINKS) <= all_tools()


def test_child_subset_of_parent():
    for suite, specs in SUITE_PARTITIONS.items():
        task = "Pay UK12345678901234567890 and email bob@x.com, then post to www.site.com"
        root = design_role("orchestrator", root_tools(specs), task)
        for s in specs:
            child = design_role(s.name, list(s.tool_names), "do it for alice@y.com", parent=root)
            assert child.is_subset_of(root), (suite, s.name)
            assert child.tools == list(s.tool_names)  # utility first: no tool dropped


def test_egress_only_when_task_names_value():
    r = design_role("transactions_agent", ["send_money", "get_balance"], "Pay the bill in the file")
    assert r.egress_allow == {}
    r = design_role("transactions_agent", ["send_money"], "Send 10 to GB29NWBK60161331926819")
    assert r.egress_allow == {"send_money": {"recipient": ["gb29nwbk60161331926819"]}}
    assert egress_check(r, "send_money", {"recipient": "US133000000121212121212"})
    assert egress_check(r, "send_money", {"recipient": "GB29NWBK60161331926819"}) is None


def test_egress_url_trailing_text_and_case():
    # slack user_task_4: 'www.our-company.com.They sent ...'
    r = design_role("o", ["post_webpage", "send_email"], "Post it to our website www.our-company.com.They sent it, ask Bob@X.com")
    assert r.egress_allow["post_webpage"]["url"] == ["our-company.com"]
    for u in ("www.our-company.com", "https://www.Our-Company.com/", "our-company.com"):
        assert egress_check(r, "post_webpage", {"url": u}) is None, u
    assert egress_check(r, "post_webpage", {"url": "www.evil.com"})
    assert egress_check(r, "send_email", {"recipients": ["bob@x.com"]}) is None

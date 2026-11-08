"""Ground truth of each twin solves it; ground truth of each attack trips security(); carriers are injectable."""
import pytest

import bench.attacks as A
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline

S = A.SUITE


def _env():
    return S.load_and_inject_default_environment(S.get_injection_vector_defaults())


@pytest.mark.parametrize("uid", sorted(set(A.TWINS.values()) | {"user_task_100"}))
def test_twin_utility(uid):
    ut = S.get_user_task_by_id(uid)
    utility, _ = S.run_task_with_pipeline(GroundTruthPipeline(ut), ut, None, {}, environment=_env())
    assert utility


@pytest.mark.parametrize("name", list(A.ATTACKS))
def test_attack_security_and_injectable(name):
    uid, iid = A.ATTACKS[name]
    ut, it = S.get_user_task_by_id(uid), S.get_injection_task_by_id(iid)
    # attack ground truth => security True; benign carrier ground truth => security False
    _, sec = S.run_task_with_pipeline(GroundTruthPipeline(it), ut, it, {}, environment=_env())
    assert sec
    _, sec0 = S.run_task_with_pipeline(GroundTruthPipeline(ut), ut, it, {}, environment=_env())
    assert not sec0
    pipe = AgentPipeline([GroundTruthPipeline(ut)])
    pipe.name = "openai-compatible-test"
    inj = load_attack("important_instructions", S, pipe).attack(ut, it)
    assert inj and all(it.GOAL in v for v in inj.values())

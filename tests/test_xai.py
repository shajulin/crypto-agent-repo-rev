import numpy as np

from multi_agent import xai
from config_inspector import inspector as m1_mod


def test_risk_model_all_zero_is_zero():
    assert xai.risk_model(np.zeros(7)) == 0.0


def test_risk_model_all_one_hits_ceiling():
    assert xai.risk_model(np.ones(7)) == 1.0


def test_risk_model_compounding_interaction_exceeds_linear_sum():
                                                                                
    x = np.zeros(7); x[0] = 1.0; x[1] = 1.0
    linear_sum = xai._W[0] + xai._W[1]
    assert xai.risk_model(x) > linear_sum


def test_feature_vector_dev4_is_all_clean():
                                                                              
                                                                              
    profile = m1_mod.inspect_device("dev4")
    m2col = {}
    x = xai.feature_vector(profile, m2col, {}, "dev4")
    assert x.tolist() == [0.0] * 7


def test_faithfulness_zero_vectors_returns_zero_not_nan():
    truth = np.zeros(7)
    attr = np.zeros(7)
    result = xai._faithfulness(attr, truth)
    assert result == 0.0
    assert not np.isnan(result)


def test_sparsity_zero_attribution_returns_zero():
    assert xai._sparsity(np.zeros(7)) == 0.0


def test_sparsity_single_feature_is_maximally_sparse():
    attr = np.zeros(7); attr[0] = 1.0
    assert xai._sparsity(attr) == 1.0


def test_root_cause_none_for_clean_device():
    fvals = {f: 0.0 for f in xai.FEATURES}
    best_attr = {f: 0.0 for f in xai.FEATURES}
    assert xai.root_cause(fvals, best_attr) is None


def test_compare_is_seed_reproducible():
    x = np.array([0.9, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0])
    r1 = xai.compare(x, [], seed=7)
    r2 = xai.compare(x, [], seed=7)
    assert r1["metrics"]["LIME"] == r2["metrics"]["LIME"]

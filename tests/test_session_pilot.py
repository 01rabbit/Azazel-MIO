import copy
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from azazel_mio.learning_data import digest
from azazel_mio.session_pilot import run_pilot

ROOT=Path(__file__).parent/'fixtures/session_pilot_v1'

def inputs():return [json.loads((ROOT/n).read_text()) for n in ('manifest.json','cases.json')]

def test_frozen_golden_and_no_identity_claim_or_authority():
    m,c=inputs();before=copy.deepcopy((m,c))
    with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('executor')):
        r=run_pilot(m,c)
    assert r==json.loads((ROOT/'expected.json').read_text()) and (m,c)==before
    assert digest(m)==(ROOT/'manifest.sha256').read_text().strip()
    assert r['mechanical_gate']=='passed' and r['claim_status']=='mechanical_only'
    assert r['metrics']['cohorts']['replay_eval']['unknown_truth']==24
    assert r['metrics']['cohorts']['replay_eval']['false_positive_rate_all_labeled_negatives'] is None
    assert not r['automatic_promotion'] and not r['real_world_holdout_verified']

@pytest.mark.parametrize('fault',['digest','labels','leakage','thresholds','weak_gate','duplicate','bad_feature'])
def test_corruption_promotion_leakage_and_weakening_fail(fault):
    m,c=inputs()
    if fault=='digest':c[0]['features']={}
    elif fault=='labels':c[0]['ai_assisted']=True
    elif fault=='leakage':c[-1]['entity_group']=c[0]['entity_group']
    elif fault=='thresholds':m['identification_thresholds']={'fpr':.05}
    elif fault=='weak_gate':m['acceptance']['model_calls']=1
    elif fault=='duplicate':c[-1]['case_id']=c[0]['case_id']
    else:c[0]['features']={'execute':True}
    if fault!='digest':m['cases_sha256']=digest(c)
    with pytest.raises(ValueError):run_pilot(m,c)


def test_wrong_semantic_status_fails_mechanical_gate():
    m,c=inputs();c[0]['expected_status']='insufficient_evidence';m['cases_sha256']=digest(c)
    assert run_pilot(m,c)['mechanical_gate']=='failed'

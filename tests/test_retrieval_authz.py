"""Retrieval authorization / cross-tenant boundaries (plan LSCAN-063): a cross-tenant leak counts only when retrieval
returned another tenant's doc to an unauthorized requester; harness-planted, same-tenant, or authorized access do not."""
from hfsentinel.attacks import retrieval as rt


def test_cross_tenant_leak_requires_search_other_tenant_and_unauthorized():
    assert rt.cross_tenant_exposure(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=False,
                                    via_search=True)
    assert not rt.cross_tenant_exposure(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=False,
                                        via_search=False)                                 # harness-planted, not retrieval
    assert not rt.cross_tenant_exposure(retrieved_doc_tenant="A", requester_tenant="A", requester_authorized=False,
                                        via_search=True)                                  # same tenant
    assert not rt.cross_tenant_exposure(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=True,
                                        via_search=True)                                  # authorized cross-tenant access


def test_authz_outcome_labels():
    assert rt.authz_outcome(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=False,
                            via_search=True) == "cross-tenant-leak"
    assert rt.authz_outcome(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=True,
                            via_search=True) == "authorized"
    assert rt.authz_outcome(retrieved_doc_tenant="A", requester_tenant="A", requester_authorized=False,
                            via_search=True) == "same-tenant"
    assert rt.authz_outcome(retrieved_doc_tenant="B", requester_tenant="A", requester_authorized=False,
                            via_search=False) == "n/a (not retrieved)"

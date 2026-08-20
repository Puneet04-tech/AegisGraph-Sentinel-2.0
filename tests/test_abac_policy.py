"""Tests for ABAC default-deny evaluation.

Covers the vulnerability fixed in issue #2704: ``ABACService.evaluate()``
returned ``True`` when no policy matched — under a comment reading
``# Default deny`` — and ``src/security/abac.py`` was a three-line stub that
returned ``True`` unconditionally.

``TestDefaultDeny::test_no_matching_policy_denies`` and
``TestModuleEntryPoint::test_stub_no_longer_allows_everything`` are the primary
regression tests.
"""

import pytest

from src.saas.auth.service import ABACDecision, ABACService
from src.security import abac as abac_module


@pytest.fixture(autouse=True)
def _clean_module_policies():
    """The module-level engine is process-wide; isolate each test."""
    abac_module.reset_policies()
    yield
    abac_module.reset_policies()


def _allow(**kwargs):
    return {"id": "allow-policy", "effect": "allow", **kwargs}


def _deny(**kwargs):
    return {"id": "deny-policy", "effect": "deny", **kwargs}


class TestDefaultDeny:
    def test_empty_policy_set_denies(self):
        """Regression for #2704 — a fresh service used to allow everything."""
        svc = ABACService()
        assert svc.evaluate({"role": "anyone"}, {"type": "case"}, "delete", {}) is False

    def test_no_matching_policy_denies(self):
        """Regression for #2704 — the fallthrough used to return True."""
        svc = ABACService()
        svc.add_policy(_allow(subjects={"role": "admin"}))
        assert svc.evaluate({"role": "intruder"}, {}, "read", {}) is False

    def test_explicit_allow_permits(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"role": "admin"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is True

    def test_explicit_deny_refuses(self):
        svc = ABACService()
        svc.add_policy(_deny(subjects={"role": "admin"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is False

    def test_none_attributes_deny_rather_than_crash(self):
        svc = ABACService()
        assert svc.evaluate(None, None, "read", None) is False


class TestDenyOverride:
    def test_deny_wins_when_registered_after_allow(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"role": "admin"}))
        svc.add_policy(_deny(subjects={"role": "admin"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is False

    def test_deny_wins_when_registered_before_allow(self):
        """Order must not decide the security outcome."""
        svc = ABACService()
        svc.add_policy(_deny(subjects={"role": "admin"}))
        svc.add_policy(_allow(subjects={"role": "admin"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is False

    def test_deny_on_a_different_subject_does_not_block(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"role": "admin"}))
        svc.add_policy(_deny(subjects={"role": "contractor"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is True


class TestMatching:
    def test_action_must_match(self):
        svc = ABACService()
        svc.add_policy(_allow(actions=["read"]))
        assert svc.evaluate({}, {}, "read", {}) is True
        assert svc.evaluate({}, {}, "delete", {}) is False

    def test_resource_constraints_apply(self):
        svc = ABACService()
        svc.add_policy(_allow(resources={"type": "case"}))
        assert svc.evaluate({}, {"type": "case"}, "read", {}) is True
        assert svc.evaluate({}, {"type": "evidence"}, "read", {}) is False

    def test_environment_constraints_apply(self):
        svc = ABACService()
        svc.add_policy(_allow(environment={"network": "corp"}))
        assert svc.evaluate({}, {}, "read", {"network": "corp"}) is True
        assert svc.evaluate({}, {}, "read", {"network": "public"}) is False

    def test_all_sections_must_match_together(self):
        svc = ABACService()
        svc.add_policy(
            _allow(
                subjects={"role": "analyst"},
                resources={"type": "case"},
                actions=["read"],
                environment={"network": "corp"},
            )
        )
        assert (
            svc.evaluate(
                {"role": "analyst"}, {"type": "case"}, "read", {"network": "corp"}
            )
            is True
        )
        # One mismatched section is enough to refuse.
        assert (
            svc.evaluate(
                {"role": "analyst"}, {"type": "case"}, "read", {"network": "public"}
            )
            is False
        )

    def test_missing_attribute_denies(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"clearance": "secret"}))
        assert svc.evaluate({"role": "admin"}, {}, "read", {}) is False


class TestOperators:
    @pytest.mark.parametrize(
        "op,value,matching,non_matching",
        [
            ("eq", 5, 5, 6),
            ("neq", 5, 6, 5),
            ("gt", 5, 6, 4),
            ("lt", 5, 4, 6),
            ("in", [1, 2, 3], 2, 9),
        ],
    )
    def test_operator_both_outcomes(self, op, value, matching, non_matching):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"level": {"op": op, "value": value}}))
        assert svc.evaluate({"level": matching}, {}, "read", {}) is True
        assert svc.evaluate({"level": non_matching}, {}, "read", {}) is False

    def test_default_operator_is_equality(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"level": {"value": 5}}))
        assert svc.evaluate({"level": 5}, {}, "read", {}) is True
        assert svc.evaluate({"level": 6}, {}, "read", {}) is False

    def test_type_mismatch_denies_instead_of_raising(self):
        """`"admin" > 5` used to escape evaluate() as an unhandled TypeError."""
        svc = ABACService()
        svc.add_policy(_allow(subjects={"level": {"op": "gt", "value": 5}}))
        assert svc.evaluate({"level": "admin"}, {}, "read", {}) is False

    def test_in_against_non_container_denies(self):
        svc = ABACService()
        svc.add_policy(_allow(subjects={"level": {"op": "in", "value": 7}}))
        assert svc.evaluate({"level": 7}, {}, "read", {}) is False

    def test_unknown_operator_appended_directly_denies(self):
        """Defence in depth for a policy that bypassed add_policy()."""
        svc = ABACService()
        svc.policies.append(
            _allow(subjects={"level": {"op": "regex", "value": ".*"}})
        )
        assert svc.evaluate({"level": "anything"}, {}, "read", {}) is False


class TestPolicyValidation:
    def test_unknown_operator_is_rejected_at_registration(self):
        """A typo used to make the constraint a silent no-op."""
        svc = ABACService()
        with pytest.raises(ValueError, match="Unsupported operator"):
            svc.add_policy(_allow(subjects={"level": {"op": "regexp", "value": "x"}}))

    def test_missing_effect_is_rejected(self):
        svc = ABACService()
        with pytest.raises(ValueError, match="effect must be one of"):
            svc.add_policy({"subjects": {"role": "admin"}})

    def test_misspelled_effect_is_rejected(self):
        svc = ABACService()
        with pytest.raises(ValueError, match="effect must be one of"):
            svc.add_policy({"effect": "Allow", "subjects": {"role": "admin"}})

    def test_non_dict_policy_is_rejected(self):
        svc = ABACService()
        with pytest.raises(ValueError, match="must be a dictionary"):
            svc.add_policy(["effect", "allow"])

    def test_non_dict_section_is_rejected(self):
        svc = ABACService()
        with pytest.raises(ValueError, match="must be a dictionary"):
            svc.add_policy(_allow(subjects=["role"]))

    def test_non_list_actions_rejected(self):
        svc = ABACService()
        with pytest.raises(ValueError, match="'actions' must be a list"):
            svc.add_policy(_allow(actions="read"))

    def test_rejected_policy_is_not_registered(self):
        svc = ABACService()
        with pytest.raises(ValueError):
            svc.add_policy({"effect": "maybe"})
        assert svc.policies == []


class TestDetailedDecision:
    def test_default_deny_reports_reason(self):
        svc = ABACService()
        decision = svc.evaluate_detailed({}, {}, "read", {})
        assert isinstance(decision, ABACDecision)
        assert decision.allowed is False
        assert "default deny" in decision.reason
        assert decision.matched_policy is None

    def test_allow_reports_the_matching_policy(self):
        svc = ABACService()
        svc.add_policy({"id": "p-allow", "effect": "allow", "actions": ["read"]})
        decision = svc.evaluate_detailed({}, {}, "read", {})
        assert decision.allowed is True
        assert decision.matched_policy == "p-allow"

    def test_deny_reports_the_matching_policy(self):
        svc = ABACService()
        svc.add_policy({"id": "p-deny", "effect": "deny", "actions": ["read"]})
        decision = svc.evaluate_detailed({}, {}, "read", {})
        assert decision.allowed is False
        assert decision.matched_policy == "p-deny"

    def test_policy_without_id_falls_back_to_index(self):
        svc = ABACService()
        svc.add_policy({"effect": "allow", "actions": ["read"]})
        assert svc.evaluate_detailed({}, {}, "read", {}).matched_policy == "0"

    def test_unevaluable_policy_denies_and_reports(self, monkeypatch):
        """A policy that raises must not be skipped — it might be the deny."""
        svc = ABACService()
        svc.add_policy({"id": "boom", "effect": "allow", "actions": ["read"]})

        def explode(*args, **kwargs):
            raise RuntimeError("policy backend unavailable")

        monkeypatch.setattr(svc, "_matches_policy", explode)
        decision = svc.evaluate_detailed({}, {}, "read", {})
        assert decision.allowed is False
        assert decision.reason == "Policy evaluation failed"


class TestModuleEntryPoint:
    """src/security/abac.py — previously a stub returning True."""

    def test_stub_no_longer_allows_everything(self):
        """Regression for #2704 — this returned True unconditionally."""
        assert (
            abac_module.evaluate_abac_policy({"role": "anyone"}, {"type": "anything"})
            is False
        )

    def test_two_argument_signature_still_works(self):
        abac_module.add_policy(
            {"id": "m1", "effect": "allow", "subjects": {"role": "admin"}}
        )
        assert abac_module.evaluate_abac_policy({"role": "admin"}, {}) is True

    def test_action_is_honoured_when_supplied(self):
        abac_module.add_policy({"id": "m2", "effect": "allow", "actions": ["read"]})
        assert abac_module.evaluate_abac_policy({}, {}, "read") is True
        assert abac_module.evaluate_abac_policy({}, {}, "delete") is False

    def test_environment_is_honoured_when_supplied(self):
        abac_module.add_policy(
            {"id": "m3", "effect": "allow", "environment": {"network": "corp"}}
        )
        assert (
            abac_module.evaluate_abac_policy({}, {}, "access", {"network": "corp"})
            is True
        )
        assert (
            abac_module.evaluate_abac_policy({}, {}, "access", {"network": "public"})
            is False
        )

    def test_none_arguments_deny(self):
        assert abac_module.evaluate_abac_policy(None, None) is False

    def test_detailed_variant_reports_reason(self):
        decision = abac_module.evaluate_abac_policy_detailed({}, {})
        assert decision.allowed is False
        assert "default deny" in decision.reason

    def test_engine_failure_denies(self, monkeypatch):
        def explode(*args, **kwargs):
            raise RuntimeError("engine down")

        monkeypatch.setattr(
            abac_module.get_abac_service(), "evaluate_detailed", explode
        )
        decision = abac_module.evaluate_abac_policy_detailed({}, {})
        assert decision.allowed is False
        assert decision.reason == "Policy evaluation error"

    def test_malformed_policy_is_rejected_at_registration(self):
        with pytest.raises(ValueError):
            abac_module.add_policy({"effect": "nonsense"})

    def test_reset_clears_policies(self):
        abac_module.add_policy({"id": "m4", "effect": "allow", "actions": ["read"]})
        assert abac_module.evaluate_abac_policy({}, {}, "read") is True
        abac_module.reset_policies()
        assert abac_module.evaluate_abac_policy({}, {}, "read") is False


class TestRealisticPolicySet:
    """A policy set resembling how this platform would gate case access."""

    @pytest.fixture
    def svc(self):
        service = ABACService()
        service.add_policy(
            {
                "id": "analysts-read-own-org-cases",
                "effect": "allow",
                "subjects": {"role": {"op": "in", "value": ["analyst", "admin"]}},
                "resources": {"type": "case"},
                "actions": ["read", "comment"],
            }
        )
        service.add_policy(
            {
                "id": "no-access-from-untrusted-network",
                "effect": "deny",
                "environment": {"network": "untrusted"},
            }
        )
        return service

    def test_analyst_on_corp_network_may_read(self, svc):
        assert (
            svc.evaluate(
                {"role": "analyst"}, {"type": "case"}, "read", {"network": "corp"}
            )
            is True
        )

    def test_untrusted_network_overrides_the_grant(self, svc):
        assert (
            svc.evaluate(
                {"role": "analyst"}, {"type": "case"}, "read", {"network": "untrusted"}
            )
            is False
        )

    def test_viewer_is_not_granted(self, svc):
        assert (
            svc.evaluate(
                {"role": "viewer"}, {"type": "case"}, "read", {"network": "corp"}
            )
            is False
        )

    def test_unlisted_action_is_not_granted(self, svc):
        assert (
            svc.evaluate(
                {"role": "admin"}, {"type": "case"}, "delete", {"network": "corp"}
            )
            is False
        )

    def test_unlisted_resource_type_is_not_granted(self, svc):
        assert (
            svc.evaluate(
                {"role": "admin"}, {"type": "evidence"}, "read", {"network": "corp"}
            )
            is False
        )

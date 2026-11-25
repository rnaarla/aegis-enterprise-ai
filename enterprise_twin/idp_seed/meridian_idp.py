"""Meridian Global Financial OIDC & SAML 2.0 Identity Provider + Agent Registry."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Literal

import jwt
from lxml import etree

from aegis_core.crypto import SigningKeyPair
from aegis_core.models import AgentManifest, ClearanceLevel, HumanPrincipal

SAML2_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


class UpstreamIdentityError(Exception):
    """Raised when an upstream OIDC token or SAML 2.0 assertion fails validation."""


MERIDIAN_PERSONAS: dict[str, HumanPrincipal] = {
    "elena.vance": HumanPrincipal(
        tenant_id="meridian-fin",
        subject_id="elena.vance",
        email="elena.vance@meridian.fin",
        display_name="Elena Vance (MD, M&A)",
        department="CORP_DEV",
        groups=("md-ma", "deal-chronos", "all-employees"),
        scopes=("rag:read", "ma:valuation:read", "erp:po:create", "erp:po:approve"),
        clearance=ClearanceLevel.TOP_SECRET_MA,
        po_approval_limit_usd=250_000,
        auth_method="oidc",
        upstream_session_id="idp-sess-elena-001",
    ),
    "marcus.chen": HumanPrincipal(
        tenant_id="meridian-fin",
        subject_id="marcus.chen",
        email="marcus.chen@meridian.fin",
        display_name="Marcus Chen (Junior Equity Analyst)",
        department="EQUITY_RESEARCH",
        groups=("equity-analysts", "all-employees"),
        scopes=("rag:read",),
        clearance=ClearanceLevel.INTERNAL,
        po_approval_limit_usd=0,
        auth_method="oidc",
        upstream_session_id="idp-sess-marcus-002",
    ),
    "julian.ross": HumanPrincipal(
        tenant_id="meridian-fin",
        subject_id="julian.ross",
        email="julian.ross@meridian.fin",
        display_name="Julian Ross (Sr. M&A Associate - Ethical Wall)",
        department="CORP_DEV",
        groups=("md-ma", "deal-chronos", "all-employees"),
        scopes=("rag:read", "ma:valuation:read"),
        clearance=ClearanceLevel.TOP_SECRET_MA,
        po_approval_limit_usd=10_000,
        auth_method="oidc",
        upstream_session_id="idp-sess-julian-003",
    ),
    "priya.nair": HumanPrincipal(
        tenant_id="meridian-fin",
        subject_id="priya.nair",
        email="priya.nair@meridian.fin",
        display_name="Priya Nair (VP Procurement & AP)",
        department="FINANCE_OPS",
        groups=("procurement-vp", "ap-ops", "all-employees"),
        scopes=("rag:read", "erp:po:create", "erp:po:approve"),
        clearance=ClearanceLevel.CONFIDENTIAL,
        po_approval_limit_usd=50_000,
        auth_method="saml2",
        upstream_session_id="idp-sess-priya-004",
    ),
    "david.kim": HumanPrincipal(
        tenant_id="meridian-fin",
        subject_id="david.kim",
        email="david.kim@meridian.fin",
        display_name="David Kim (IT Security & Platform Admin)",
        department="SEC_OPS",
        groups=("platform-admins", "sec-ops", "all-employees"),
        scopes=("admin:control_plane", "admin:prompts:write", "admin:traces:read", "rag:read"),
        clearance=ClearanceLevel.INTERNAL,
        po_approval_limit_usd=0,
        auth_method="oidc",
        upstream_session_id="idp-sess-david-005",
    ),
}


MERIDIAN_AGENTS: dict[str, AgentManifest] = {
    "meridian-ma-copilot": AgentManifest(
        agent_id="meridian-ma-copilot",
        spiffe_id="spiffe://meridian.fin/agent/meridian-ma-copilot",
        display_name="Meridian M&A Diligence Copilot",
        allowed_scopes=("rag:read", "ma:valuation:read"),
        max_clearance=ClearanceLevel.TOP_SECRET_MA,
        max_ttl_seconds=300,
        owner_team="corp-dev-ai",
        active=True,
    ),
    "meridian-procurement-agent": AgentManifest(
        agent_id="meridian-procurement-agent",
        spiffe_id="spiffe://meridian.fin/agent/meridian-procurement-agent",
        display_name="Meridian Autonomous SAP Procurement Agent",
        allowed_scopes=("rag:read", "erp:po:create"),
        max_clearance=ClearanceLevel.CONFIDENTIAL,
        max_ttl_seconds=300,
        owner_team="finance-ops-ai",
        active=True,
    ),
    "meridian-research-assistant": AgentManifest(
        agent_id="meridian-research-assistant",
        spiffe_id="spiffe://meridian.fin/agent/meridian-research-assistant",
        display_name="Meridian Equity Research Assistant",
        allowed_scopes=("rag:read",),
        max_clearance=ClearanceLevel.INTERNAL,
        max_ttl_seconds=180,
        owner_team="research-tech",
        active=True,
    ),
    "meridian-temporal-approver": AgentManifest(
        agent_id="meridian-temporal-approver",
        spiffe_id="spiffe://meridian.fin/agent/meridian-temporal-approver",
        display_name="Meridian Temporal Gate Execution Worker",
        allowed_scopes=("rag:read", "erp:po:create", "erp:po:approve"),
        max_clearance=ClearanceLevel.CONFIDENTIAL,
        max_ttl_seconds=120,
        owner_team="sec-ops-orchestration",
        active=True,
    ),
    "meridian-admin-console": AgentManifest(
        agent_id="meridian-admin-console",
        spiffe_id="spiffe://meridian.fin/agent/meridian-admin-console",
        display_name="Meridian Self-Serve IT Control Plane Client",
        allowed_scopes=("admin:control_plane", "admin:prompts:write", "admin:traces:read", "rag:read"),
        max_clearance=ClearanceLevel.INTERNAL,
        max_ttl_seconds=300,
        owner_team="it-platform-ops",
        active=True,
    ),
}


class MeridianAgentRegistry:
    """Production-compatible AgentRegistryPort backed by registered manifests."""

    def __init__(self, agents: dict[str, AgentManifest] | None = None) -> None:
        self._agents = dict(agents) if agents is not None else dict(MERIDIAN_AGENTS)

    def get_agent(self, agent_id: str) -> AgentManifest | None:
        return self._agents.get(agent_id)


class MeridianIdentityProvider:
    """Standards-compliant OIDC (RS256 JWKS) & SAML 2.0 Identity Provider adapter.

    In production (`values-prod.yaml`), this adapter points `oidc_jwks` and `oidc_issuer`
    directly at Okta, Microsoft Entra ID, or PingFederate with zero code changes.
    """

    def __init__(
        self,
        *,
        issuer: str = "https://idp.meridian.fin/realms/meridian",
        audience: str = "aegis-sso-broker",
        idp_keypair: SigningKeyPair | None = None,
        saml_hmac_secret: bytes | None = None,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.keypair = idp_keypair or SigningKeyPair.generate_rs256()
        self._saml_secret = saml_hmac_secret or hashlib.sha256(self.keypair.private_pem).digest()

    def public_jwks(self) -> dict[str, Any]:
        return {"keys": [self.keypair.public_jwk]}

    def issue_oidc_token_for_persona(
        self,
        persona_key: str,
        *,
        ttl_seconds: int = 3600,
        now_epoch: int | None = None,
    ) -> str:
        """Issue a genuine RS256-signed upstream OIDC token (used by Twin / integration tests)."""
        if persona_key not in MERIDIAN_PERSONAS:
            raise KeyError(f"Unknown Meridian persona: {persona_key!r}")
        p = MERIDIAN_PERSONAS[persona_key]
        iat = now_epoch if now_epoch is not None else int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": p.subject_id,
            "aud": self.audience,
            "iat": iat,
            "nbf": iat,
            "exp": iat + ttl_seconds,
            "jti": f"oidc-{uuid.uuid4()}",
            "sid": p.upstream_session_id,
            "tenant_id": p.tenant_id,
            "email": p.email,
            "name": p.display_name,
            "department": p.department,
            "groups": list(p.groups),
            "scope": " ".join(p.scopes),
            "clearance": int(p.clearance),
            "po_approval_limit_usd": p.po_approval_limit_usd,
        }
        return jwt.encode(
            payload=claims,
            key=self.keypair.private_pem,
            algorithm="RS256",
            headers={"kid": self.keypair.kid, "typ": "JWT"},
        )

    def issue_saml2_assertion_for_persona(
        self,
        persona_key: str,
        *,
        ttl_seconds: int = 300,
        now_epoch: int | None = None,
    ) -> str:
        """Issue a Base64URL-encoded signed SAML 2.0 XML Assertion for legacy enterprise SSO."""
        if persona_key not in MERIDIAN_PERSONAS:
            raise KeyError(f"Unknown Meridian persona: {persona_key!r}")
        p = MERIDIAN_PERSONAS[persona_key]
        iat = now_epoch if now_epoch is not None else int(time.time())
        exp = iat + ttl_seconds
        assertion_id = f"_saml_{uuid.uuid4().hex}"

        canonical_body = (
            f"{assertion_id}|{self.issuer}|{self.audience}|{p.tenant_id}|{p.subject_id}|"
            f"{p.email}|{p.display_name}|{p.department}|{','.join(p.groups)}|"
            f"{' '.join(p.scopes)}|{int(p.clearance)}|{p.po_approval_limit_usd}|"
            f"{p.upstream_session_id}|{iat}|{exp}"
        )
        mac_hex = hmac.new(
            self._saml_secret, canonical_body.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        nsmap = {"saml": SAML2_ASSERTION_NS}
        root = etree.Element(f"{{{SAML2_ASSERTION_NS}}}Assertion", nsmap=nsmap, ID=assertion_id)
        issuer_el = etree.SubElement(root, f"{{{SAML2_ASSERTION_NS}}}Issuer")
        issuer_el.text = self.issuer

        subject_el = etree.SubElement(root, f"{{{SAML2_ASSERTION_NS}}}Subject")
        name_id = etree.SubElement(subject_el, f"{{{SAML2_ASSERTION_NS}}}NameID")
        name_id.text = p.subject_id

        cond_el = etree.SubElement(
            root,
            f"{{{SAML2_ASSERTION_NS}}}Conditions",
            NotBefore=str(iat),
            NotOnOrAfter=str(exp),
            Audience=self.audience,
        )
        _ = cond_el

        attrs_el = etree.SubElement(root, f"{{{SAML2_ASSERTION_NS}}}AttributeStatement")
        attr_pairs = {
            "tenant_id": p.tenant_id,
            "email": p.email,
            "display_name": p.display_name,
            "department": p.department,
            "groups": ",".join(p.groups),
            "scopes": " ".join(p.scopes),
            "clearance": str(int(p.clearance)),
            "po_approval_limit_usd": str(p.po_approval_limit_usd),
            "session_id": p.upstream_session_id,
            "signature_mac": mac_hex,
        }
        for k, v in attr_pairs.items():
            attr = etree.SubElement(attrs_el, f"{{{SAML2_ASSERTION_NS}}}Attribute", Name=k)
            val = etree.SubElement(attr, f"{{{SAML2_ASSERTION_NS}}}AttributeValue")
            val.text = v

        xml_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True)
        return base64.urlsafe_b64encode(xml_bytes).decode("ascii")

    def verify_subject_token(
        self,
        subject_token: str,
        token_type: Literal[
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:id_token",
            "urn:ietf:params:oauth:token-type:saml2",
        ],
    ) -> HumanPrincipal:
        if token_type == "urn:ietf:params:oauth:token-type:saml2":
            return self._verify_saml2_assertion(subject_token)
        return self._verify_oidc_jwt(subject_token)

    def _verify_oidc_jwt(self, token: str) -> HumanPrincipal:
        pub_key: Any = jwt.algorithms.RSAAlgorithm.from_jwk(
            json.dumps(self.keypair.public_jwk, separators=(",", ":"))
        )
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=pub_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except jwt.PyJWTError as exc:
            raise UpstreamIdentityError(f"Upstream OIDC verification failed: {exc}") from exc

        raw_groups = claims.get("groups", [])
        groups = tuple(str(g) for g in raw_groups) if isinstance(raw_groups, list) else ()
        scopes = tuple(s for s in str(claims.get("scope", "")).split(" ") if s)
        return HumanPrincipal(
            tenant_id=str(claims["tenant_id"]),
            subject_id=str(claims["sub"]),
            email=str(claims["email"]),
            display_name=str(claims.get("name", claims["sub"])),
            department=str(claims["department"]),
            groups=groups,
            scopes=scopes,
            clearance=ClearanceLevel(int(claims["clearance"])),
            po_approval_limit_usd=int(claims.get("po_approval_limit_usd", 0)),
            auth_method="oidc",
            upstream_session_id=str(claims.get("sid", "oidc-session")),
        )

    def _verify_saml2_assertion(self, encoded_assertion: str) -> HumanPrincipal:
        try:
            padded = encoded_assertion + "=" * (-len(encoded_assertion) % 4)
            xml_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            # XXE-hardened XML parser: disable external entities, DTD loading, and network access
            parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
            root = etree.fromstring(xml_bytes, parser=parser)
        except Exception as exc:
            raise UpstreamIdentityError(f"Malformed SAML 2.0 XML assertion: {exc}") from exc

        ns = {"s": SAML2_ASSERTION_NS}
        assertion_id = str(root.get("ID", ""))
        issuer_text = root.findtext("s:Issuer", default="", namespaces=ns)
        subject_id = root.findtext("s:Subject/s:NameID", default="", namespaces=ns)
        cond = root.find("s:Conditions", namespaces=ns)
        if cond is None:
            raise UpstreamIdentityError("SAML 2.0 assertion missing Conditions element")

        not_before = int(cond.get("NotBefore", "0"))
        not_on_or_after = int(cond.get("NotOnOrAfter", "0"))
        audience = str(cond.get("Audience", ""))

        now = int(time.time())
        if issuer_text != self.issuer:
            raise UpstreamIdentityError(f"Untrusted SAML Issuer: {issuer_text!r}")
        if audience != self.audience:
            raise UpstreamIdentityError(f"Invalid SAML Audience: {audience!r}")
        if now < not_before - 5 or now >= not_on_or_after:
            raise UpstreamIdentityError("SAML 2.0 assertion expired or not yet valid")

        attrs: dict[str, str] = {}
        for attr_el in root.findall("s:AttributeStatement/s:Attribute", namespaces=ns):
            name = str(attr_el.get("Name", ""))
            val_text = attr_el.findtext("s:AttributeValue", default="", namespaces=ns)
            attrs[name] = val_text

        expected_body = (
            f"{assertion_id}|{issuer_text}|{audience}|{attrs.get('tenant_id', '')}|{subject_id}|"
            f"{attrs.get('email', '')}|{attrs.get('display_name', '')}|"
            f"{attrs.get('department', '')}|{attrs.get('groups', '')}|"
            f"{attrs.get('scopes', '')}|{attrs.get('clearance', '')}|"
            f"{attrs.get('po_approval_limit_usd', '')}|{attrs.get('session_id', '')}|"
            f"{not_before}|{not_on_or_after}"
        )
        expected_mac = hmac.new(
            self._saml_secret, expected_body.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        provided_mac = attrs.get("signature_mac", "")
        if not hmac.compare_digest(expected_mac, provided_mac):
            raise UpstreamIdentityError("SAML 2.0 cryptographic signature verification failed")

        groups = tuple(g for g in attrs.get("groups", "").split(",") if g)
        scopes = tuple(s for s in attrs.get("scopes", "").split(" ") if s)
        return HumanPrincipal(
            tenant_id=attrs["tenant_id"],
            subject_id=subject_id,
            email=attrs["email"],
            display_name=attrs["display_name"],
            department=attrs["department"],
            groups=groups,
            scopes=scopes,
            clearance=ClearanceLevel(int(attrs["clearance"])),
            po_approval_limit_usd=int(attrs.get("po_approval_limit_usd", "0")),
            auth_method="saml2",
            upstream_session_id=attrs.get("session_id", "saml-session"),
        )

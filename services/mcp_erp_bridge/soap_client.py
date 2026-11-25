"""Resilient SOAP 1.2 + WS-Security Client & XXE-Hardened `BAPIRET2` XML Codec."""

from __future__ import annotations

from typing import Protocol

import httpx
from enterprise_twin.soap_erp_mock.sap_soap_server import (
    SAP_BAPI_NS,
    SOAP12_ENV_NS,
    WSSE_NS,
    LegacySAPSoapTwin,
)
from lxml import etree

from aegis_core.resilience import (
    CircuitBreaker,
    TransientDependencyError,
    execute_with_full_jitter_retry,
)


class SOAPTransportPort(Protocol):
    """Pluggable SOAP 1.2 transport (resilient HTTP/mTLS in prod, direct twin in unit tests)."""

    def post_envelope(self, xml_payload: bytes) -> tuple[int, bytes]:
        ...


class DirectInProcessSOAPTransport:
    """In-process adapter to `LegacySAPSoapTwin` using identical raw XML byte serialization."""

    def __init__(self, twin: LegacySAPSoapTwin) -> None:
        self._twin = twin

    def post_envelope(self, xml_payload: bytes) -> tuple[int, bytes]:
        return self._twin.handle_soap_envelope(xml_payload)


class HttpSOAPTransport:
    """Circuit-broken + full-jitter-retried HTTP/TLS SOAP 1.2 client for SAP S/4HANA."""

    def __init__(
        self,
        endpoint_url: str,
        timeout_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        max_attempts: int = 3,
    ) -> None:
        self._url = endpoint_url
        self._timeout = timeout_seconds
        self._transport = transport
        self._breaker = circuit_breaker or CircuitBreaker("sap-soap-erp", failure_threshold=5)
        self._max_attempts = max_attempts

    def post_envelope(self, xml_payload: bytes) -> tuple[int, bytes]:
        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}

        def _attempt() -> tuple[int, bytes]:
            try:
                with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                    resp = client.post(self._url, content=xml_payload, headers=headers)
            except httpx.TransportError as exc:
                raise TransientDependencyError(f"SAP SOAP transport fault: {exc}") from exc
            if resp.status_code in (502, 503, 504):
                raise TransientDependencyError(f"SAP SOAP gateway HTTP {resp.status_code}")
            return resp.status_code, resp.content

        return self._breaker.call(
            lambda: execute_with_full_jitter_retry(
                _attempt,
                max_attempts=self._max_attempts,
            )
        )


def build_wsse_soap_envelope(
    operation: str,
    params: dict[str, str],
    *,
    wsse_username: str,
    wsse_credential: str,
) -> bytes:
    """Construct SOAP 1.2 XML envelope with OASIS WS-Security UsernameToken header."""
    nsmap = {"soap": SOAP12_ENV_NS, "wsse": WSSE_NS, "bapi": SAP_BAPI_NS}
    env = etree.Element(f"{{{SOAP12_ENV_NS}}}Envelope", nsmap=nsmap)
    hdr = etree.SubElement(env, f"{{{SOAP12_ENV_NS}}}Header")
    sec = etree.SubElement(hdr, f"{{{WSSE_NS}}}Security")
    ut = etree.SubElement(sec, f"{{{WSSE_NS}}}UsernameToken")
    u_el = etree.SubElement(ut, f"{{{WSSE_NS}}}Username")
    u_el.text = wsse_username
    p_el = etree.SubElement(ut, f"{{{WSSE_NS}}}Password")
    p_el.text = wsse_credential

    body = etree.SubElement(env, f"{{{SOAP12_ENV_NS}}}Body")
    op_el = etree.SubElement(body, f"{{{SAP_BAPI_NS}}}{operation}")
    for key, val in params.items():
        f_el = etree.SubElement(op_el, f"{{{SAP_BAPI_NS}}}{key}")
        f_el.text = val
    return bytes(etree.tostring(env, encoding="utf-8", xml_declaration=True))


def parse_sap_bapiret2_response(xml_bytes: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """Parse SAP BAPI XML response with XXE-hardened `lxml` parser."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_bytes, parser=parser)
    ns = {"soap": SOAP12_ENV_NS, "bapi": SAP_BAPI_NS}
    body = root.find("soap:Body", ns)
    if body is None or len(body) == 0:
        return {}, {"type": "E", "code": "SOAP-EMPTY", "message": "Empty SOAP body"}

    op_resp = body[0]
    fields: dict[str, str] = {}
    for child in op_resp:
        lname = etree.QName(child.tag).localname
        if lname != "RETURN" and child.text is not None:
            fields[lname] = child.text

    ret_item = op_resp.find("bapi:RETURN/bapi:item", ns)
    if ret_item is None:
        return fields, {"type": "S", "code": "00-000", "message": "OK"}

    r_type = ret_item.findtext("bapi:TYPE", default="S", namespaces=ns)
    r_id = ret_item.findtext("bapi:ID", default="00", namespaces=ns)
    r_num = ret_item.findtext("bapi:NUMBER", default="000", namespaces=ns)
    r_msg = ret_item.findtext("bapi:MESSAGE", default="", namespaces=ns)
    return fields, {"type": r_type, "code": f"{r_id}-{r_num}", "message": r_msg}

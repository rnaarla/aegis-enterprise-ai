"""Realistic on-prem SAP ECC 6.0 / S/4HANA SOAP 1.2 + WS-Security server.

Reproduces legacy ERP behaviors that break naive AI wrappers:
1. Cryptic German field identifiers (`LIFNR`, `BUKRS`, `EBELN`, `NETPR`, `SPERR`).
2. `HTTP 200 OK` responses containing `<BAPIRET2><TYPE>E</TYPE>...</BAPIRET2>` business faults.
3. Zero native write idempotency (duplicate SOAP calls create duplicate POs unless guarded).
4. Mutable vendor bank details (`BANKN`) to test TOCTOU drift during async human approvals.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass

from fastapi import FastAPI, Request, Response
from lxml import etree

SOAP12_ENV_NS = "http://www.w3.org/2003/05/soap-envelope"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
SAP_BAPI_NS = "urn:sap-com:document:sap:rfc:functions"


@dataclass
class SAPVendorRecord:
    lifnr: str
    name1: str
    bukrs: str
    sperr_blocked: bool
    bank_iban: str
    currency: str = "USD"

    def state_hash(self) -> str:
        payload = f"{self.lifnr}|{self.name1}|{self.bukrs}|{int(self.sperr_blocked)}|{self.bank_iban}|{self.currency}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SAPPurchaseOrder:
    ebeln: str
    lifnr: str
    bukrs: str
    description: str
    amount_usd: float
    created_by: str
    approved_by: str | None


class LegacySAPSoapTwin:
    """Stateful in-process SAP BAPI engine exposed via SOAP 1.2 XML envelopes."""

    def __init__(
        self,
        *,
        wsse_username: str = "SVC_AEGIS_RFC",
        wsse_credential: str = "sap_rfc_twin_credential",
    ) -> None:
        self._wsse_user = wsse_username
        self._wsse_pass = wsse_credential
        self._lock = threading.Lock()
        self._po_counter = 4500019200
        self._vendors: dict[str, SAPVendorRecord] = {
            "0000100450": SAPVendorRecord(
                lifnr="0000100450",
                name1="Helios Cloud & Semiconductor Advisory LLP",
                bukrs="1000",
                sperr_blocked=False,
                bank_iban="US64SVBK000098124401",
            ),
            "0000999999": SAPVendorRecord(
                lifnr="0000999999",
                name1="Sanctioned Offshore Holdings Ltd",
                bukrs="1000",
                sperr_blocked=True,
                bank_iban="KY11OFFS000000009999",
            ),
        }
        self._purchase_orders: list[SAPPurchaseOrder] = []

    def get_vendor_snapshot(self, lifnr: str) -> SAPVendorRecord | None:
        with self._lock:
            v = self._vendors.get(lifnr)
            if v is None:
                return None
            return SAPVendorRecord(
                lifnr=v.lifnr,
                name1=v.name1,
                bukrs=v.bukrs,
                sperr_blocked=v.sperr_blocked,
                bank_iban=v.bank_iban,
                currency=v.currency,
            )

    def mutate_vendor_bank_iban(self, lifnr: str, new_iban: str) -> str:
        """Simulate mid-flight ERP state drift (e.g., vendor bank change during approval wait)."""
        with self._lock:
            v = self._vendors[lifnr]
            v.bank_iban = new_iban
            return v.state_hash()

    def list_purchase_orders(self) -> list[SAPPurchaseOrder]:
        with self._lock:
            return list(self._purchase_orders)

    def wsdl_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" '
            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            f'targetNamespace="{SAP_BAPI_NS}" name="SAP_MM_PO_BAPI">'
            "<types><xsd:schema>"
            '<xsd:element name="BAPI_VENDOR_GETDETAIL"><xsd:complexType><xsd:sequence>'
            '<xsd:element name="LIFNR" type="xsd:string" minOccurs="1"/>'
            "</xsd:sequence></xsd:complexType></xsd:element>"
            '<xsd:element name="BAPI_PO_CREATE1"><xsd:complexType><xsd:sequence>'
            '<xsd:element name="LIFNR" type="xsd:string" minOccurs="1"/>'
            '<xsd:element name="NETPR" type="xsd:decimal" minOccurs="1"/>'
            '<xsd:element name="TXZ01" type="xsd:string" minOccurs="1"/>'
            '<xsd:element name="TESTRUN" type="xsd:string" minOccurs="0"/>'
            "</xsd:sequence></xsd:complexType></xsd:element>"
            '<xsd:element name="BAPI_PO_CANCEL"><xsd:complexType><xsd:sequence>'
            '<xsd:element name="EBELN" type="xsd:string" minOccurs="1"/>'
            "</xsd:sequence></xsd:complexType></xsd:element>"
            "</xsd:schema></types>"
            '<portType name="SAP_MM_PortType">'
            '<operation name="BAPI_VENDOR_GETDETAIL"><documentation>Read SAP vendor LFA1</documentation></operation>'
            '<operation name="BAPI_PO_CREATE1"><documentation>Create or simulate SAP PO</documentation></operation>'
            '<operation name="BAPI_PO_CANCEL">'
            "<documentation>Compensating reverse PO cancellation</documentation></operation>"
            "</portType>"
            "</definitions>"
        )

    def handle_soap_envelope(self, raw_xml: bytes) -> tuple[int, bytes]:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
        try:
            root = etree.fromstring(raw_xml, parser=parser)
        except Exception as exc:
            return 400, self._soap_fault("Sender", f"Malformed SOAP XML: {exc}")

        ns = {"soap": SOAP12_ENV_NS, "wsse": WSSE_NS, "bapi": SAP_BAPI_NS}
        user = root.findtext("soap:Header/wsse:Security/wsse:UsernameToken/wsse:Username", "", ns)
        pw = root.findtext("soap:Header/wsse:Security/wsse:UsernameToken/wsse:Password", "", ns)
        if not (
            hmac.compare_digest(user, self._wsse_user) and hmac.compare_digest(pw, self._wsse_pass)
        ):
            return 401, self._soap_fault("Sender", "WS-Security authentication failed")

        body = root.find("soap:Body", ns)
        if body is None or len(body) == 0:
            return 400, self._soap_fault("Sender", "Empty SOAP Body")

        op_el = body[0]
        local_name = etree.QName(op_el.tag).localname
        if local_name == "BAPI_VENDOR_GETDETAIL":
            return 200, self._exec_vendor_getdetail(op_el, ns)
        if local_name == "BAPI_PO_CREATE1":
            return 200, self._exec_po_create(op_el, ns)
        if local_name == "BAPI_PO_CANCEL":
            return 200, self._exec_po_cancel(op_el, ns)
        return 400, self._soap_fault("Sender", f"Unsupported SAP RFC operation: {local_name}")

    def _exec_po_cancel(self, op_el: etree._Element, ns: dict[str, str]) -> bytes:
        ebeln = op_el.findtext("bapi:EBELN", default="", namespaces=ns).strip()
        with self._lock:
            before = len(self._purchase_orders)
            self._purchase_orders = [po for po in self._purchase_orders if po.ebeln != ebeln]
            if len(self._purchase_orders) == before:
                return self._bapi_response(
                    "BAPI_PO_CANCELResponse",
                    fields={"EBELN": ebeln},
                    bapiret2=("E", "ME", "099", f"PO {ebeln} not found for cancellation"),
                )
            return self._bapi_response(
                "BAPI_PO_CANCELResponse",
                fields={"EBELN": ebeln, "CANCELLED": "X"},
                bapiret2=("S", "06", "022", f"Purchase order {ebeln} reversed via Saga compensation"),
            )

    def _exec_vendor_getdetail(self, op_el: etree._Element, ns: dict[str, str]) -> bytes:
        lifnr = op_el.findtext("bapi:LIFNR", default="", namespaces=ns).strip()
        with self._lock:
            vendor = self._vendors.get(lifnr)
            if vendor is None:
                return self._bapi_response(
                    "BAPI_VENDOR_GETDETAILResponse",
                    fields={},
                    bapiret2=("E", "F2", "152", f"Vendor {lifnr} does not exist in master LFA1"),
                )
            return self._bapi_response(
                "BAPI_VENDOR_GETDETAILResponse",
                fields={
                    "LIFNR": vendor.lifnr,
                    "NAME1": vendor.name1,
                    "BUKRS": vendor.bukrs,
                    "SPERR": "X" if vendor.sperr_blocked else "",
                    "BANKN": vendor.bank_iban,
                    "WAERS": vendor.currency,
                    "STATE_ETAG": vendor.state_hash(),
                },
                bapiret2=("S", "00", "000", "OK"),
            )

    def _exec_po_create(self, op_el: etree._Element, ns: dict[str, str]) -> bytes:
        lifnr = op_el.findtext("bapi:LIFNR", default="", namespaces=ns).strip()
        bukrs = op_el.findtext("bapi:BUKRS", default="1000", namespaces=ns).strip()
        short_text = op_el.findtext("bapi:TXZ01", default="", namespaces=ns).strip()
        netpr_str = op_el.findtext("bapi:NETPR", default="0", namespaces=ns).strip()
        created_by = op_el.findtext("bapi:ERNAM", default="UNKNOWN", namespaces=ns).strip()
        approved_by = op_el.findtext("bapi:AFNAM", default="", namespaces=ns).strip() or None
        dry_run = op_el.findtext("bapi:TESTRUN", default="", namespaces=ns).strip() == "X"

        try:
            amount = round(float(netpr_str), 2)
        except ValueError:
            return self._bapi_response(
                "BAPI_PO_CREATE1Response",
                fields={"EBELN": ""},
                bapiret2=("E", "ME", "002", f"Invalid NETPR currency value: {netpr_str}"),
            )

        if amount <= 0:
            return self._bapi_response(
                "BAPI_PO_CREATE1Response",
                fields={"EBELN": ""},
                bapiret2=("E", "ME", "040", "Net price NETPR must be greater than 0.00"),
            )

        with self._lock:
            vendor = self._vendors.get(lifnr)
            if vendor is None:
                return self._bapi_response(
                    "BAPI_PO_CREATE1Response",
                    fields={"EBELN": ""},
                    bapiret2=("E", "ME", "081", f"Vendor {lifnr} not maintained in company {bukrs}"),
                )
            # Classic SAP trap: HTTP 200 OK, but BAPIRET2 TYPE='E' because vendor has SPERR='X'
            if vendor.sperr_blocked:
                return self._bapi_response(
                    "BAPI_PO_CREATE1Response",
                    fields={"EBELN": ""},
                    bapiret2=(
                        "E",
                        "ME",
                        "083",
                        f"Vendor {lifnr} ({vendor.name1}) has central posting/purchasing block SPERR=X",
                    ),
                )

            if dry_run:
                return self._bapi_response(
                    "BAPI_PO_CREATE1Response",
                    fields={"EBELN": "SIMULATED", "STATE_ETAG": vendor.state_hash()},
                    bapiret2=("S", "06", "017", "Simulation of BAPI_PO_CREATE1 succeeded with 0 errors"),
                )

            self._po_counter += 1
            ebeln = str(self._po_counter)
            po = SAPPurchaseOrder(
                ebeln=ebeln,
                lifnr=lifnr,
                bukrs=bukrs,
                description=short_text,
                amount_usd=amount,
                created_by=created_by,
                approved_by=approved_by,
            )
            self._purchase_orders.append(po)
            return self._bapi_response(
                "BAPI_PO_CREATE1Response",
                fields={"EBELN": ebeln, "STATE_ETAG": vendor.state_hash()},
                bapiret2=("S", "06", "017", f"Standard PO created under the number {ebeln}"),
            )

    def _bapi_response(
        self,
        response_tag: str,
        *,
        fields: dict[str, str],
        bapiret2: tuple[str, str, str, str],
    ) -> bytes:
        nsmap = {"soap": SOAP12_ENV_NS, "bapi": SAP_BAPI_NS}
        env = etree.Element(f"{{{SOAP12_ENV_NS}}}Envelope", nsmap=nsmap)
        body = etree.SubElement(env, f"{{{SOAP12_ENV_NS}}}Body")
        op_resp = etree.SubElement(body, f"{{{SAP_BAPI_NS}}}{response_tag}")
        for k, v in fields.items():
            el = etree.SubElement(op_resp, f"{{{SAP_BAPI_NS}}}{k}")
            el.text = v
        ret = etree.SubElement(op_resp, f"{{{SAP_BAPI_NS}}}RETURN")
        item = etree.SubElement(ret, f"{{{SAP_BAPI_NS}}}item")
        for tag, val in zip(("TYPE", "ID", "NUMBER", "MESSAGE"), bapiret2, strict=True):
            t_el = etree.SubElement(item, f"{{{SAP_BAPI_NS}}}{tag}")
            t_el.text = val
        return bytes(etree.tostring(env, encoding="utf-8", xml_declaration=True))

    def _soap_fault(self, code: str, reason: str) -> bytes:
        env = etree.Element(f"{{{SOAP12_ENV_NS}}}Envelope", nsmap={"soap": SOAP12_ENV_NS})
        body = etree.SubElement(env, f"{{{SOAP12_ENV_NS}}}Body")
        fault = etree.SubElement(body, f"{{{SOAP12_ENV_NS}}}Fault")
        c_el = etree.SubElement(fault, f"{{{SOAP12_ENV_NS}}}Code")
        c_el.text = code
        r_el = etree.SubElement(fault, f"{{{SOAP12_ENV_NS}}}Reason")
        r_el.text = reason
        return bytes(etree.tostring(env, encoding="utf-8", xml_declaration=True))


def create_sap_soap_app(twin: LegacySAPSoapTwin) -> FastAPI:
    """Expose `LegacySAPSoapTwin` as an HTTP SOAP 1.2 + WSDL endpoint."""
    app = FastAPI(title="Meridian Legacy SAP ECC 6.0 SOAP 1.2 Server", docs_url=None)

    @app.get("/sap/bc/srt/wsdl/bapi_po")
    def get_wsdl() -> Response:
        return Response(content=twin.wsdl_xml(), media_type="text/xml; charset=utf-8")

    @app.post("/sap/bc/srt/rfc/sap/bapi_po")
    async def post_soap(request: Request) -> Response:
        raw_xml = await request.body()
        status, resp_xml = twin.handle_soap_envelope(raw_xml)
        return Response(
            status_code=status,
            content=resp_xml,
            media_type="application/soap+xml; charset=utf-8",
        )

    return app

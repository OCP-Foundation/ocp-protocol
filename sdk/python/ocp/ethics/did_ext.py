"""
DID Document Ethics Service Extensions.
Ref: Integration Spec INT-009,010,048

Helpers for adding ethics service endpoints to DID Documents.
"""
from __future__ import annotations


class DIDDocumentEthicsExtension:
    """
    Extends a DID Document with ethics service endpoints.

    Usage:
        ext = DIDDocumentEthicsExtension()
        did_doc = ext.add_ethics_contact(did_doc, "mailto:ethics@org.com")
        did_doc = ext.add_transparency_card(did_doc, "https://org.com/.well-known/ocp/transparency.json")
    """

    def add_ethics_contact(self, did_document: dict, endpoint: str) -> dict:
        """Add OCPEthicsContact service to DID Document."""
        did_document = dict(did_document)
        services = did_document.setdefault("service", [])
        agent_id = did_document.get("id", "")

        # Remove existing ethics contact if present
        services = [s for s in services if s.get("type") != "OCPEthicsContact"]

        services.append({
            "id": f"{agent_id}#ethics-contact",
            "type": "OCPEthicsContact",
            "serviceEndpoint": endpoint
        })
        did_document["service"] = services
        return did_document

    def add_transparency_card(self, did_document: dict, endpoint: str) -> dict:
        """Add OCPTransparencyCard service to DID Document."""
        did_document = dict(did_document)
        services = did_document.setdefault("service", [])
        agent_id = did_document.get("id", "")

        services = [s for s in services if s.get("type") != "OCPTransparencyCard"]

        services.append({
            "id": f"{agent_id}#transparency-card",
            "type": "OCPTransparencyCard",
            "serviceEndpoint": endpoint
        })
        did_document["service"] = services
        return did_document

    def add_cognitive_classification(self, did_document: dict) -> dict:
        """Add cognitive_data_classification to capability declarations."""
        did_document = dict(did_document)
        caps = did_document.setdefault("capabilityDeclaration", [])
        if "cognitive_data_classification" not in caps:
            caps.append("cognitive_data_classification")
        return did_document

    def validate(self, did_document: dict, conformance_level: str = "ocp_core") -> tuple[bool, list[str]]:
        """Validate ethics service endpoints."""
        issues = []
        if conformance_level != "ocp_ethical":
            return True, []

        services = did_document.get("service", [])
        types = {s.get("type") for s in services}

        if "OCPEthicsContact" not in types:
            issues.append("OCPEthicsContact service endpoint required for OCP Ethical")
        if "OCPTransparencyCard" not in types:
            issues.append("OCPTransparencyCard service endpoint required for OCP Ethical")

        return len(issues) == 0, issues

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Union
import xml.etree.ElementTree as ET

class ConfigAuthMessageType(Enum):
    Init = "init"
    AuthReply = "auth-reply"
    AuthRequest = "auth-request"
    Complete = "complete"


class ConfigAuthId(Enum):
    Main = "main"
    Success = "success"
    Failure = "failure"


class Authenticator(Enum):
    Form = "form"
    OneTouch = "onetouch"
    OIDC = "oidc"


@dataclass
class ConfigAuthXmlParameter:
    Name: str
    Value: str = ""
    Label: Optional[str] = None
    Type: Optional[str] = None  # "text" | "password"


@dataclass
class ClientEnvironment:
    UID: Optional[str] = None
    ClientVersion: Optional[str] = None
    WolfSSLVersion: Optional[str] = None
    OperatingSystemInformation: Optional[str] = None
    OperatingSystemArchitecture: Optional[str] = None
    IsAVEnable: Optional[bool] = None
    IsAVUpdated: Optional[bool] = None


@dataclass
class ConfigAuthXml:
    MessageType: ConfigAuthMessageType = ConfigAuthMessageType.Init
    AuthId: ConfigAuthId = ConfigAuthId.Failure
    authenticator: Authenticator = Authenticator.Form
    Parameters: List[ConfigAuthXmlParameter] = field(default_factory=list)

    Message: str = ""
    FormAction: Optional[str] = None
    SessionToken: Optional[str] = None

    clientEnvironment: Optional[ClientEnvironment] = None
    DiscoveryEndPoint: str = ""
    ClientId: str = ""
    Nonce: Optional[str] = None

    # ---------- Build XML like CreateXmlDocument ----------
    def create_xml_document_string(self) -> str:
        # For Form/OIDC: if parameters exist -> auth-reply, else init
        msg_type = self.MessageType
        if self.authenticator in (Authenticator.Form, Authenticator.OIDC):
            msg_type = (ConfigAuthMessageType.AuthReply
                        if self.Parameters else ConfigAuthMessageType.Init)
        elif self.authenticator == Authenticator.OneTouch:
            msg_type = ConfigAuthMessageType.AuthReply

        root = ET.Element("config-auth", {
            "client": "vpn",
            "type": msg_type.value,
        })

        ver = ET.SubElement(root, "version", {"who": "vpn"})
        ver.text = "v2.0"

        device = ET.SubElement(root, "device-id")
        device.text = "win"

        if msg_type == ConfigAuthMessageType.AuthReply:
            auth_el = ET.Element("auth")
            if self.authenticator in (Authenticator.Form, Authenticator.OIDC):
                for p in self.Parameters:
                    # Write <{Name}>Value</{Name}>
                    el = ET.Element(p.Name)
                    el.text = p.Value or ""
                    auth_el.append(el)
            elif self.authenticator == Authenticator.OneTouch:
                auth_el.set("authenticator", "onetouch")
            root.append(auth_el)

        if self.clientEnvironment is not None:
            ce = self.clientEnvironment
            ce_el = ET.SubElement(root, "client-environment")

            def add(tag: str, val: Optional[Union[str, bool]]):
                el = ET.SubElement(ce_el, tag)
                el.text = "" if val is None else (str(val))

            add("uid", ce.UID)
            add("client-version", ce.ClientVersion)
            add("wolfssl-version", ce.WolfSSLVersion)
            add("os-information", ce.OperatingSystemInformation)
            add("os-architecture", ce.OperatingSystemArchitecture)
            add("av-enabled", ce.IsAVEnable)
            add("av-updated", ce.IsAVUpdated)

        return ET.tostring(root, encoding="utf-8", xml_declaration=True, method="xml").decode("utf-8")

    @staticmethod
    def read_xml(xml_string: str) -> "ConfigAuthXml":
        try:
            root = ET.fromstring(xml_string)
        except Exception as ex:
            raise ValueError("Could not load XML string") from ex

        if root.tag != "config-auth":
            raise ValueError('Was expecting one (1) single config-auth element from server')

        # type
        type_attr = (root.attrib.get("type") or "").strip() or None
        if type_attr is None:
            raise NotImplementedError("Could not parse XML, no type was found")
        try:
            msg_type = ConfigAuthMessageType(type_attr)
        except ValueError:
            raise NotImplementedError(f'Could not parse XML, type "{type_attr}" is unknown')

        # <auth>
        auth_nodes = root.findall("auth")
        if len(auth_nodes) != 1:
            raise ValueError(f'Was expecting one (1) single auth element from server, got {len(auth_nodes)}')
        auth_el = auth_nodes[0]

        # auth id
        id_attr = (auth_el.attrib.get("id") or "").strip() or None
        if id_attr is None:
            raise ValueError('Missing "id" attribute in auth-element')
        try:
            auth_id = {
                "main": ConfigAuthId.Main,
                "success": ConfigAuthId.Success,
                "failure": ConfigAuthId.Failure,
            }[id_attr]
        except KeyError:
            raise NotImplementedError(f'Could not parse XML, auth id "{id_attr}" is unknown')

        # authenticator
        authenticator_attr = auth_el.attrib.get("authenticator")
        if authenticator_attr is None:
            authenticator = Authenticator.Form
        else:
            try:
                authenticator = Authenticator(authenticator_attr)
            except ValueError:
                raise NotImplementedError(
                    f'Could not parse XML, auth authenticator="{authenticator_attr}" is unknown'
                )

        # message (0..1)
        message_nodes = auth_el.findall("message")
        if len(message_nodes) > 1:
            raise ValueError(f'Was expecting zero (0) or one (1) message element from server, got {len(message_nodes)}')
        message = message_nodes[0].text if message_nodes else ""
        message = (message or "").strip()

        # discovery-endpoint (0..1)
        discovery_nodes = auth_el.findall("discovery-endpoint")
        if len(discovery_nodes) > 1:
            raise ValueError(f'Was expecting zero (0) or one (1) discovery-endpoint element from server, got {len(discovery_nodes)}')
        discovery = (discovery_nodes[0].text or "").strip() if discovery_nodes else ""

        # client-id (0..1)
        client_id_nodes = auth_el.findall("client-id")
        if len(client_id_nodes) > 1:
            raise ValueError(f'Was expecting zero (0) or one (1) client-id element from server, got {len(client_id_nodes)}')
        client_id = (client_id_nodes[0].text or "").strip() if client_id_nodes else ""

        # nonce (0..1)
        nonce_nodes = auth_el.findall("nonce")
        if len(nonce_nodes) > 1:
            raise ValueError(f'Was expecting zero (0) or one (1) nonce element from server, got {len(nonce_nodes)}')
        nonce = (nonce_nodes[0].text or None) if nonce_nodes else None

        # form (0..1) with inputs
        form_nodes = auth_el.findall("form")
        if len(form_nodes) > 1:
            raise ValueError(f'Was expecting zero (0) or one (1) "form" element from server, got {len(form_nodes)}')
        parameters: List[ConfigAuthXmlParameter] = []
        form_action: Optional[str] = None
        if form_nodes:
            form_el = form_nodes[0]
            form_action = (form_el.attrib.get("action") or "").strip()
            if form_action == "":
                form_action = None
            for input_el in form_el.findall("input"):
                attrs = input_el.attrib
                label = attrs.get("label")
                name = attrs.get("name")
                typ = attrs.get("type")
                if label is None:
                    raise ValueError('Missing "label" attribute in input-element')
                if name is None:
                    raise ValueError('Missing "name" attribute in input-element')
                if typ is None:
                    raise ValueError('Missing "type" attribute in input-element')
                if typ not in ("text", "password"):
                    raise NotImplementedError(f'Could not parse XML, input type "{typ}" is unknown')
                parameters.append(ConfigAuthXmlParameter(Name=name, Label=label, Type=typ))

        # session-token (0..1) anywhere under root
        sess_nodes = root.findall(".//session-token")
        if sess_nodes:
            if len(sess_nodes) > 1:
                raise ValueError(f'Was expecting zero (0) or one (1) "session-token" element from server, got {len(sess_nodes)}')
            session_text = (sess_nodes[0].text or "").strip()
            if session_text and len(session_text) <= 12:
                session_token = None
            else:
                session_token = session_text if session_text else None
        else:
            session_token = None

        return ConfigAuthXml(
            MessageType=msg_type,
            AuthId=auth_id,
            authenticator=authenticator,
            Parameters=parameters,
            Message=message,
            FormAction=form_action,
            SessionToken=session_token,
            clientEnvironment=None,
            DiscoveryEndPoint=discovery,
            ClientId=client_id,
            Nonce=nonce,
        )
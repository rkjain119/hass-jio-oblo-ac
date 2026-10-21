"""MQTT client for the Midea RAC Wi-Fi cloud (Jio Smart Living / OBLO platform)."""
from __future__ import annotations

import json
import logging
import random
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import paho.mqtt.client as mqtt

from homeassistant.exceptions import HomeAssistantError

from .const import BROKER_HOST, BROKER_PORT

_LOGGER = logging.getLogger(__name__)

# The broker presents a certificate from Oblo's private CA (not sent in the chain), so
# the public CA bundle cannot verify it. Trust exactly that certificate instead.
_BROKER_CERT = Path(__file__).with_name("broker.pem")


def _broker_tls_context() -> ssl.SSLContext:
    """TLS context that only accepts the pinned broker certificate."""
    ctx = ssl.create_default_context(cafile=str(_BROKER_CERT))
    # Let the pinned leaf act as the trust anchor without its (unpublished) issuer.
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    # The certificate's only name is CN=jiosmartliving.com (no SAN), which never matches
    # BROKER_HOST. Pinning the exact certificate is the stronger check, so the
    # name check is off. Certificate verification itself stays CERT_REQUIRED.
    ctx.check_hostname = False
    return ctx


class ObloOffline(HomeAssistantError):
    """A command could not be sent because the cloud connection is down."""


# The full device list can lag a pushed change by several seconds; for this long after an
# event, keep the event's value instead of the (possibly stale) list value.
_EVENT_HOLD = 20.0
# Consecutive "not authorized" CONNACKs before treating the session as expired, so a
# single transient rejection doesn't force an OTP re-login.
_AUTH_REJECT_LIMIT = 2


class ObloNode:
    """A single appliance (AC) behind the gateway."""

    def __init__(self, node_id: int, name: str, serial: str) -> None:
        self.id = node_id
        self.name = name
        self.serial = serial
        self.services: dict[str, dict[str, Any]] = {}

    def prop(self, service: str, name: str, default=None):
        return self.services.get(service, {}).get(name, default)


class ObloClient:
    """Connects to the OBLO MQTT broker and controls AC nodes."""

    def __init__(self, phone: str, token: str, owner_id: str, serial: str) -> None:
        self._phone = phone
        self._token = token                      # "<userId>-<rand>"
        self._user_id = token.split("-", 1)[0]
        self._owner = owner_id
        self._serial = serial                    # gateway serial, e.g. FFFF137614FB
        self._sender = f"cli/{token}"
        self._client_id = f"m-{token}-ha{random.randint(1000,9999)}"
        self._req_topic_tpl = "oblo/{owner}/gtw/{serial}/ohm/req"
        # Responses come back addressed to the sender (cli/<token>), not the mqtt client id
        self._rsp_topic = f"oblo/{owner_id}/cli/{token}/rsp"
        # The gateway pushes device_property_changed events here (same topic the app uses)
        self._evt_topic = f"oblo/{owner_id}/gtw/{serial}/ohm/evt"
        self._event_ts: dict[tuple[int, str, str], float] = {}
        self.nodes: dict[int, ObloNode] = {}
        self.gateways: set[str] = set()
        self._connected = threading.Event()
        self._first_state = threading.Event()
        self.auth_failed = False
        self._auth_rejects = 0
        self._fail_logged = False
        self.last_error: str | None = None
        self.on_auth_failed: Callable[[], None] | None = None
        self._state_cbs: list[Callable[[], None]] = []
        self._last_full: dict | None = None

        self._mqtt = mqtt.Client(client_id=self._client_id, protocol=mqtt.MQTTv311)
        self._mqtt.username_pw_set(phone, token)
        self._mqtt.tls_set_context(_broker_tls_context())
        self._mqtt.on_connect = self._on_connect
        self._mqtt.on_connect_fail = self._on_connect_fail
        self._mqtt.on_message = self._on_message
        self._mqtt.on_disconnect = self._on_disconnect

    # ---- lifecycle ----
    def connect(self) -> None:
        # Non-blocking: the network loop thread performs connect + auto-reconnect.
        self._mqtt.connect_async(BROKER_HOST, BROKER_PORT, keepalive=30)
        self._mqtt.loop_start()

    def wait_ready(self, timeout: float = 25) -> bool:
        """Wait until connected and the first device list has been parsed."""
        return self._first_state.wait(timeout)

    def disconnect(self) -> None:
        # Disconnect first so the loop thread sends DISCONNECT and closes the socket.
        try:
            self._mqtt.disconnect()
        except Exception:  # noqa: BLE001
            _LOGGER.debug("Midea cloud disconnect failed", exc_info=True)
        try:
            self._mqtt.loop_stop()
        except Exception:  # noqa: BLE001
            _LOGGER.debug("Midea cloud loop stop failed", exc_info=True)

    def set_state_callback(self, cb: Callable[[], None]) -> None:
        self._state_cbs.append(cb)

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def wait_connected(self, timeout: float = 15) -> bool:
        return self._connected.wait(timeout)

    # ---- mqtt callbacks ----
    def _on_connect(self, client, userdata, flags, rc, props=None):
        if rc == 0:
            _LOGGER.info("Midea cloud MQTT connected")
            self._auth_rejects = 0
            self._fail_logged = False
            self.last_error = None
            client.subscribe(self._rsp_topic)
            client.subscribe(self._evt_topic, qos=1)
            self._connected.set()
            # Request the full device list as soon as we are connected
            self.refresh(self._serial)
        else:
            _LOGGER.error("Midea cloud MQTT connect failed rc=%s", rc)
            self.last_error = f"broker refused the connection (rc={rc})"
            # rc 4/5 = bad credentials / not authorized -> token expired
            if int(rc) in (4, 5):
                self._auth_rejects += 1
                if self._auth_rejects < _AUTH_REJECT_LIMIT:
                    return  # paho reconnects; give up only if it is refused again
                self.auth_failed = True
                self._first_state.set()  # unblock setup wait
                # Stop paho from retrying a dead token forever
                client.disconnect()
                if self.on_auth_failed:
                    self.on_auth_failed()

    def _on_connect_fail(self, client, userdata):
        # paho calls this from inside its except block, so the cause is still available
        exc = sys.exc_info()[1]
        self.last_error = str(exc) if exc else "connection failed"
        if self._fail_logged:
            return  # paho keeps retrying; log once per outage
        self._fail_logged = True
        if isinstance(exc, ssl.SSLCertVerificationError):
            _LOGGER.error(
                "Midea cloud broker certificate does not match the pinned broker.pem "
                "(%s); not sending credentials. The broker certificate may have changed",
                exc.verify_message,
            )
        else:
            _LOGGER.warning("Cannot reach Midea cloud, retrying: %s", self.last_error)

    def _on_disconnect(self, client, userdata, rc, props=None):
        self._connected.clear()
        _LOGGER.warning("Midea cloud MQTT disconnected rc=%s", rc)

    def _on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            return
        if not isinstance(data, dict):
            return
        if data.get("name") == "device_property_changed":
            if self._apply_event(data.get("params") or {}):
                self._notify()
        # Full device list response contains node/service model
        elif self._parse_full(data):
            self._first_state.set()
            self._notify()

    def _notify(self) -> None:
        for cb in list(self._state_cbs):
            try:
                cb()
            except Exception:  # noqa: BLE001
                _LOGGER.exception("state callback failed")

    def _apply_event(self, params: dict) -> bool:
        """Apply a pushed property change. Returns True if a known node changed."""
        node = self.nodes.get(params.get("device_id"))
        service = params.get("service_name")
        prop = params.get("property_name")
        if node is None or not service or not prop:
            return False
        node.services.setdefault(service, {})[prop] = params.get("property_value")
        self._event_ts[(node.id, service, prop)] = time.monotonic()
        return True

    # ---- parsing ----
    def _parse_full(self, data: dict) -> bool:
        """Parse a get_object_list_by_type_detailed response. Returns True if nodes updated."""
        found = self._walk_nodes(data)
        if found:
            self._last_full = data
        return found

    def _walk_nodes(self, obj: Any, serial: str | None = None) -> bool:
        updated = False
        if isinstance(obj, dict):
            if "serialNumber" in obj and obj.get("serialNumber"):
                serial = obj.get("serialNumber")
                self.gateways.add(serial)
            # A node/object with services
            nid = obj.get("id")
            svc_list = obj.get("service_list") or obj.get("services")
            if isinstance(nid, int) and isinstance(svc_list, list):
                services: dict[str, dict[str, Any]] = {}
                for svc in svc_list:
                    if not isinstance(svc, dict):
                        continue
                    sname = svc.get("name")
                    props = {}
                    for p in svc.get("property_list", []) or []:
                        if isinstance(p, dict) and "name" in p:
                            props[p["name"]] = p.get("value")
                    if sname:
                        services[sname] = props
                # Only treat as AC node if it is an HVAC class / exposes thermostat
                cls = str(obj.get("class", ""))
                if cls.startswith("Hvac") or "ThermostatService" in services:
                    name = obj.get("device_name") or obj.get("name") or f"AC {nid}"
                    node = self.nodes.get(nid) or ObloNode(nid, name, serial or self._serial)
                    now = time.monotonic()
                    for (eid, sname, pname), ts in self._event_ts.items():
                        if eid == nid and now - ts < _EVENT_HOLD:
                            held = node.services.get(sname, {}).get(pname)
                            services.setdefault(sname, {})[pname] = held
                    node.name = name
                    node.serial = serial or node.serial or self._serial
                    node.services = services
                    self.nodes[nid] = node
                    updated = True
            for v in obj.values():
                updated |= self._walk_nodes(v, serial)
        elif isinstance(obj, list):
            for v in obj:
                updated |= self._walk_nodes(v, serial)
        return updated

    # ---- commands ----
    def _publish(self, serial: str, body: dict) -> bool:
        """Send a request now or not at all; returns whether it was sent.

        QoS 0 so paho never stores it for replay: a stale AC command applied after a
        reconnect is worse than none. A full refresh runs on every reconnect.
        """
        if not (self._connected.is_set() and self._mqtt.is_connected()):
            return False
        topic = self._req_topic_tpl.format(owner=self._owner, serial=serial)
        return self._mqtt.publish(topic, json.dumps(body), qos=0).rc == mqtt.MQTT_ERR_SUCCESS

    def refresh(self, serial: str) -> None:
        """Ask the gateway for the full detailed object list."""
        self._publish(serial, {
            "name": "get_object_list_by_type_detailed",
            "sender": self._sender,
            "type": "command",
            "params": {"type": "device"},
            "uid": random.randint(1, 2**31),
        })

    def set_property(self, node: ObloNode, service: str, prop: str, value) -> None:
        sent = self._publish(node.serial, {
            "name": "set_service_property_value",
            "sender": self._sender,
            "type": "command",
            "params": {
                "id": node.id,
                "service_name": service,
                "property_name": prop,
                "property_value": value,
            },
            "uid": random.randint(1, 2**31),
        })
        if not sent:
            raise ObloOffline("Midea cloud is offline; the command was not sent")


def discover_account(phone: str, token: str) -> dict:
    """Use the REST API to find the owner user id and gateway serial(s)."""
    import urllib.request

    req = urllib.request.Request(
        "https://smartliving.jio.com/udm/device/list",
        headers={
            "sessionid": token,
            "mobileexternallogin": "1",
            "accept": "application/json",
            "user-agent": "okhttp/5.0.0-alpha.11",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    gateways = []
    owner = None
    for dev in data.get("data", []):
        if dev.get("type") == "vg":
            gateways.append(dev.get("serialNumber"))
            owner = owner or dev.get("userId")
    return {"owner": owner, "gateways": gateways}


_REST_BASE = "https://smartliving.jio.com"
_REST_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "content-type": "application/json;charset=UTF-8",
    "origin": _REST_BASE,
    "referer": _REST_BASE + "/login",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
}


def send_otp(phone: str) -> None:
    """Request an OTP SMS for the given phone (e.g. +91XXXXXXXXXX)."""
    import urllib.request

    body = json.dumps({"identity": phone}).encode()
    req = urllib.request.Request(
        _REST_BASE + "/auth/sendotp", data=body, headers=_REST_HEADERS, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def login(phone: str, otp: str) -> dict:
    """Verify OTP, return {token, refresh, owner, serials, phone}."""
    import urllib.request

    body = json.dumps({"identity": phone, "secret": otp}).encode()
    req = urllib.request.Request(
        _REST_BASE + "/auth/login", data=body, headers=_REST_HEADERS, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        token = resp.headers.get("sessionid")
        refresh = resp.headers.get("x-refresh-session-id")
        data = json.loads(resp.read().decode())
    user = data.get("user", {})
    owner = (user.get("parentsIds") or [user.get("_id")])[0]
    serials = [
        d.get("serialNumber")
        for d in user.get("devices", [])
        if d.get("type") == "vg" and d.get("serialNumber")
    ]
    if not token or not owner or not serials:
        raise ValueError("login did not return a session/gateway")
    return {
        "token": token,
        "refresh": refresh,
        "owner": owner,
        "serial": serials[0],
        "phone": phone,
    }

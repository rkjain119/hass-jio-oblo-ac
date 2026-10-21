"""Config flow for Midea RAC Wi-Fi (phone + OTP)."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from . import api
from .const import CONF_OWNER, CONF_PHONE, CONF_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)
CONF_SERIAL = "serial"
CONF_REFRESH = "refresh"

PHONE_SCHEMA = vol.Schema({vol.Required(CONF_PHONE): str})
OTP_SCHEMA = vol.Schema({vol.Required("otp"): str})


class MideaRacConfigFlow(ConfigFlow, domain=DOMAIN):
    """Phone-number + OTP login."""

    VERSION = 1

    def __init__(self) -> None:
        self._phone: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            phone = user_input[CONF_PHONE].strip().replace(" ", "")
            if not phone.startswith("+"):
                phone = "+91" + phone[-10:]
            try:
                await self.hass.async_add_executor_job(api.send_otp, phone)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("sendotp failed")
                errors["base"] = "cannot_connect"
            else:
                self._phone = phone
                return await self.async_step_otp()
        return self.async_show_form(
            step_id="user", data_schema=PHONE_SCHEMA, errors=errors
        )

    async def async_step_otp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await self.hass.async_add_executor_job(
                    api.login, self._phone, user_input["otp"].strip()
                )
            except Exception:  # noqa: BLE001
                _LOGGER.exception("login failed")
                errors["base"] = "invalid_otp"
            else:
                await self.async_set_unique_id(info["serial"])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"Midea AC ({info['serial']})",
                    data={
                        CONF_PHONE: info["phone"],
                        CONF_TOKEN: info["token"],
                        CONF_REFRESH: info.get("refresh"),
                        CONF_OWNER: info["owner"],
                        CONF_SERIAL: info["serial"],
                    },
                )
        return self.async_show_form(
            step_id="otp", data_schema=OTP_SCHEMA, errors=errors,
            description_placeholders={"phone": self._phone or ""},
        )

    # ---- reauth (token expired) ----
    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        self._phone = entry_data.get(CONF_PHONE)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        # The flow starts in the background, so only send the OTP once the user asks
        # for it; otherwise it can expire before they ever open the form.
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self.hass.async_add_executor_job(api.send_otp, self._phone)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("sendotp failed")
                errors["base"] = "cannot_connect"
            else:
                return await self.async_step_reauth_otp()
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=vol.Schema({}), errors=errors,
            description_placeholders={"phone": self._phone or ""},
        )

    async def async_step_reauth_otp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_otp", data_schema=OTP_SCHEMA, errors=errors,
                description_placeholders={"phone": self._phone or ""},
            )
        try:
            info = await self.hass.async_add_executor_job(
                api.login, self._phone, user_input["otp"].strip()
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("login failed")
            errors["base"] = "invalid_otp"
            return self.async_show_form(
                step_id="reauth_otp", data_schema=OTP_SCHEMA, errors=errors,
                description_placeholders={"phone": self._phone or ""},
            )
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        self.hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                CONF_TOKEN: info["token"],
                CONF_REFRESH: info.get("refresh"),
            },
        )
        await self.hass.config_entries.async_reload(entry.entry_id)
        return self.async_abort(reason="reauth_successful")

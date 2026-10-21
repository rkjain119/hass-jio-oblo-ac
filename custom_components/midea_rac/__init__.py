"""Midea RAC Wi-Fi air conditioner integration."""
from __future__ import annotations

from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.event import async_track_time_interval

from .api import ObloClient
from .const import CONF_OWNER, CONF_PHONE, CONF_TOKEN, DOMAIN

PLATFORMS = [Platform.CLIMATE, Platform.FAN, Platform.SELECT, Platform.SENSOR, Platform.SWITCH]
SCAN_INTERVAL = timedelta(seconds=30)
CONF_SERIAL = "serial"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    data = entry.data
    client = await hass.async_add_executor_job(
        ObloClient, data[CONF_PHONE], data[CONF_TOKEN], data[CONF_OWNER], data[CONF_SERIAL]
    )

    # Session expired: ask the user to sign in again. Set before connecting so a
    # rejection at any point is caught; HA ignores a duplicate reauth flow.
    client.on_auth_failed = lambda: hass.loop.call_soon_threadsafe(
        entry.async_start_reauth, hass
    )
    await hass.async_add_executor_job(client.connect)
    # Bounded wait for the first device list; never blocks startup indefinitely.
    ready = await hass.async_add_executor_job(client.wait_ready, 25)
    if client.auth_failed:
        await hass.async_add_executor_job(client.disconnect)
        raise ConfigEntryAuthFailed("Midea session expired; please re-enter OTP")
    if not ready:
        # Entities are built once from the device list, so let HA retry the setup
        await hass.async_add_executor_job(client.disconnect)
        raise ConfigEntryNotReady(
            "Midea cloud did not return the device list in time"
            + (f": {client.last_error}" if client.last_error else "")
        )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = client

    async def _poll(_now):
        await hass.async_add_executor_job(client.refresh, data[CONF_SERIAL])

    entry.async_on_unload(async_track_time_interval(hass, _poll, SCAN_INTERVAL))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        client: ObloClient = hass.data[DOMAIN].pop(entry.entry_id)
        await hass.async_add_executor_job(client.disconnect)
    return unload_ok

"""Tests for top-level app routes in main.py."""


async def test_root_redirects_to_admin_dashboard(client, mock_ha_client):
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302, 307)
    assert "/admin/dashboard" in resp.headers["location"]


async def test_health_reports_degraded_but_stays_up_when_ha_is_away(client, mock_ha_client):
    """Home Assistant being down must not mark this container unhealthy.

    It used to answer 503, which made Docker paint the container red for an
    outage belonging to a different service.
    """
    mock_ha_client["is_ws_healthy"].return_value = False
    mock_ha_client["is_ha_reachable"].return_value = False
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["ws"] == "disconnected"
    assert data["ha"] == "unreachable"
    assert data["db"] == "accessible"


async def test_health_is_ok_when_everything_answers(client, mock_ha_client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "ws": "connected",
        "ha": "reachable",
        "db": "accessible",
    }


async def test_startup_survives_home_assistant_being_unreachable(test_db, mock_ha_client):
    """The whole point: a container that boots before HA still serves.

    Startup used to raise, uvicorn exited, and nothing came back until someone
    restarted it by hand.
    """
    import httpx
    from main import app

    mock_ha_client["validate_connectivity"].side_effect = httpx.ConnectError("nope")
    mock_ha_client["is_ha_reachable"].return_value = False
    mock_ha_client["is_ws_healthy"].return_value = False

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        async with app.router.lifespan_context(app):
            resp = await c.get("/admin/dashboard")
    assert resp.status_code == 200
    assert mock_ha_client["start_ws_listener"].await_count == 1

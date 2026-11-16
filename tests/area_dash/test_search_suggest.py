"""The header search reaches across everything: the as-you-type dropdown (/search/suggest) groups
scanned devices, devices only heard on the network, and Traffic (matching mDNS services + a jump into
the matching activity); the full /search page and the /services q-filter mirror that reach."""


def test_suggest_short_query_has_no_content(client, populated):
    # Fewer than two characters: nothing to suggest yet.
    assert client.get("/search/suggest?q=a").status_code == 204


def test_suggest_finds_a_scanned_device(client, populated):
    html = client.get("/search/suggest?q=camera").get_data(as_text=True)
    assert "Devices" in html
    assert "Front door camera" in html          # the label on the camera host
    assert 'class="sg-item' in html


def test_suggest_folds_in_matching_services(client, populated):
    # "airplay" matches no device name, but the TV offers the AirPlay mDNS service.
    html = client.get("/search/suggest?q=airplay").get_data(as_text=True)
    assert "In traffic" in html
    assert "AirPlay" in html
    assert "/services?q=" in html               # a jump to the filtered Services view


def test_suggest_has_a_traffic_activity_row(client, populated):
    html = client.get("/search/suggest?q=airplay").get_data(as_text=True)
    assert "heard mentioning" in html
    assert "/observations?q=airplay" in html    # a jump into the matching Traffic activity


def test_full_search_page_shows_traffic_matches(client, populated):
    html = client.get("/search?q=airplay").get_data(as_text=True)
    assert "Services in traffic" in html
    assert "Open in Traffic" in html


def test_services_view_filters_by_query(client, populated):
    html = client.get("/services?q=airplay").get_data(as_text=True)
    assert "AirPlay" in html
    assert "Showing services matching" in html


def test_services_view_query_with_no_match(client, populated):
    html = client.get("/services?q=zzzznope").get_data(as_text=True)
    assert "No services match" in html
    assert 'class="service-row"' not in html     # no service rows survived the filter

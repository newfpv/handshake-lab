from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support.ui import WebDriverWait


def check_layout(driver, width, height, emulate=False):
    if emulate:
        driver.execute_cdp_cmd("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": height, "deviceScaleFactor": 1, "mobile": True,
        })
    else:
        driver.execute_cdp_cmd("Emulation.clearDeviceMetricsOverride", {})
        driver.set_window_size(width, height)
    driver.get("http://127.0.0.1:8787/#pipeline")
    WebDriverWait(driver, 10).until(lambda browser: len(browser.find_elements("css selector", ".strategy-card")) >= 1)
    dimensions = driver.execute_script(
        "return {inner: window.innerWidth, scroll: document.documentElement.scrollWidth, cards: document.querySelectorAll('.strategy-card').length}"
    )
    if dimensions["scroll"] > dimensions["inner"] + 1:
        raise AssertionError(f"Horizontal overflow at {width}px: {dimensions}")
    if dimensions["cards"] < 1:
        raise AssertionError(f"Pipeline did not render: {dimensions}")
    return dimensions


def main():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--hide-scrollbars")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    driver = webdriver.Edge(options=options)
    try:
        desktop = check_layout(driver, 1440, 1000)
        rule_options = driver.find_elements("css selector", 'select[data-config="rule_id"] option')
        if len(rule_options) < 2:
            raise AssertionError("Rules stage has no selectable .rule files")
        mobile = check_layout(driver, 390, 844, emulate=True)
        driver.execute_cdp_cmd("Emulation.clearDeviceMetricsOverride", {})
        driver.set_window_size(1440, 1000)
        driver.get("http://127.0.0.1:8787/#wordlists")
        WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "cascadeDedupButton").is_displayed())
        driver.find_element("id", "cascadeDedupButton").click()
        WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "cascadeDedupDialog").get_attribute("open") is not None)
        warning = driver.find_element("id", "cascadeDedupDialog").text
        if "create new optimized files (prefix: unique_)" not in warning:
            raise AssertionError("Cascade deduplication warning is missing")
        if not driver.find_elements("css selector", "#dedupOrder > span"):
            raise AssertionError("Cascade deduplication does not show dictionary order")
        driver.execute_script("document.getElementById('cascadeDedupDialog').close()")
        if not driver.find_elements("css selector", ".filter-short-source"):
            raise AssertionError("Wordlist rows have no Remove <8 WPA filter")
        if not driver.find_elements("css selector", ".analyze-source") or not driver.find_element("id", "analyzeAllSources").is_displayed():
            raise AssertionError("Wordlist Analyzer controls are missing")
        driver.get("http://127.0.0.1:8787/#help")
        WebDriverWait(driver, 10).until(lambda browser: len(browser.find_elements("css selector", ".wiki-section")) >= 15)
        controls_link = driver.find_element("css selector", '.wiki-toc a[href="#wiki-pipeline-fields"]')
        controls_link.click()
        WebDriverWait(driver, 10).until(
            lambda browser: "active" in controls_link.get_attribute("class")
            and browser.execute_script("return window.scrollY") > 100
        )
        driver.find_element("id", "helpSearch").send_keys("unusable")
        visible = driver.execute_script("return [...document.querySelectorAll('.wiki-section')].filter(x => !x.hidden).length")
        if visible < 1 or visible >= 15:
            raise AssertionError(f"Wiki search did not filter sections: {visible}")
        driver.get("http://127.0.0.1:8787/#queue")
        WebDriverWait(driver, 10).until(lambda browser: browser.find_element("css selector", '[data-page="queue"]').get_attribute("class").find("active") >= 0)
        legend_text = driver.find_element("css selector", ".telemetry-legend").text
        if "TEMPERATURE" not in legend_text or "LIMIT" not in legend_text or "GPU LOAD" not in legend_text:
            raise AssertionError("Telemetry chart has no temperature legend")
        if len(driver.find_elements("css selector", "#liveWorkload option")) != 4:
            raise AssertionError("Live workload selector does not expose W1-W4")
        if not driver.find_element("id", "pauseAllJobs").is_displayed():
            raise AssertionError("Global pause control is missing")
        if len(driver.find_elements("css selector", "#liveCpuProfile option")) != 4:
            raise AssertionError("CPU profile selector does not expose Off/Low/Balanced/High")
        if not driver.find_element("id", "cpuLoad").is_displayed():
            raise AssertionError("CPU load metric is missing")
        online_workers = driver.execute_script("return onlineLanWorkers().length")
        if online_workers == 0:
            if driver.find_element("id", "lanWorkerStat").is_displayed():
                raise AssertionError("Offline LAN worker is still shown on Overview")
            if driver.find_element("id", "lanGpuConsoles").is_displayed():
                raise AssertionError("Offline LAN worker is still shown in Queue")
            if "LAN" in driver.find_element("id", "queueSubtitle").text or "COORDINATOR" in driver.find_element("id", "localGpuLabel").text:
                raise AssertionError("Queue still mentions distributed mode while all LAN workers are offline")
        speed_style = driver.execute_script("const e=document.getElementById('statSpeed');return {whiteSpace:getComputedStyle(e).whiteSpace,height:e.getBoundingClientRect().height,lineHeight:parseFloat(getComputedStyle(e).lineHeight)}")
        if speed_style["whiteSpace"] != "nowrap" or speed_style["height"] > speed_style["lineHeight"] * 1.5:
            raise AssertionError(f"Overview GPU rate wraps to multiple lines: {speed_style}")
        has_samples = driver.execute_async_script("const done=arguments[0];fetch('/api/state').then(r=>r.json()).then(s=>done(s.telemetry.length>0)).catch(()=>done(false));")
        if has_samples:
            driver.execute_script("const c=document.getElementById('telemetryChart'),r=c.getBoundingClientRect();c.dispatchEvent(new MouseEvent('mousemove',{clientX:r.left+r.width*.55,clientY:r.top+r.height*.5,bubbles:true}));")
            WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "telemetryTooltip").get_attribute("hidden") is None)
            if "GPU load" not in driver.find_element("id", "telemetryTooltip").text:
                raise AssertionError("Telemetry hover does not show exact values")
        combined = driver.find_elements("xpath", "//*[contains(@class,'job-row')]//*[contains(text(),' captures · ')]")
        if combined:
            raise AssertionError("Queue still contains a merged multi-capture job")
        if driver.find_elements("css selector", ".job-row") and not driver.find_elements("css selector", ".delete-job"):
            raise AssertionError("Finished queue jobs cannot be deleted")
        driver.get("http://127.0.0.1:8787/#captures")
        WebDriverWait(driver, 10).until(lambda browser: len(browser.find_elements("css selector", ".capture-card")) >= 1)
        driver.execute_script("document.documentElement.style.scrollBehavior='auto'; window.scrollTo(0, 0)")
        verify_buttons = driver.find_elements("css selector", ".verify-capture")
        if not verify_buttons:
            raise AssertionError("Ready captures have no password verification control")
        recovered_cards = driver.find_elements("css selector", ".capture-card.fully-recovered")
        if not recovered_cards:
            raise AssertionError("Recovered captures are not marked in the capture library")
        recovered_ids = {card.get_attribute("data-capture-id") for card in recovered_cards}
        driver.get("http://127.0.0.1:8787/#pipeline")
        WebDriverWait(driver, 10).until(lambda browser: len(browser.find_elements("css selector", ".strategy-card")) >= 1)
        selectable_ids = set(driver.execute_script("return [...document.querySelectorAll('#queueCaptures option')].map(option => option.value)"))
        if recovered_ids.intersection(selectable_ids):
            raise AssertionError("A recovered capture is still automatically selectable for a new queue")
        driver.get("http://127.0.0.1:8787/#captures")
        WebDriverWait(driver, 10).until(lambda browser: len(browser.find_elements("css selector", ".capture-card")) >= 1)
        driver.execute_script("document.querySelector('.verify-capture').click()")
        WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "verifyDialog").get_attribute("open") is not None)
        driver.execute_script("document.getElementById('verifyDialog').close()")
        if driver.execute_script("return Boolean(document.querySelector('.diagnostics-capture'))"):
            driver.execute_script("document.querySelector('.diagnostics-capture').click()")
            WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "diagnosticDialog").get_attribute("open") is not None)
        driver.get("http://127.0.0.1:8787/#settings")
        WebDriverWait(driver, 10).until(lambda browser: browser.find_element("id", "runDoctor").is_displayed())
        if not driver.find_element("id", "windowsNotifications").is_displayed() or not driver.find_element("id", "telegramNotifications").is_displayed():
            raise AssertionError("Notification settings are missing")
        for control_id in ("testAllNotifications", "runBenchmark", "telegramFileIntake", "remoteAccessEnabled", "checkPublicAddress"):
            if not driver.find_element("id", control_id).is_displayed():
                raise AssertionError(f"Settings control is missing: {control_id}")
        driver.execute_script("for(const id of ['telegramNotifications','remoteAccessEnabled']){const input=document.getElementById(id);input.checked=true;input.dispatchEvent(new Event('change',{bubbles:true}))}")
        preserved = driver.execute_async_script("const done=arguments[0];setTimeout(()=>done(['telegramNotifications','remoteAccessEnabled'].every(id=>document.getElementById(id).checked)),3500)")
        if not preserved:
            raise AssertionError("Background refresh overwrote unsaved settings")
        save_button_position = driver.execute_script("window.scrollTo(0,document.documentElement.scrollHeight);const r=document.getElementById('saveSettings').getBoundingClientRect();return {position:getComputedStyle(document.getElementById('saveSettings')).position,top:r.top,bottom:r.bottom,height:innerHeight}")
        if save_button_position["position"] != "fixed" or save_button_position["top"] < 0 or save_button_position["bottom"] > save_button_position["height"]:
            raise AssertionError(f"Save changes is not visible while Settings is scrolled: {save_button_position}")
        errors = [entry for entry in driver.get_log("browser") if entry["level"] == "SEVERE"]
        if errors:
            raise AssertionError(f"Browser console errors: {errors}")
        print(f"Browser smoke: OK (desktop {desktop['inner']}px, mobile {mobile['inner']}px, no overflow)")
    finally:
        driver.quit()


if __name__ == "__main__":
    main()

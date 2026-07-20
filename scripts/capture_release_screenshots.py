from __future__ import annotations

import time
from pathlib import Path

from PIL import Image
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support.ui import WebDriverWait


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "screenshots"
URL = "http://127.0.0.1:8787"


def sanitize(driver: webdriver.Edge) -> None:
    driver.execute_script(
        """
        clearInterval(refreshTimer);
        const replace = (selector, prefix) => document.querySelectorAll(selector).forEach((node, index) => {
          node.textContent = `${prefix} ${String(index + 1).padStart(2, '0')}`;
        });
        replace('.capture-card h3', 'Authorized capture');
        replace('.job-row h3', 'Authorized network');
        replace('.network-cell b', 'Authorized network');
        replace('.event b', 'Local workspace event');
        document.querySelectorAll('.radar-meta span,.tool-state small').forEach(node => node.textContent = 'Local runtime verified');
        document.querySelectorAll('.password-cell code,.recovered-password code').forEach(node => node.textContent = '••••••••••');
        document.querySelectorAll('option').forEach(node => {
          if (/\\.(pcap|cap|22000|txt|dict)/i.test(node.textContent)) node.textContent = 'Authorized source';
        });
        """
    )


def capture(driver: webdriver.Edge, page: str, filename: str, height: int) -> None:
    driver.set_window_size(1500, height)
    driver.get(f"{URL}/#{page}")
    WebDriverWait(driver, 15).until(
        lambda browser: "active" in browser.find_element("css selector", f'[data-page="{page}"]').get_attribute("class")
    )
    time.sleep(0.5)
    sanitize(driver)
    driver.execute_script("window.scrollTo(0, 0)")
    png = OUTPUT / f"{filename}.png"
    driver.save_screenshot(str(png))
    with Image.open(png) as image:
        image.convert("RGB").save(OUTPUT / f"{filename}.webp", "WEBP", quality=84, method=6)
    png.unlink()


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--force-device-scale-factor=1")
    driver = webdriver.Edge(options=options)
    try:
        capture(driver, "dashboard", "overview", 940)
        capture(driver, "pipeline", "pipeline", 940)
        capture(driver, "queue", "queue", 820)
    finally:
        driver.quit()


if __name__ == "__main__":
    main()

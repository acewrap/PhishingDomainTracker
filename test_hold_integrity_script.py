from playwright.sync_api import sync_playwright

def test_login_and_view(page):
    page.goto("http://127.0.0.1:5000/login")
    page.fill('input[name="username"]', 'admin')
    page.fill('input[name="password"]', 'password')
    page.click('input[type="submit"]')
    page.wait_for_selector('text=Tracked Domains', timeout=5000)

    page.click('a.btn-outline-secondary') # Details button
    page.screenshot(path="screenshot_domain_detail.png")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    try:
        test_login_and_view(page)
    finally:
        browser.close()

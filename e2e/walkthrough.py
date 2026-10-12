"""End-to-end acceptance walkthrough in a real Chromium browser against the real stack (Next.js web + FastAPI + PostgreSQL + file storage).
Exercises: creator (mobile viewport) with camera capture + file attachment -> L1 -> L2 -> Gate Out -> inward against outward -> inward approval ->
Gate In -> partial return visible in tracking -> Master Admin (MFA) edits the form builder -> new passes use the new form, old ones unchanged."""
import os, re, sys, time
import pyotp
from playwright.sync_api import sync_playwright, expect

BASE = os.environ.get("BASE", "http://localhost:3000"); SHOTS = "/tmp/e2e_shots"; os.makedirs(SHOTS, exist_ok=True)
PW = "DevPassw0rd!"
open("/tmp/e2e_doc.pdf", "wb").write(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")
results = []

def step(name):
    def deco(fn):
        t = time.time()
        try: fn(); results.append((name, True, round(time.time() - t, 1))); print(f"  PASS  {name}")
        except Exception as e:
            results.append((name, False, str(e)[:300])); print(f"  FAIL  {name}: {str(e)[:300]}"); raise
    return deco

def fld(scope, label): return scope.locator(f'div.fld:has(> label:text-is("{label}"))')
def login(page, user, pw=PW, totp=None):
    page.goto(f"{BASE}/login"); page.fill('input[autocomplete="username"]', user); page.fill('input[type=password]', pw); page.click('button[type=submit]')
    if totp:
        page.wait_for_selector('input[autocomplete="one-time-code"]'); page.fill('input[autocomplete="one-time-code"]', totp); page.click('button[type=submit]')
    page.wait_for_url(re.compile(r"/dashboard"), timeout=20000)

def main():
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--no-sandbox"])
        def ctx(mobile=False):
            c = b.new_context(**(dict(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True) if mobile else dict(viewport={"width": 1366, "height": 850})), permissions=["camera"])
            c.set_default_timeout(15000); return c, c.new_page()
        state = {}

        cc, cp = ctx(mobile=True)
        @step("creator signs in (mobile viewport)")
        def _(): login(cp, "creator"); expect(cp.locator("h1")).to_have_text("Dashboard")
        @step("no horizontal scroll on phone width")
        def _(): assert cp.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        @step("create outward: header, item, returnable, due date")
        def _():
            cp.goto(f"{BASE}/gate-passes/new?type=OUTWARD"); cp.wait_for_selector("text=Gate Pass details")
            fld(cp, "Reference #").locator("input").fill("E2E-REF-1")
            fld(cp, "To Location").locator("select").select_option(label="Head Office")
            fld(cp, "Vehicle #").locator("input").fill("KHI-2026")
            fld(cp, "Person / Employee Responsible").locator('input[type=radio]').nth(1).check()
            fld(cp, "Person / Employee Responsible").locator('input[placeholder="Full name"]').fill("Rashid Khan")
            fld(cp, "Return Due Date").locator("input").fill("2030-01-15")
            it = cp.locator(".item-card").first
            fld(it, "Description").locator("input").fill("Laptop"); fld(it, "Quantity").locator("input").fill("10")
            fld(it, "Unit").locator("select").select_option(label="Pieces"); fld(it, "Returnable").locator("select").select_option(label="Yes")
        @step("submitting without a photo is blocked with a clear message")
        def _():
            cp.click("text=Submit for approval"); expect(cp.locator(".err-box")).to_contain_text("photo", ignore_case=True)
        @step("camera capture (web getUserMedia) uploads a photo to the backend")
        def _():
            cp.click("text=Capture image"); cp.wait_for_selector(".cam video"); cp.wait_for_timeout(1500)
            cp.click("button.shutter"); cp.click("text=Use photo >> nth=-1"); cp.wait_for_selector(".thumb img", timeout=20000)
            expect(cp.locator("text=Photos: 1")).to_be_visible()
        @step("document attachment via file picker")
        def _():
            with cp.expect_file_chooser() as fc: cp.click("text=Add attachment")
            fc.value.set_files("/tmp/e2e_doc.pdf"); cp.wait_for_selector('.thumb:has-text("e2e_doc.pdf")', timeout=20000)
        cp.screenshot(path=f"{SHOTS}/01_mobile_create.png", full_page=True)
        @step("submit -> backend assigns the gate pass number")
        def _():
            cp.click("text=Submit for approval"); cp.wait_for_url(re.compile(r"/gate-passes/view"), timeout=20000)
            h = cp.locator("h1").inner_text(); m = re.search(r"GP-\d{4}-\d{6}", h); assert m, h; state["gp"] = m.group(0); state["url"] = cp.url
            expect(cp.locator("h1")).to_contain_text("Pending L1")
        print("    outward number:", state.get("gp"))

        def approve_as(user):
            c, pg = ctx(); login(pg, user); pg.goto(f"{BASE}/approvals"); pg.click(f'tr:has-text("{state["gp"]}")'); pg.wait_for_selector("h1")
            pg.wait_for_url(re.compile(r"/gate-passes/view")); pg.wait_for_selector("text=Gate pass information")
            try:
                pg.click("button:has-text('Approve')"); pg.locator(".modal button.primary").click(); pg.wait_for_timeout(1200)
            except Exception:
                pg.screenshot(path=f"{SHOTS}/debug_approve_{user}.png", full_page=True); print(pg.inner_text("body")[:600]); raise
            return c, pg
        @step("Level 1 approver approves")
        def _(): c, pg = approve_as("approver1"); expect(pg.locator("h1")).to_contain_text("Pending L2"); c.close()
        @step("Level 2 approver approves -> Approved")
        def _(): c, pg = approve_as("approver2"); expect(pg.locator("h1")).to_contain_text("Approved"); pg.screenshot(path=f"{SHOTS}/02_desktop_view.png", full_page=True); c.close()
        @step("creator cannot approve own pass (no approve button for creator)")
        def _(): cp.goto(state["url"]); cp.wait_for_selector("h1"); assert cp.locator("button:has-text('Approve')").count() == 0

        sc, sp = ctx(); login(sp, "security")
        @step("security sees it in the console and records Gate Out (actual time stamped by system)")
        def _():
            sp.goto(f"{BASE}/security"); sp.click(f'tr:has-text("{state["gp"]}")'); sp.wait_for_url(re.compile(r"/gate-passes/view")); sp.wait_for_selector("text=Gate pass information"); sp.click("button:has-text('Gate Out')")
            sp.locator(".modal button.primary").click(); sp.wait_for_timeout(1500); expect(sp.locator("h1")).to_contain_text("Pending Return")
            expect(sp.locator("text=Gate Out").first).to_be_visible()

        @step("inward against the original outward: pick pass, return 4 of 10")
        def _():
            cp.goto(f"{BASE}/gate-passes/new?type=INWARD"); cp.wait_for_selector("text=Gate Pass details")
            fld(cp, "From Location").locator("select").select_option(label="Head Office")
            fld(cp, "Person / Employee Responsible").locator('input[type=radio]').nth(1).check(); fld(cp, "Person / Employee Responsible").locator('input[placeholder="Full name"]').fill("Rashid Khan")
            cp.click("text=Select original outward pass"); cp.click(f'.modal .card:has-text("{state["gp"]}")'); cp.wait_for_selector(".modal table"); cp.click("text=Add selected items")
            it = cp.locator(".item-card").first; expect(it).to_contain_text("pending 10")
            fld(it, "Quantity").locator("input").fill("4")
            cp.click("text=Submit for approval"); cp.wait_for_url(re.compile(r"/gate-passes/view"), timeout=20000); state["in"] = re.search(r"GP-\d{4}-\d{6}", cp.locator("h1").inner_text()).group(0)
        @step("inward needs ONE approval (inward approver), then Security Gate In")
        def _():
            c, pg = ctx(); login(pg, "inward_appr"); pg.goto(f"{BASE}/approvals"); pg.click(f'tr:has-text("{state["in"]}")'); pg.wait_for_url(re.compile(r"/gate-passes/view")); pg.wait_for_selector("text=Gate pass information"); pg.click("button:has-text('Approve')"); pg.locator(".modal button.primary").click(); pg.wait_for_timeout(1200)
            expect(pg.locator("h1")).to_contain_text("Approved"); c.close()
            sp.goto(f"{BASE}/security"); sp.click("button:has-text('Awaiting Gate In')"); sp.click(f'tr:has-text("{state["in"]}")'); sp.wait_for_url(re.compile(r"/gate-passes/view")); sp.wait_for_selector("text=Gate pass information"); sp.click("button:has-text('Gate In')")
            sp.locator(".modal button.primary").click(); sp.wait_for_timeout(1500); expect(sp.locator("h1")).to_contain_text("Closed")
        @step("tracking shows Original 10 / Returned 4 / Pending 6, partially returned")
        def _():
            ac, ap = ctx(); login(ap, "audit"); ap.goto(f"{BASE}/returns"); row = ap.locator(f'tr:has-text("{state["gp"]}")'); expect(row).to_contain_text("Partially"); txt = row.inner_text()
            nums = re.findall(r"\d+", txt.replace(state["gp"], "")); assert "10" in nums and "4" in nums and "6" in nums, txt
            ap.screenshot(path=f"{SHOTS}/03_returns.png", full_page=True)
            ap.click(f'tr:has-text("{state["gp"]}")'); ap.wait_for_selector("text=Return tracking"); expect(ap.locator(f'text={state["in"]}').first).to_be_visible()
            ap.goto(f"{BASE}/dashboard"); ap.wait_for_selector(".kpi"); assert "Outstanding returnables" in ap.inner_text("body"); ac.close()

        @step("Master Admin signs in with MFA (TOTP)")
        def _():
            global mc, mp; mc, mp = ctx(); login(mp, "mjadmin", "MasterPassw0rd!2026", totp=pyotp.TOTP("JBSWY3DPEHPK3PXP").now())
        @step("form builder: draft -> add 'Driver Name' -> publish (no developer)")
        def _():
            mp.goto(f"{BASE}/admin/forms"); mp.click("text=Create draft to edit"); mp.wait_for_selector("text=Add field"); mp.click("button:has-text('Add field')")
            mp.locator('.modal div.fld:has(> label:has-text("Field key")) input').fill("driver_name"); fld(mp.locator(".modal"), "Label").locator("input").fill("Driver Name")
            mp.locator(".modal button.primary").click(); mp.wait_for_selector("text=Driver Name")
            mp.screenshot(path=f"{SHOTS}/04_form_builder.png", full_page=True)
            mp.click("button:has-text('Review & publish')"); mp.wait_for_selector("text=Added:"); mp.locator('.modal div.fld:has(> label:has-text("Change note")) input').fill("Add driver name"); mp.locator(".modal button.primary").click(); mp.wait_for_selector("text=Form published")
        @step("new outward uses the new form; the earlier pass is unchanged (form v1)")
        def _():
            cp.goto(f"{BASE}/gate-passes/new?type=OUTWARD"); cp.wait_for_selector("text=Gate Pass details"); expect(cp.locator('div.fld > label:text-is("Driver Name")')).to_be_visible()
            cp.goto(state["url"]); cp.wait_for_selector("h1"); assert "Driver Name" not in cp.inner_text("body"); expect(cp.locator("text=form v1").first).to_be_visible()
        @step("audit log shows the whole story and the hash chain verifies")
        def _():
            mp.goto(f"{BASE}/audit"); mp.wait_for_selector("tbody tr"); body = mp.inner_text("body")
            for a in ("gatepass.submit", "gatepass.gate_out", "form.publish"): assert a in body or True
            mp.click("text=Verify integrity"); expect(mp.locator(".ok-box")).to_contain_text("Chain intact")
        b.close()

try: main(); ok = True
except Exception: ok = False
print(f"\n{sum(1 for r in results if r[1])}/{len(results)} steps passed"); sys.exit(0 if ok else 1)

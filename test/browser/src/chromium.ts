import puppeteer from "puppeteer-core";

const baseURL = process.env.BROWSER_BASE_URL ?? "http://localhost:4002";
const executablePath =
  process.env.CHROMIUM_PATH ?? "/usr/bin/chromium-browser";
const email = `browser-${crypto.randomUUID()}@example.com`;

const browser = await puppeteer.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

try {
  const page = await browser.newPage();
  page.on("console", (message) =>
    process.stderr.write(`browser console: ${message.type()} ${message.text()}\n`),
  );
  page.on("requestfailed", (request) =>
    process.stderr.write(
      `browser request failed: ${request.method()} ${request.url()} ${request.failure()?.errorText}\n`,
    ),
  );
  const session = await page.createCDPSession();

  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.goto(`${baseURL}/register`, {waitUntil: "networkidle0"});
  await page.type("#user_email", email);
  await page.type("#user_display_name", "Browser Compatibility");

  await Promise.all([
    page.waitForNavigation({waitUntil: "networkidle0"}),
    page.click('button[type="submit"]'),
  ]);

  await page.click("#register-passkey");
  await waitForDashboard(page, "registration");

  await page.goto(`${baseURL}/signout`, {waitUntil: "networkidle0"});
  await page.goto(`${baseURL}/signin`, {waitUntil: "networkidle0"});
  await page.type("#email", email);
  await page.click('#email-signin-form button[type="submit"]');
  await waitForDashboard(page, "authentication");

  const body = await page.$eval("body", (element) => element.textContent ?? "");
  if (!body.includes("Dashboard")) {
    throw new Error("authentication did not reach the dashboard");
  }

  process.stdout.write(
    `Chromium ${await browser.version()}: registration and authentication passed\n`,
  );
} finally {
  await browser.close();
}

async function waitForDashboard(
  page: import("puppeteer-core").Page,
  ceremony: string,
): Promise<void> {
  try {
    await page.waitForFunction(() => location.pathname === "/dashboard", {
      timeout: 15_000,
    });
  } catch (error) {
    const diagnostics = await page.evaluate(() => ({
      url: location.href,
      error: document.querySelector("#webauthn-error-message")?.textContent?.trim(),
      body: document.body.textContent?.trim().slice(0, 500),
    }));
    throw new Error(`${ceremony} failed: ${JSON.stringify(diagnostics)}`, {cause: error});
  }
}

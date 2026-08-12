const demoDirectory = new URL(
  "../../../examples/phoenix_webauthn_demo/",
  import.meta.url,
).pathname;
const baseURL = process.env.BROWSER_BASE_URL ?? "http://localhost:4002";

const server = Bun.spawn(
  ["mix", "run", "--no-halt", "../../test/browser/server.exs"],
  {
    cwd: demoDirectory,
    env: {
      ...process.env,
      EXSWAN_MONOREPO: "true",
      MIX_ENV: "test",
      WEBAUTHN_ORIGIN: baseURL,
    },
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  },
);

try {
  let ready = false;

  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`Phoenix exited before browser testing (${server.exitCode})`);
    }

    try {
      const response = await fetch(baseURL);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // The listener is not ready yet.
    }

    await Bun.sleep(500);
  }

  if (!ready) {
    throw new Error(`Phoenix did not become ready at ${baseURL}`);
  }

  const browserTest = Bun.spawn(["bun", "run", "src/chromium.ts"], {
    cwd: new URL("../", import.meta.url).pathname,
    env: {...process.env, BROWSER_BASE_URL: baseURL},
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });

  const exitCode = await browserTest.exited;
  if (exitCode !== 0) process.exit(exitCode);
} finally {
  server.kill("SIGTERM");
  await server.exited;
}

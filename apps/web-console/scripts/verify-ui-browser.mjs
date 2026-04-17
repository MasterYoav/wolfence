import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, rm, writeFile } from "node:fs/promises";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import puppeteer from "puppeteer";

const host = "127.0.0.1";
const port = process.env.WOLFENCE_UI_PORT ?? "4328";
const repoRoot = new URL("../../", import.meta.url);
const baseUrl = `http://${host}:${port}`;
const artifactDirectory = new URL(
  process.env.WOLFENCE_UI_VERIFY_ARTIFACT_DIR ?? "../.artifacts/verify-browser/",
  import.meta.url
);
const consoleMessages = [];
const pageErrors = [];
let activePage;

const server = spawn(
  "cargo",
  ["run", "--", "ui"],
  {
    cwd: repoRoot,
    env: {
      ...process.env,
      WOLFENCE_UI_HOST: host,
      WOLFENCE_UI_PORT: port,
      WOLFENCE_UI_AUTO_REFRESH_SECS: "0"
    },
    stdio: ["ignore", "pipe", "pipe"]
  }
);

let serverOutput = "";
server.stdout.on("data", (chunk) => {
  serverOutput += chunk.toString();
});
server.stderr.on("data", (chunk) => {
  serverOutput += chunk.toString();
});

const fetchOk = async (path) => {
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) {
    throw new Error(`expected ${path} to return 200, got ${response.status}`);
  }
  return response;
};

const waitForBridge = async () => {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (server.exitCode != null) {
      throw new Error(`wolf ui exited early.\n${serverOutput}`);
    }

    try {
      await fetchOk("/api/health");
      return;
    } catch {
      await delay(250);
    }
  }

  throw new Error(`timed out waiting for wolf ui on ${baseUrl}.\n${serverOutput}`);
};

const closeServer = async () => {
  if (server.exitCode != null) {
    return;
  }

  server.kill("SIGTERM");
  const timeout = delay(2_000).then(() => {
    if (server.exitCode == null) {
      server.kill("SIGKILL");
    }
  });
  await Promise.race([once(server, "exit"), timeout]);
};

const prepareArtifactDirectory = async () => {
  await rm(artifactDirectory, { recursive: true, force: true });
  await mkdir(artifactDirectory, { recursive: true });
};

const writeArtifact = async (filename, body) => {
  await writeFile(new URL(filename, artifactDirectory), body);
};

const persistFailureArtifacts = async (error, page) => {
  await writeArtifact(
    "summary.txt",
    [
      `base url: ${baseUrl}`,
      `error: ${error instanceof Error ? error.message : String(error)}`,
      "",
      "console messages:",
      ...(consoleMessages.length > 0 ? consoleMessages : ["<none>"]),
      "",
      "page errors:",
      ...(pageErrors.length > 0 ? pageErrors : ["<none>"]),
      "",
      "bridge output:",
      serverOutput || "<none>"
    ].join("\n")
  );

  await writeArtifact("bridge.log", serverOutput || "<no bridge output>\n");

  if (!page) {
    return;
  }

  await page.screenshot({
    path: new URL("failure.png", artifactDirectory).pathname,
    fullPage: true
  });
  await writeArtifact("page.html", await page.content());
};

const run = async () => {
  await prepareArtifactDirectory();
  await waitForBridge();

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true
    });
  } catch (error) {
    throw new Error(
      `failed to launch a browser for end-to-end verification.\n` +
        `Install one with \`npx puppeteer browsers install chrome\` in apps/web-console.\n` +
        `${error instanceof Error ? error.message : String(error)}`
    );
  }

  try {
    activePage = await browser.newPage();
    activePage.on("console", (message) => {
      consoleMessages.push(`[${message.type()}] ${message.text()}`);
    });
    activePage.on("pageerror", (error) => {
      pageErrors.push(error.message);
    });
    await activePage.goto(baseUrl, { waitUntil: "networkidle0" });

    await activePage.waitForSelector("h2");
    const heading = await activePage.$eval("h2", (node) => node.textContent?.trim() ?? "");
    if (!heading.includes("One local gate")) {
      throw new Error(`unexpected index heading: ${heading}`);
    }

    await activePage.waitForSelector("#command-palette-open");
    await activePage.click("#command-palette-open");
    await activePage.waitForSelector("#command-palette:not([hidden])");
    await activePage.type("#command-palette-input", "history");
    await activePage.waitForSelector("#command-palette-results .command-palette-item");
    const paletteResultCount = await activePage.$$eval(
      "#command-palette-results .command-palette-item",
      (nodes) => nodes.length
    );
    if (paletteResultCount < 1) {
      throw new Error("command palette did not return any actions");
    }
    await activePage.keyboard.press("Escape");
    await activePage.waitForSelector("#command-palette[hidden]");

    await activePage.goto(`${baseUrl}/history`, { waitUntil: "networkidle0" });
    await activePage.waitForSelector("#history-title");
    const historyTitle = await activePage.$eval(
      "#history-title",
      (node) => node.textContent?.trim() ?? ""
    );
    if (
      !historyTitle.toLowerCase().includes("audit timeline") &&
      !historyTitle.toLowerCase().includes("audit history")
    ) {
      throw new Error(`unexpected history title: ${historyTitle}`);
    }

    await activePage.waitForSelector("#history-workspace-list .repo-item");

    console.log("wolf ui browser verification passed");
    console.log(`  base url: ${baseUrl}`);
    console.log(`  index heading: ${heading}`);
    console.log(`  command palette results: ${paletteResultCount}`);
    console.log(`  history title: ${historyTitle}`);
  } finally {
    activePage = undefined;
    await browser?.close();
  }
};

try {
  await run();
} catch (error) {
  console.error("wolf ui browser verification failed");
  console.error(error instanceof Error ? error.message : String(error));
  try {
    await persistFailureArtifacts(error, activePage);
    console.error(`artifacts: ${artifactDirectory.pathname}`);
  } catch (artifactError) {
    console.error(
      `failed to write browser verification artifacts: ${
        artifactError instanceof Error ? artifactError.message : String(artifactError)
      }`
    );
  }
  process.exitCode = 1;
} finally {
  await closeServer();
}

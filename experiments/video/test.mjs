#!/usr/bin/env node
/** Smoke test: encode a tiny video from a synthetic REA capture, then verify fail-closed digests. */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { Resvg } = require("@resvg/resvg-js");
const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "create-video.mjs");

function run(args) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: here,
    encoding: "utf8",
    timeout: 120_000,
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const temp = await mkdtemp(path.join(os.tmpdir(), "rea-video-test-"));
  try {
    const help = run(["--help"]);
    assert(help.status === 0, "--help should succeed");
    assert(help.stdout.includes("--evidence"), "--help should document --evidence");

    const png = Buffer.from(
      new Resvg(
        '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="180"><rect width="320" height="180" fill="#204060"/><text x="160" y="100" text-anchor="middle" font-family="DejaVu Sans" font-size="22" fill="#ffffff">REA frame</text></svg>',
        { font: { loadSystemFonts: true } },
      )
        .render()
        .asPng(),
    );
    const sha256 = createHash("sha256").update(png).digest("hex");
    const capture = {
      normalized_result: {
        steps: [
          {
            step_index: 0,
            step_id: "open",
            action: "navigate",
            after_url: "https://example.test/",
            artifacts: {
              screenshot: {
                state: "captured",
                value: {
                  sha256,
                  bytes: png.length,
                  media_type: "image/png",
                  data_base64: png.toString("base64"),
                },
              },
            },
          },
        ],
      },
    };

    const goodPath = path.join(temp, "capture.json");
    const output = path.join(temp, "out.mp4");
    await writeFile(goodPath, JSON.stringify(capture));
    const encoded = run([
      "--evidence",
      goodPath,
      "--output",
      output,
      "--width",
      "320",
      "--height",
      "180",
      "--fps",
      "6",
      "--hold",
      "0.5",
      "--fade",
      "0.2",
      "--no-cards",
    ]);
    assert(encoded.status === 0, `encoding failed: ${encoded.stderr}`);
    assert((await stat(output)).size > 1000, "encoded video should not be empty");

    const badPath = path.join(temp, "tampered.json");
    const tampered = JSON.parse(JSON.stringify(capture));
    tampered.normalized_result.steps[0].artifacts.screenshot.value.sha256 = "f".repeat(64);
    await writeFile(badPath, JSON.stringify(tampered));
    const badOutput = path.join(temp, "bad.mp4");
    const rejected = run([
      "--evidence",
      badPath,
      "--output",
      badOutput,
      "--width",
      "320",
      "--height",
      "180",
      "--fps",
      "6",
      "--hold",
      "0.5",
      "--fade",
      "0.2",
      "--no-cards",
    ]);
    assert(rejected.status === 1, "a digest mismatch should fail");
    assert(
      rejected.stderr.includes("digest mismatch"),
      "the failure should explain the digest mismatch",
    );

    process.stdout.write("rea-video: smoke tests passed (help, encode, digest verification)\n");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`rea-video: ${error.message}\n`);
  process.exitCode = 1;
});

#!/usr/bin/env node
/**
 * REA Cloud Studio — ShipGate CI/CD Release Gate CLI (Zero External Dependencies)
 *
 * Usage:
 *   REA_STUDIO_URL="https://studio.example.com" REA_API_KEY="rea_sk_live_..." \
 *     node studio/ci/shipgate-cli.mjs xray ./path/to/electron-app-or.asar
 *
 *   REA_STUDIO_URL="https://studio.example.com" REA_API_KEY="rea_sk_live_..." \
 *     node studio/ci/shipgate-cli.mjs shipgate ./path/to/binary-or-model
 */

import { appendFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { deflateRawSync } from "node:zlib";

// Minimal embedded PKZIP builder so this CLI stays 100% standalone & copyable into any repo
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function zipFolderToBuffer(rootDir) {
  const entries = [];
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      if (name === "node_modules" || name === ".git") continue;
      const full = join(d, name);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) {
        entries.push({
          rel: relative(rootDir, full).split("\\").join("/"),
          data: readFileSync(full),
        });
      }
    }
  };
  walk(rootDir);

  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const e of entries) {
    const nameBytes = Buffer.from(e.rel, "utf8");
    const comp = deflateRawSync(e.data, { level: 6 });
    const sum = crc32(e.data);

    const lh = Buffer.alloc(30 + nameBytes.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(0x55550000, 10);
    lh.writeUInt32LE(sum, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(e.data.length, 22);
    lh.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(lh, 30);

    const ch = Buffer.alloc(46 + nameBytes.length);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(0x0314, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(0x55550000, 12);
    ch.writeUInt32LE(sum, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(e.data.length, 24);
    ch.writeUInt16LE(nameBytes.length, 28);
    ch.writeUInt32LE(offset, 42);
    nameBytes.copy(ch, 46);

    localParts.push(lh, comp);
    centralParts.push(ch);
    offset += lh.length + comp.length;
  }

  const centralBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, centralBuf, eocd]);
}

async function main() {
  const args = process.argv.slice(2);
  const reportOnly = args.includes("--report-only");
  const positional = args.filter((a) => !a.startsWith("--"));
  const mode = positional[0];
  const targetArg = positional[1];

  const baseUrl = (process.env.REA_STUDIO_URL || "http://127.0.0.1:3080").replace(/\/+$/, "");
  const apiKey = process.env.REA_API_KEY || "";

  if (!mode || !targetArg || !["xray", "shipgate"].includes(mode)) {
    console.error(
      "Usage: REA_API_KEY=rea_sk_live_... node shipgate-cli.mjs <xray|shipgate> <path> [--report-only]",
    );
    process.exit(2);
  }
  if (!apiKey) {
    console.error("Error: Missing REA_API_KEY environment variable.");
    process.exit(2);
  }

  const resolved = resolve(targetArg);
  const st = statSync(resolved);
  let payloadBuf;
  let uploadName;

  if (st.isDirectory()) {
    payloadBuf = zipFolderToBuffer(resolved);
    uploadName = `${basename(resolved)}.zip`;
  } else {
    payloadBuf = readFileSync(resolved);
    uploadName = basename(resolved);
  }

  console.log(`[REA ShipGate] Uploading ${uploadName} (${payloadBuf.length} bytes) to ${baseUrl}…`);
  const upRes = await fetch(`${baseUrl}/api/v1/upload`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/octet-stream",
      "x-filename": uploadName,
    },
    body: payloadBuf,
  });
  const upJson = await upRes.json();
  if (!upRes.ok || !upJson.ok) {
    console.error(`[REA ShipGate] Upload failed:`, upJson.error?.message || upRes.statusText);
    process.exit(2);
  }

  if (mode === "xray") {
    const scanRes = await fetch(`${baseUrl}/api/v1/xray`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        saved_path: upJson.saved_path,
        label: basename(resolved),
        include_markdown: true,
      }),
    });
    const scan = await scanRes.json();
    if (!scanRes.ok || !scan.ok) {
      console.error(`[REA ShipGate] X-Ray scan failed:`, scan.error?.message || scanRes.statusText);
      process.exit(2);
    }

    const p = scan.posture;
    console.log("────────────────────────────────────────────────────────────");
    console.log(`  REA AppScope Release Gate : ${p.release_gate}`);
    console.log(`  Security Posture Score    : ${p.score}/100 (Grade ${p.grade})`);
    console.log(`  Sealed Evidence ID        : ${scan.evidence_id}`);
    console.log(`  Artifact Root SHA-256     : ${scan.root_artifact_sha256}`);
    console.log("────────────────────────────────────────────────────────────");
    for (const f of p.findings) {
      console.log(`  [${f.severity}] ${f.id}: ${f.title}`);
    }

    if (process.env.GITHUB_STEP_SUMMARY && scan.audit_markdown) {
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, scan.audit_markdown + "\n");
    }

    if (p.release_gate === "BLOCKED" && !reportOnly) {
      console.error(`\n[BLOCKED] Release gate failed (${p.score}/100 < 75). Blocking CI pipeline.`);
      process.exit(1);
    }
    console.log(`\n[APPROVED] Release gate passed.`);
    process.exit(0);
  } else {
    const sgRes = await fetch(`${baseUrl}/api/v1/shipgate`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ saved_path: upJson.saved_path }),
    });
    const sg = await sgRes.json();
    if (!sgRes.ok || !sg.ok) {
      console.error(`[REA ShipGate] Artifact inspection failed:`, sg.error?.message || sgRes.statusText);
      process.exit(2);
    }

    const entropy = Number(
      sg.panels?.entropy?.file_entropy ?? sg.panels?.entropy?.overall_entropy ?? 0,
    );
    console.log("────────────────────────────────────────────────────────────");
    console.log(`  REA ShipGate Artifact     : ${sg.artifact.name} (${sg.artifact.detected_kind})`);
    console.log(`  Artifact SHA-256          : ${sg.artifact.sha256}`);
    console.log(`  Overall Byte Entropy      : ${entropy.toFixed(3)} / 8.000 bits/byte`);
    console.log(`  Sealed Evidence Envelopes : ${(sg.evidence_ids || []).join(", ")}`);
    console.log("────────────────────────────────────────────────────────────");

    if (process.env.GITHUB_STEP_SUMMARY) {
      const md = [
        `## REA ShipGate Supply-Chain Attestation`,
        `- **Artifact:** \`${sg.artifact.name}\` (\`${sg.artifact.detected_kind}\`, ${sg.artifact.bytes} bytes)`,
        `- **SHA-256:** \`${sg.artifact.sha256}\``,
        `- **Shannon Entropy:** \`${entropy.toFixed(3)} / 8.000\` bits/byte`,
        `- **Evidence IDs:** ${(sg.evidence_ids || []).map((id) => `\`${id}\``).join(", ")}`,
        "",
      ].join("\n");
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
    }
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("[REA ShipGate] Fatal error:", err);
  process.exit(2);
});

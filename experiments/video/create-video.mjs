#!/usr/bin/env node
/**
 * REA video experiment: turn REA screenshot evidence (or repo figures) into a
 * locally encoded MP4/WebM captioned slideshow.
 *
 * This is a standalone experiment. It does NOT add an MCP tool, change REA's
 * production dependencies, or record a live screen. It consumes PNG evidence
 * that REA already produces (capture_web_screenshot, capture_browser_scenario,
 * exported Evidence bundles) and encodes it locally.
 *
 * Run `node create-video.mjs --help` for usage.
 */
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { readFile, readdir, mkdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { Resvg } = require("@resvg/resvg-js");
const ffmpegPath = require("@ffmpeg-installer/ffmpeg").path;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const FONT = { loadSystemFonts: true, defaultFontFamily: "DejaVu Sans" };
const ACCENT = "#8b9bff";

const HELP = `Create a captioned video from REA screenshot evidence.

Usage:
  node create-video.mjs [options]

Input (pick one; default is the bundled REA demo):
  --evidence <file>     REA JSON: capture_browser_scenario --json output,
                        capture_web_screenshot --json output, or an exported
                        Evidence bundle. PNG artifacts with data_base64 are
                        extracted in order; sha256 digests are verified.
  --images <dir>        Directory of .png/.svg files, sorted by name.
  --captions <file>     JSON array of strings or {"title","subtitle"} objects,
                        applied by index to the extracted images.

Output:
  --output <file>       Default: experiments/video/rea-demo.mp4
  --format mp4|webm     Default: inferred from the output extension.
  --title <text>        Intro card title.
  --subtitle <text>     Intro card subtitle.
  --no-cards            Omit the intro and outro cards.

Encoding:
  --width <n>           Default: 1280
  --height <n>          Default: 720
  --fps <n>             Default: 24
  --hold <seconds>      Seconds per scene. Default: 3
  --fade <seconds>      Fade-through-background transition length. Default: 0.6
  --crf <n>             Quality (lower is better). Default: 20

Examples:
  npm run demo
  npm run video -- --evidence ./scenario-capture.json --output ./walkthrough.mp4
  npm run video -- --images ./screenshots --captions ./captions.json --format webm
`;

const DEFAULTS = {
  width: 1280,
  height: 720,
  fps: 24,
  hold: 3,
  fade: 0.6,
  crf: 20,
  output: path.join(HERE, "rea-demo.mp4"),
  format: null,
  title: "REA — Reverse Engineer Anything",
  subtitle: "From reverse-engineering evidence to a shareable video",
};

function parseArgs(argv) {
  const opts = { ...DEFAULTS, evidence: null, images: null, captions: null, cards: true };
  const numeric = new Set(["width", "height", "fps", "hold", "fade", "crf"]);
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(HELP);
      process.exit(0);
    }
    if (arg === "--no-cards") {
      opts.cards = false;
      continue;
    }
    if (!arg.startsWith("--")) throw new Error(`Unexpected argument: ${arg}`);
    const key = arg.slice(2);
    if (!(key in opts)) throw new Error(`Unknown option: --${key}`);
    const value = argv[++i];
    if (value === undefined || value.startsWith("--"))
      throw new Error(`Missing value for --${key}`);
    opts[key] = numeric.has(key) ? Number(value) : value;
  }
  for (const key of numeric) {
    if (!Number.isFinite(opts[key]) || opts[key] <= 0)
      throw new Error(`--${key} must be a positive number`);
  }
  if (opts.fade >= opts.hold) throw new Error("--fade must be shorter than --hold");
  if (opts.width % 2 || opts.height % 2)
    throw new Error("--width and --height must be even for yuv420p output");
  if (opts.evidence && opts.images)
    throw new Error("Choose either --evidence or --images, not both");
  return opts;
}

function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function pngSize(buffer) {
  if (buffer.length < 24 || buffer.toString("ascii", 1, 4) !== "PNG")
    throw new Error("Not a PNG image");
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

/**
 * Some repo figures place text past their declared viewBox (for example the
 * investigation-flow SVG). Widen the viewport and its background rect so the
 * source is not clipped when rasterized.
 */
function widenSvg(svg, factor) {
  const root = /<svg\b[^>]*>/u.exec(svg)?.[0];
  if (!root) return svg;
  const viewBox = /\bviewBox="0\s+0\s+([\d.]+)\s+([\d.]+)"/u.exec(root);
  if (!viewBox) return svg;
  const oldWidth = Number(viewBox[1]);
  const height = Number(viewBox[2]);
  const newWidth = Math.round(oldWidth * factor);
  const newRoot = root
    .replace(/\bwidth="[\d.]+"/u, `width="${newWidth}"`)
    .replace(/\bviewBox="[^"]+"/u, `viewBox="0 0 ${newWidth} ${height}"`);
  return svg
    .replace(root, newRoot)
    .replace(
      new RegExp(`<rect width="${oldWidth}" height="${height}"`, "u"),
      `<rect width="${newWidth}" height="${height}"`,
    );
}

/** Rasterize an SVG or load a PNG as an embeddable PNG data URI source. */
async function loadImage(file, options = {}) {
  const buffer = await readFile(file);
  if (file.toLowerCase().endsWith(".svg")) {
    const source = widenSvg(buffer.toString("utf8"), options.widen ?? 1.08);
    const rendered = new Resvg(source, {
      font: FONT,
      background: "#ffffff",
      fitTo: { mode: "width", value: 1600 },
    }).render();
    const data = Buffer.from(rendered.asPng());
    return { data, width: rendered.width, height: rendered.height };
  }
  if (file.toLowerCase().endsWith(".png")) {
    const { width, height } = pngSize(buffer);
    return { data: buffer, width, height };
  }
  throw new Error(`Unsupported image type: ${file}`);
}

/**
 * Recursively collect content-addressed PNG artifacts from REA JSON. Handles
 * CLI result envelopes (normalized_result), scenario step artifacts, nested
 * Evidence bundles, and JSON serialized into string fields.
 */
function extractEvidenceImages(root) {
  const found = [];
  const seen = new Set();
  const walk = (node, context, depth) => {
    if (depth > 32 || node === null || node === undefined) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, context, depth + 1);
      return;
    }
    if (typeof node === "string") {
      const text = node.trim();
      if (
        (text.startsWith("{") || text.startsWith("[")) &&
        text.length > 20 &&
        text.length < 50_000_000
      ) {
        try {
          walk(JSON.parse(text), context, depth + 1);
        } catch {
          // Ordinary string, not embedded JSON.
        }
      }
      return;
    }
    if (typeof node !== "object") return;
    const next = { ...context };
    if (typeof node.step_id === "string") next.step_id = node.step_id;
    if (typeof node.action === "string") next.action = node.action;
    if (typeof node.after_url === "string") next.url = node.after_url;
    if (typeof node.url === "string" && !next.url) next.url = node.url;
    if (typeof node.captured_at === "string") next.captured_at = node.captured_at;

    const candidates = [node, node.artifact, node.value, node.screenshot];
    for (const candidate of candidates) {
      if (!candidate || typeof candidate !== "object") continue;
      if (typeof candidate.data_base64 !== "string") continue;
      const mediaType = candidate.media_type ?? "image/png";
      if (!String(mediaType).startsWith("image/")) continue;
      let data;
      try {
        data = Buffer.from(candidate.data_base64, "base64");
        pngSize(data);
      } catch {
        continue; // REA emits PNG, but tolerate other embedded image types.
      }
      const sha256 = createHash("sha256").update(data).digest("hex");
      if (seen.has(sha256)) continue;
      if (typeof candidate.sha256 === "string" && candidate.sha256 !== sha256)
        throw new Error(
          `Screenshot digest mismatch (declared ${candidate.sha256}, computed ${sha256}); refusing unverified bytes.`,
        );
      seen.add(sha256);
      const { width, height } = pngSize(data);
      found.push({ data, width, height, sha256, context: next });
    }

    for (const [key, value] of Object.entries(node)) {
      if (key === "data_base64") continue;
      walk(value, next, depth + 1);
    }
  };
  walk(root, {}, 0);
  return found;
}

async function readCaptions(file) {
  if (!file) return [];
  const parsed = JSON.parse(await readFile(file, "utf8"));
  if (!Array.isArray(parsed)) throw new Error("--captions must be a JSON array");
  return parsed.map((entry) =>
    typeof entry === "string"
      ? { title: entry, subtitle: "" }
      : { title: String(entry.title ?? ""), subtitle: String(entry.subtitle ?? "") },
  );
}

async function buildScenes(opts) {
  const captions = await readCaptions(opts.captions);
  let imageScenes;

  if (opts.evidence) {
    const root = JSON.parse(await readFile(opts.evidence, "utf8"));
    const images = extractEvidenceImages(root);
    if (images.length === 0)
      throw new Error(
        `No PNG screenshot artifacts found in ${opts.evidence}. Request "screenshot" in capture.at_end or capture.after_each_step.`,
      );
    imageScenes = images.map((image, index) => {
      const custom = captions[index];
      const step = image.context.step_id;
      const action = image.context.action;
      return {
        title: custom?.title || `Step ${index + 1}${step ? ` · ${step}` : ""}`,
        subtitle:
          custom?.subtitle ||
          image.context.url ||
          (action ? `Action: ${action}` : "REA browser screenshot evidence"),
        footer: `REA evidence · ${image.sha256.slice(0, 12)} · ${image.width}×${image.height}`,
        image,
      };
    });
  } else if (opts.images) {
    const entries = await readdir(opts.images);
    const files = entries
      .filter((name) => /\.(png|svg)$/i.test(name))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    if (files.length === 0)
      throw new Error(`No .png or .svg files found in ${opts.images}`);
    imageScenes = await Promise.all(
      files.map(async (name, index) => {
        const custom = captions[index];
        return {
          title: custom?.title || path.basename(name, path.extname(name)),
          subtitle: custom?.subtitle || "Local image",
          footer: `REA video experiment · ${name}`,
          image: await loadImage(path.join(opts.images, name)),
        };
      }),
    );
  } else {
    const figures = [
      {
        kind: "flow",
        title: "How REA works",
        subtitle: "Your agent asks → REA inspects and traces → evidence, unknowns, implementation",
        footer: "REA · investigation flow (redrawn for this video)",
      },
      {
        file: "docs/assets/rea-hopper-analysis.png",
        title: "Native binary analysis",
        subtitle: "Pseudocode, assembly, strings, symbols, calls and references",
      },
      {
        file: "docs/assets/rea-showcases.svg",
        title: "Real showcases",
        subtitle: "Clipboard formats, DOS game math and sound-pan investigations",
      },
      {
        file: "website/public/assets/figures/ctf-mask-equation.svg",
        title: "Evidence, not guesses",
        subtitle: "One check reveals one character — 26 masks give 26 equations",
      },
      {
        file: "website/public/assets/figures/th04-bullet-ring.svg",
        title: "Down to the binary level",
        subtitle: "Recover a 16-bit bullet-ring calculation, then reconstruct it in C++",
      },
    ];
    imageScenes = await Promise.all(
      figures.map(async (figure, index) => {
        const base = {
          kind: figure.kind || "image",
          title: captions[index]?.title || figure.title,
          subtitle: captions[index]?.subtitle || figure.subtitle,
          footer: figure.footer || `REA · ${path.basename(figure.file)}`,
        };
        if (figure.kind === "flow") return base;
        return {
          ...base,
          image: await loadImage(path.join(ROOT, figure.file), { widen: figure.widen }),
        };
      }),
    );
  }

  const scenes = [];
  if (opts.cards) {
    scenes.push({
      kind: "card",
      title: opts.title,
      subtitle: opts.subtitle,
      badge: "LOCAL VIDEO EXPERIMENT · NOT PART OF THE MCP TOOL CATALOG",
      footer: "rea.tools · Reverse Engineer Anything",
    });
  }
  scenes.push(...imageScenes.map((scene) => ({ kind: "image", ...scene })));
  if (opts.cards) {
    scenes.push({
      kind: "card",
      title: "Your turn",
      subtitle: `Point this script at capture-browser-scenario --json output · ${imageScenes.length} frames used`,
      badge: "npm run video -- --evidence ./capture.json --output ./walkthrough.mp4",
      footer: "All frames are rendered and encoded locally. No external service.",
    });
  }
  return scenes;
}

function wrapText(text, maxChars) {
  const words = String(text || "").split(/\s+/u).filter(Boolean);
  if (words.length === 0) return [""];
  const lines = [];
  let line = "";
  for (const word of words) {
    if (line && `${line} ${word}`.length > maxChars) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.slice(0, 3);
}

/**
 * A clean, video-sized redraw of REA's investigation flow. The repo's own
 * flow SVG relies on fonts that are wider than the boxes when rasterized with
 * the locally available DejaVu Sans, so the demo draws its own version.
 */
function flowMarkup(width, box) {
  const k = width / 1280;
  const n = (value) => value * k;
  const steps = [
    { title: "1. Ask", lines: ["Agent + local target", "App / binary / browser"] },
    {
      title: "2. Inspect & trace",
      lines: ["REA CLI / MCP", "Evidence provenance"],
      highlight: true,
    },
    { title: "3. Read evidence", lines: ["Code / references", "Unknowns / limits"] },
    { title: "4. Use it", lines: ["Explain / implement", "test in your project"] },
  ];
  let svg = `<rect x="${box.x}" y="${box.y}" width="${box.w}" height="${box.h}" rx="${n(16)}" fill="#f7f9ff"/>`;
  svg += `<text x="${box.x + n(34)}" y="${box.y + n(52)}" font-family="DejaVu Sans" font-weight="700" font-size="${n(26)}" fill="#16203a">REA investigation flow</text>`;

  const inner = n(34);
  const gap = n(28);
  const boxWidth = (box.w - inner * 2 - gap * (steps.length - 1)) / steps.length;
  const boxHeight = Math.min(n(196), box.h * 0.44);
  const boxY = box.y + box.h * 0.27;
  steps.forEach((step, index) => {
    const x = box.x + inner + index * (boxWidth + gap);
    const centre = x + boxWidth / 2;
    svg += `<rect x="${x}" y="${boxY}" width="${boxWidth}" height="${boxHeight}" rx="${n(12)}" fill="#ffffff" stroke="${step.highlight ? "#294f82" : "#c7d0e2"}" stroke-width="${step.highlight ? n(3) : n(2)}"/>`;
    svg += `<text x="${centre}" y="${boxY + n(44)}" text-anchor="middle" font-family="DejaVu Sans" font-weight="700" font-size="${n(20)}" fill="#16203a">${escapeXml(step.title)}</text>`;
    step.lines.forEach((line, lineIndex) => {
      svg += `<text x="${centre}" y="${boxY + n(82) + lineIndex * n(28)}" text-anchor="middle" font-family="DejaVu Sans" font-size="${n(16)}" fill="#5b6570">${escapeXml(line)}</text>`;
    });
    if (index < steps.length - 1) {
      const x1 = x + boxWidth + n(3);
      const x2 = x + boxWidth + gap - n(3);
      const y = boxY + boxHeight / 2;
      svg += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="#5b6570" stroke-width="${n(3)}"/>`;
      svg += `<path d="M ${x2} ${y} l ${-n(9)} ${-n(7)} v ${n(14)} z" fill="#5b6570"/>`;
    }
  });

  const toolsWidth = Math.min(boxWidth * 1.7, box.w * 0.45);
  const toolsX = box.x + (box.w - toolsWidth) / 2;
  const toolsY = boxY + boxHeight + n(36);
  const toolsHeight = n(88);
  const centreX = box.x + inner + 1.5 * (boxWidth + gap) + boxWidth / 2;
  svg += `<line x1="${centreX}" y1="${boxY + boxHeight + n(2)}" x2="${centreX}" y2="${toolsY - n(2)}" stroke="#5b6570" stroke-width="${n(3)}"/>`;
  svg += `<path d="M ${centreX} ${boxY + boxHeight + n(2)} l ${-n(7)} ${n(9)} h ${n(14)} z" fill="#5b6570"/>`;
  svg += `<rect x="${toolsX}" y="${toolsY}" width="${toolsWidth}" height="${toolsHeight}" rx="${n(12)}" fill="#eef2fb" stroke="#c7d0e2" stroke-width="${n(2)}"/>`;
  svg += `<text x="${toolsX + toolsWidth / 2}" y="${toolsY + n(38)}" text-anchor="middle" font-family="DejaVu Sans" font-weight="700" font-size="${n(22)}" fill="#16203a">Analysis tools</text>`;
  svg += `<text x="${toolsX + toolsWidth / 2}" y="${toolsY + n(66)}" text-anchor="middle" font-family="DejaVu Sans" font-size="${n(16)}" fill="#5b6570">Local analysis adapters</text>`;
  return svg;
}

/** One scene as a complete standalone SVG, rendered once to RGBA pixels. */
function sceneSvg(scene, width, height) {
  const pad = Math.round(width * 0.068);
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#111d3a"/><stop offset="1" stop-color="#070b15"/></linearGradient></defs>`;
  svg += `<rect width="${width}" height="${height}" fill="url(#bg)"/>`;
  svg += `<circle cx="${width * 0.88}" cy="${height * 0.14}" r="${height * 0.3}" fill="#1b2a55" opacity="0.35"/>`;
  svg += `<circle cx="${width * 0.06}" cy="${height * 0.92}" r="${height * 0.24}" fill="#24204a" opacity="0.3"/>`;
  svg += `<text x="${pad}" y="${pad * 0.72}" font-family="DejaVu Sans" font-size="${Math.round(width * 0.014)}" letter-spacing="2" fill="#6f82ad">REA · VIDEO EXPERIMENT</text>`;

  if (scene.kind === "card") {
    const cx = width / 2;
    svg += `<rect x="${cx - 46}" y="${height * 0.36}" width="92" height="5" rx="2.5" fill="${ACCENT}"/>`;
    svg += `<text x="${cx}" y="${height * 0.47}" text-anchor="middle" font-family="DejaVu Sans" font-weight="700" font-size="${Math.round(width * 0.044)}" fill="#f0f4ff">${escapeXml(scene.title)}</text>`;
    const lines = wrapText(scene.subtitle, 74);
    lines.forEach((line, index) => {
      svg += `<text x="${cx}" y="${height * 0.55 + index * width * 0.022}" text-anchor="middle" font-family="DejaVu Sans" font-size="${Math.round(width * 0.019)}" fill="#a9b8d8">${escapeXml(line)}</text>`;
    });
    if (scene.badge) {
      svg += `<text x="${cx}" y="${height * 0.74}" text-anchor="middle" font-family="DejaVu Sans Mono" font-size="${Math.round(width * 0.012)}" fill="#7d8fba">${escapeXml(scene.badge)}</text>`;
    }
  } else {
    svg += `<text x="${pad}" y="${height * 0.14}" font-family="DejaVu Sans" font-weight="700" font-size="${Math.round(width * 0.03)}" fill="#f0f4ff">${escapeXml(scene.title)}</text>`;
    svg += `<rect x="${pad}" y="${height * 0.165}" width="${Math.round(width * 0.045)}" height="4" rx="2" fill="${ACCENT}"/>`;
    const lines = wrapText(scene.subtitle, 100);
    lines.forEach((line, index) => {
      svg += `<text x="${pad}" y="${height * 0.218 + index * width * 0.017}" font-family="DejaVu Sans" font-size="${Math.round(width * 0.015)}" fill="#a0b0d0">${escapeXml(line)}</text>`;
    });

    const top = height * (0.218 + Math.max(0, lines.length - 1) * 0.032) + 18;
    const box = { x: pad, y: top, w: width - pad * 2, h: height - top - height * 0.095 };
    if (scene.kind === "flow") {
      svg += flowMarkup(width, box);
    } else {
      const scale = Math.min(box.w / scene.image.width, box.h / scene.image.height);
      const iw = scene.image.width * scale;
      const ih = scene.image.height * scale;
      const ix = box.x + (box.w - iw) / 2;
      const iy = box.y + (box.h - ih) / 2;
      const uri = `data:image/png;base64,${scene.image.data.toString("base64")}`;
      svg += `<defs><clipPath id="card"><rect x="${ix}" y="${iy}" width="${iw}" height="${ih}" rx="14"/></clipPath></defs>`;
      svg += `<rect x="${ix - 2}" y="${iy - 2}" width="${iw + 4}" height="${ih + 4}" rx="16" fill="#223054"/>`;
      svg += `<image x="${ix}" y="${iy}" width="${iw}" height="${ih}" preserveAspectRatio="xMidYMid meet" clip-path="url(#card)" href="${uri}" xlink:href="${uri}"/>`;
    }
  }

  if (scene.footer) {
    svg += `<text x="${width - pad}" y="${height - height * 0.052}" text-anchor="end" font-family="DejaVu Sans Mono" font-size="${Math.round(width * 0.011)}" fill="#5f7197">${escapeXml(scene.footer)}</text>`;
  }
  svg += "</svg>";
  return svg;
}

function renderScene(scene, width, height) {
  const image = new Resvg(sceneSvg(scene, width, height), {
    font: FONT,
    fitTo: { mode: "width", value: width },
  }).render();
  if (image.width !== width || image.height !== height)
    throw new Error(`Unexpected render size ${image.width}×${image.height}`);
  return new Uint8Array(image.pixels);
}

function sampleMap(size, zoom, pan) {
  const map = new Int32Array(size);
  const center = size / 2 + pan;
  for (let index = 0; index < size; index += 1) {
    const source = Math.round(center + (index - size / 2) / zoom);
    map[index] = Math.min(size - 1, Math.max(0, source));
  }
  return map;
}

/**
 * Scenes fade through the background colour rather than cross-dissolving into
 * each other: overlapping two different text layouts produces unreadable
 * ghosting. A slow zoom/pan keeps each held scene moving.
 */
function composeFrame(scenePixels, time, opts) {
  const { width, height, hold, fade } = opts;
  const halfFade = fade / 2;
  const active = [];
  scenePixels.forEach((_, index) => {
    const start = index * hold;
    const end = start + hold;
    if (time < start || time > end) return;
    const alpha =
      Math.min(1, (time - start) / halfFade) *
      Math.min(1, (end - time) / halfFade);
    if (alpha > 0.002)
      active.push({ index, alpha, progress: Math.min(1, (time - start) / hold) });
  });

  const out = new Uint8Array(width * height * 4);
  const background = [10, 14, 26];
  if (active.length === 0) {
    for (let offset = 0; offset < out.length; offset += 4) {
      out[offset] = background[0];
      out[offset + 1] = background[1];
      out[offset + 2] = background[2];
      out[offset + 3] = 255;
    }
    return Buffer.from(out.buffer);
  }
  const first = active[0];
  const second = active[1];
  const firstPixels = scenePixels[first.index];
  const secondPixels = second ? scenePixels[second.index] : null;
  const zoom1 = 1 + 0.035 * first.progress;
  const mapX1 = sampleMap(width, zoom1, -8 * first.progress);
  const mapY1 = sampleMap(height, zoom1, 4 * first.progress);
  let mapX2;
  let mapY2;
  if (secondPixels) {
    const zoom2 = 1 + 0.035 * second.progress;
    mapX2 = sampleMap(width, zoom2, -8 * second.progress);
    mapY2 = sampleMap(height, zoom2, 4 * second.progress);
  }
  const a1 = first.alpha;
  const a2 = second ? second.alpha : 0;
  const rest = Math.max(0, 1 - a1 - a2);
  const b0 = rest * background[0];
  const b1 = rest * background[1];
  const b2 = rest * background[2];

  for (let y = 0; y < height; y += 1) {
    const row1 = mapY1[y] * width * 4;
    const row2 = secondPixels ? mapY2[y] * width * 4 : 0;
    let target = y * width * 4;
    for (let x = 0; x < width; x += 1, target += 4) {
      const p1 = row1 + mapX1[x] * 4;
      if (secondPixels) {
        const p2 = row2 + mapX2[x] * 4;
        out[target] = a1 * firstPixels[p1] + a2 * secondPixels[p2] + b0;
        out[target + 1] = a1 * firstPixels[p1 + 1] + a2 * secondPixels[p2 + 1] + b1;
        out[target + 2] = a1 * firstPixels[p1 + 2] + a2 * secondPixels[p2 + 2] + b2;
      } else {
        out[target] = a1 * firstPixels[p1] + b0;
        out[target + 1] = a1 * firstPixels[p1 + 1] + b1;
        out[target + 2] = a1 * firstPixels[p1 + 2] + b2;
      }
      out[target + 3] = 255;
    }
  }
  return Buffer.from(out.buffer);
}

async function encode(scenePixels, opts) {
  await mkdir(path.dirname(path.resolve(opts.output)), { recursive: true });
  const format =
    opts.format || (opts.output.toLowerCase().endsWith(".webm") ? "webm" : "mp4");
  if (format !== "mp4" && format !== "webm")
    throw new Error(`Unsupported format: ${format}`);

  const args = [
    "-hide_banner",
    "-loglevel",
    "error",
    "-y",
    "-f",
    "rawvideo",
    "-pixel_format",
    "rgba",
    "-video_size",
    `${opts.width}x${opts.height}`,
    "-framerate",
    String(opts.fps),
    "-i",
    "pipe:0",
    "-an",
  ];
  if (format === "mp4") {
    args.push(
      "-c:v",
      "libx264",
      "-preset",
      "medium",
      "-crf",
      String(opts.crf),
      "-pix_fmt",
      "yuv420p",
      "-movflags",
      "+faststart",
    );
  } else {
    args.push(
      "-c:v",
      "libvpx-vp9",
      "-b:v",
      "0",
      "-crf",
      String(Math.min(63, opts.crf + 14)),
      "-deadline",
      "good",
      "-cpu-used",
      "4",
      "-pix_fmt",
      "yuv420p",
    );
  }
  args.push(opts.output);

  const child = spawn(ffmpegPath, args, { stdio: ["pipe", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 20_000) stderr += chunk.toString();
  });
  child.stdin.on("error", () => {});
  const done = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`ffmpeg exited with ${code}: ${stderr.slice(-2000)}`)),
    );
  });

  const duration = scenePixels.length * opts.hold;
  const totalFrames = Math.max(1, Math.round(duration * opts.fps));
  for (let frame = 0; frame < totalFrames; frame += 1) {
    const pixels = composeFrame(scenePixels, frame / opts.fps, opts);
    if (!child.stdin.write(pixels)) {
      await Promise.race([
        new Promise((resolve) => child.stdin.once("drain", resolve)),
        done,
      ]);
    }
    if (frame % opts.fps === 0 || frame === totalFrames - 1)
      process.stdout.write(`\r  encoding ${frame + 1}/${totalFrames} frames`);
  }
  child.stdin.end();
  await done;
  process.stdout.write("\n");
  return { totalFrames, duration, format };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  for (const key of ["evidence", "images", "captions"]) {
    if (opts[key]) {
      const resolved = path.resolve(opts[key]);
      await stat(resolved);
      opts[key] = resolved;
    }
  }
  opts.output = path.resolve(opts.output);

  const scenes = await buildScenes(opts);
  process.stdout.write(
    `Rendering ${scenes.length} scenes at ${opts.width}×${opts.height}…\n`,
  );
  const scenePixels = scenes.map((scene) =>
    renderScene(scene, opts.width, opts.height),
  );
  const result = await encode(scenePixels, opts);
  const size = (await stat(opts.output)).size;
  process.stdout.write(
    `Wrote ${path.relative(ROOT, opts.output) || opts.output} ` +
      `(${result.format}, ${result.duration.toFixed(1)}s, ${result.totalFrames} frames, ` +
      `${(size / 1024 / 1024).toFixed(2)} MiB)\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`create-video: ${error.message}\n`);
  process.exitCode = 1;
});

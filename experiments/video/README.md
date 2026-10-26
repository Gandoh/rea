# REA video experiment

> **Can REA create videos?** Not by itself. REA is a local MCP/CLI reverse-engineering
> toolkit: it inspects binaries, JavaScript/Electron apps, .NET assemblies and web
> pages, and returns findings with Evidence provenance. It has no video encoder,
> no text-to-video model, and no screen recorder. The only "video" in the upstream
> README is a link to an external announcement post.

This folder is a **standalone prototype** that answers "yes, we can build video
creation on top of REA". It consumes PNG evidence REA already produces, renders
captioned scenes locally, and encodes them to MP4 or WebM. It does **not** add an
MCP tool, change REA's contract schemas, or alter the production dependency set.
Per `AGENTS.md`, integrating a new target-observation capability into the MCP
catalog would need a maintainer scope decision; this experiment deliberately
stays outside that boundary.

## Quick start

Requires Node.js 22+ (matching the repository's pinned toolchain).

```bash
cd experiments/video
npm install          # two dev-time packages, installed from npm only
npm run demo         # writes experiments/video/rea-demo.mp4
npm test             # small smoke test: encode + digest verification
```

`rea-demo.mp4` is a generated 21-second, 1280×720 sample built from this repo's
own figures and the `docs/assets/rea-hopper-analysis.png` screenshot. It is kept
as a small demo artifact; regenerate it with `npm run demo`.

The two packages are confined to this folder:

| Package | Why |
| --- | --- |
| `@resvg/resvg-js` | Rasterizes SVG figures and composes title/caption cards |
| `@ffmpeg-installer/ffmpeg` | Supplies a static ffmpeg binary from the npm tarball — no system ffmpeg, browser install or external download at runtime |

After `npm install`, encoding is fully local: no network requests, no cloud
service, no API key.

## Use your own REA evidence

Get screenshots from REA first. For a browser scenario, request `screenshot`
artifacts explicitly — otherwise REA reports `not_requested` and there is no
image to turn into video:

```json
{
  "browser": { "mode": "launch", "executable_path": "/absolute/path/to/chromium" },
  "start_url": { "url": "http://127.0.0.1:3000" },
  "actions": [
    { "step_id": "open", "action": "wait_for_timeout", "duration_ms": 500 }
  ],
  "capture": { "after_each_step": ["screenshot", "url"] }
}
```

```bash
rea capture-browser-scenario ./scenario.json --json > scenario-capture.json
# or, for a single frame:
rea capture-web-screenshot http://127.0.0.1:9222 TARGET_ID --json > screenshot.json
```

Then:

```bash
cd experiments/video
npm run video -- --evidence ../../scenario-capture.json --output ../../walkthrough.mp4
```

`--evidence` accepts a `capture_browser_scenario` result, a
`capture_web_screenshot` result, or an exported Evidence bundle. The extractor
walks CLI result envelopes (`normalized_result`), scenario step artifacts, nested
bundles and JSON embedded in string fields. It keeps artifacts in discovery
order, de-duplicates by SHA-256, and **rejects** any artifact whose declared
`sha256` does not match the decoded bytes — consistent with REA's
content-addressed screenshot artifacts.

Other input/output options:

```bash
# A folder of PNG/SVG frames, with optional captions
npm run video -- --images ../../screenshots --captions ../../captions.json --output ../../slides.webm --format webm

# Tune the render
npm run video -- --evidence ./capture.json --width 1920 --height 1080 --fps 30 \
  --hold 4 --fade 0.8 --crf 18 --title "Clipboard investigation" \
  --subtitle "Preload → IPC → main process" --output ./clipboard.mp4

node create-video.mjs --help    # full option list
```

`captions.json` is an array of strings or `{ "title": "...", "subtitle": "..." }`
objects, applied by index to the extracted images. See
[`captions.example.json`](captions.example.json).

## How it works

1. **Extract** PNG bytes from REA evidence (or load PNG/SVG files from a folder).
2. **Render** each scene once at the target resolution: dark gradient background,
   title, accent rule, wrapped subtitle, and the image inside a rounded card.
   The demo also draws its own four-step investigation-flow diagram, because the
   repo's `rea-investigation-flow.svg` uses fonts wider than its boxes when
   rasterized with the locally available DejaVu Sans.
3. **Animate** in memory: a slow zoom/pan per held scene and a brief fade through
   the background colour at each boundary (a cross-dissolve would ghost two
   different text layouts together).
4. **Encode** raw RGBA frames piped into ffmpeg — H.264/`yuv420p` MP4 with
   `+faststart` by default, or VP9 WebM with `--format webm`.

## Limits and non-goals

- **No live screen recording.** This is a slideshow built from discrete frames.
  A real recorder would need CDP `Page.startScreencast` or Playwright's
  `recordVideo`, plus the host browser/permission handling REA already
  documents for browser and native-UI observation. That is a different, larger
  capability and is not implemented here.
- **No audio, narration or captions track.** Only burned-in title text.
- **No AI video generation.** There is no text-to-video or image-to-video model
  in this repo; that would require an external model/API integration.
- PNG only for embedded REA artifacts (that is what REA emits). SVG/PNG files
  are accepted from `--images`.
- Frames are held in RAM as RGBA buffers (`width × height × 4 × scenes`); very
  large resolutions or hundreds of screenshots will need a streaming renderer.
- The demo uses repo figures as illustrative frames; it makes no new claim about
  REA's analysis behavior or provider coverage.

## Files

| File | Purpose |
| --- | --- |
| `create-video.mjs` | Extract, render, animate and encode (single script) |
| `package.json` | Local, private experiment manifest |
| `test.mjs` | Smoke test for encoding and digest verification |
| `captions.example.json` | Example caption input |
| `rea-demo.mp4` | Generated 21-second sample output |

#!/usr/bin/env python3
"""
AlphaShield by Gandoh Bah Ai — 60.0s (128 BPM, 32 Bars) Full-HD 1080x1920 Motion Graphic Film
No voiceover: pure beat-locked kinetic typography ("lyrics"), glassmorphic product motion UI,
and custom synthesized stereo dark-electronic score.
"""
import math
import os
import subprocess
import time
import wave
from functools import lru_cache

import imageio_ffmpeg
import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

W, H = 1080, 1920
FPS = 30
DURATION = 60.0
TOTAL_FRAMES = int(DURATION * FPS)  # 1800 frames
BPM = 128.0
BEAT_SEC = 60.0 / BPM               # 0.46875s
BAR_SEC = BEAT_SEC * 4.0            # 1.875s (32 bars = 60.000s)

FONT_DIR = "/tmp/promo-fonts"
OUT_DIR = "/home/user/rea/studio/promo"
os.makedirs(OUT_DIR, exist_ok=True)
WAV_PATH = "/tmp/alphashield_score_60s.wav"
MP4_PATH = os.path.join(OUT_DIR, "alphashield-60s-ad.mp4")
PREVIEW_DIR = "/tmp/alphashield_keyframes"
os.makedirs(PREVIEW_DIR, exist_ok=True)

# Palette
C_BG = (5, 8, 17)
C_WHITE = (248, 250, 252)
C_MUTED = (148, 163, 184)
C_DIM = (71, 85, 105)
C_EMERALD = (16, 185, 129)
C_EMERALD_BRIGHT = (52, 211, 153)
C_INDIGO = (99, 102, 241)
C_INDIGO_BRIGHT = (129, 140, 248)
C_CRIMSON = (239, 68, 68)
C_CRIMSON_BRIGHT = (252, 129, 129)
C_AMBER = (245, 158, 11)
C_AMBER_BRIGHT = (251, 191, 36)
C_PANEL = (13, 20, 38)
C_PANEL_2 = (19, 29, 54)


@lru_cache(maxsize=128)
def get_font(name: str, size: int) -> ImageFont.FreeTypeFont:
    mapping = {
        "display": "SpaceGrotesk-Bold.ttf",
        "display_med": "SpaceGrotesk-Medium.ttf",
        "black": "Inter-Black.ttf",
        "bold": "Inter-Bold.ttf",
        "med": "Inter-Medium.ttf",
        "mono": "JetBrainsMono-Bold.ttf",
        "mono_med": "JetBrainsMono-Medium.ttf",
    }
    return ImageFont.truetype(os.path.join(FONT_DIR, mapping[name]), max(10, int(size)))


# =============================================================================
# 1. SYNTHESIZE 60.000s 128-BPM STEREO DARK-ELECTRONIC SCORE (NO VOICEOVER)
# =============================================================================
def synthesize_score(wav_path: str):
    sr = 44100
    n = int(DURATION * sr)
    t = np.arange(n, dtype=np.float32) / sr

    beat_pos = t / BEAT_SEC
    beat_idx = np.floor(beat_pos).astype(np.int32)
    beat_frac = beat_pos - beat_idx
    bar_idx = beat_idx // 4

    step16_pos = t / (BEAT_SEC / 4.0)
    step16_idx = np.floor(step16_pos).astype(np.int32)
    step16_frac = step16_pos - step16_idx

    # Active drum mask (bars 0..1 tension, drop silent half-bar right before rug at bar 2.0, full groove bars 2..31)
    kick_active = np.ones(n, dtype=np.float32)
    # Brief dramatic breath right before Act III hero drop (bar 7 beat 3..4: 14.06s..15.00s)
    riser_gap = (t >= 14.0625) & (t < 15.0)
    kick_active[riser_gap] = 0.0
    # Clean outro tail after 58.6s
    kick_active[t >= 58.6] = 0.0

    # 808 / Tech Punch Kick (pitch sweep 155Hz -> 44Hz)
    bt = beat_frac * BEAT_SEC
    k_pitch = 44.0 + 115.0 * np.exp(-bt * 34.0)
    # Exact phase integration per beat reset
    k_phase = 2.0 * np.pi * (44.0 * bt + (115.0 / 34.0) * (1.0 - np.exp(-bt * 34.0)))
    k_env = np.exp(-bt * 8.5) * np.minimum(1.0, bt * 400.0)
    k_click = np.exp(-bt * 95.0) * np.sin(2.0 * np.pi * 1100.0 * bt) * 0.28
    kick = (np.tanh(np.sin(k_phase) * 1.65) * k_env + k_click) * kick_active

    # Sidechain envelope (ducks bass & pads cleanly on every kick)
    sidechain = np.where(kick_active > 0.5, 1.0 - 0.72 * np.exp(-bt * 10.0), 1.0)

    # Crisp Clap / Snare on beats 1 & 3 (0-indexed: beat % 4 in {1, 3}) from bar 2 onward
    rng = np.random.default_rng(42)
    white = rng.standard_normal(n).astype(np.float32)
    is_snare = ((beat_idx % 4 == 1) | (beat_idx % 4 == 3)) & (bar_idx >= 2) & (~riser_gap) & (t < 58.1)
    sn_env = np.where(is_snare, np.exp(-bt * 19.0) * np.minimum(1.0, bt * 500.0), 0.0)
    sn_body = np.where(is_snare, np.sin(2.0 * np.pi * 185.0 * bt) * np.exp(-bt * 28.0), 0.0)
    snare = white * sn_env * 0.36 + sn_body * 0.25

    # Stereo 16th-note Hi-Hats (offbeat open accent on step % 4 == 2)
    st_sec = step16_frac * (BEAT_SEC / 4.0)
    hat_active = (bar_idx >= 1) & (~riser_gap) & (t < 58.1)
    decay_rate = np.where(step16_idx % 4 == 2, 26.0, 68.0)
    hat_amp = np.where(step16_idx % 4 == 2, 0.16, 0.085)
    # High-frequency metallic sheen via differenced noise
    metal = np.diff(white, prepend=0.0)
    hat = np.where(hat_active, metal * np.exp(-st_sec * decay_rate) * hat_amp, 0.0)

    # Chord root progression every bar: Fm (F1=43.65Hz) -> Db (34.65Hz) -> Ab (51.91Hz) -> Eb (38.89Hz)
    prog_roots = np.array([43.65, 34.65, 51.91, 38.89], dtype=np.float32)
    root_freq = prog_roots[bar_idx % 4]
    # Danger dissonance drop on Bar 2..3 (Rug crash)
    root_freq = np.where((bar_idx == 2) | (bar_idx == 3), 41.20, root_freq)  # low E1 menace

    # Stereo Detuned Reese Sub-Bass
    ph_base = np.cumsum(2.0 * np.pi * root_freq / sr)
    ph_l = np.cumsum(2.0 * np.pi * (root_freq * 2.006) / sr)
    ph_r = np.cumsum(2.0 * np.pi * (root_freq * 1.994) / sr)
    sub = np.sin(ph_base) * 0.52
    saw_l = (((ph_l / (2.0 * np.pi)) % 1.0) * 2.0 - 1.0)
    saw_r = (((ph_r / (2.0 * np.pi)) % 1.0) * 2.0 - 1.0)
    # Warm waveshaper filter approximation
    reese_l = (sub + np.tanh(saw_l * 1.4) * 0.26) * sidechain
    reese_r = (sub + np.tanh(saw_r * 1.4) * 0.26) * sidechain

    # 16th-Note Dark Synthwave Arpeggiator (F minor pentatonic / natural minor intervals)
    # Semitone offsets per 16th step: [0, 3, 7, 12, 7, 3, 10, 7, 0, 3, 7, 15, 12, 10, 7, 3]
    arp_semitones = np.array([0, 3, 7, 12, 7, 3, 10, 7, 0, 3, 7, 15, 12, 10, 7, 3], dtype=np.float32)
    semi = arp_semitones[step16_idx % 16]
    arp_freq = (root_freq * 4.0) * (2.0 ** (semi / 12.0))
    arp_phase = np.cumsum(2.0 * np.pi * arp_freq / sr)
    arp_env = np.exp(-st_sec * 15.0) * np.minimum(1.0, st_sec * 350.0)
    # Dynamic energy brightness curve across the 60s ad
    energy = (
        0.45
        + 0.35 * np.clip((t - 7.5) / 7.5, 0.0, 1.0)
        + 0.25 * np.clip((t - 15.0) / 3.0, 0.0, 1.0)
        + 0.20 * np.clip((t - 48.0) / 4.0, 0.0, 1.0)
    )
    arp_raw = np.sin(arp_phase) + 0.45 * np.sin(2.0 * arp_phase) * energy
    arp_l = arp_raw * arp_env * 0.16 * sidechain
    arp_r = np.roll(arp_l, int(0.014 * sr)) * 0.92  # stereo Haas / ping-pong width!

    # Cinematic Sub-Drops & Riser Sweeps at Key Story Transitions
    fx = np.zeros(n, dtype=np.float32)
    for drop_t in [3.75, 15.0, 24.375, 30.0, 41.25, 48.75, 52.5]:
        mask = (t >= drop_t) & (t < drop_t + 1.4)
        dt = t[mask] - drop_t
        boom_ph = 2.0 * np.pi * (36.0 * dt + (90.0 / 6.0) * (1.0 - np.exp(-dt * 6.0)))
        fx[mask] += np.sin(boom_ph) * np.exp(-dt * 2.8) * 0.55

    # Pre-reveal Riser (13.125s -> 15.000s) & Pre-finale Riser (50.625s -> 52.500s)
    for r_start, r_end in [(13.125, 15.0), (50.625, 52.5)]:
        mask = (t >= r_start) & (t < r_end)
        u = (t[mask] - r_start) / (r_end - r_start)
        sweep_f = 220.0 * (2.0 ** (u * 3.2))
        sw_ph = np.cumsum(2.0 * np.pi * sweep_f / sr)
        fx[mask] += (np.sin(sw_ph) * 0.22 + white[mask] * 0.18) * (u ** 2)

    # Shimmering Climax Pad (48.75s -> 59.8s): Fm9 lush stereo fifths
    pad_l = np.zeros(n, dtype=np.float32)
    pad_r = np.zeros(n, dtype=np.float32)
    pmask = t >= 15.0
    pt = t[pmask]
    pad_amp = np.where(pt >= 48.75, 0.14, 0.065) * np.clip((59.8 - pt) / 1.4, 0.0, 1.0)
    for mult, pan in [(4.0, 0.7), (6.0, 0.3), (8.0, 0.8), (9.0, 0.2)]:
        s = np.sin(2.0 * np.pi * (root_freq[pmask] * mult) * pt)
        pad_l[pmask] += s * pad_amp * pan
        pad_r[pmask] += s * pad_amp * (1.0 - pan)

    # Master Fade Out (58.8s -> 60.0s)
    fade_out = np.clip((60.0 - t) / 1.1, 0.0, 1.0)

    mix_l = (kick * 0.78 + snare + hat * 1.15 + reese_l * 0.62 + arp_l + pad_l * sidechain + fx) * fade_out
    mix_r = (kick * 0.78 + snare + hat * 0.85 + reese_r * 0.62 + arp_r + pad_r * sidechain + fx) * fade_out

    # Soft studio brickwall mastering limiter
    mix_l = np.tanh(mix_l * 1.18) * 0.92
    mix_r = np.tanh(mix_r * 1.18) * 0.92

    stereo = np.empty((n, 2), dtype=np.int16)
    stereo[:, 0] = np.clip(mix_l * 32767.0, -32767, 32767).astype(np.int16)
    stereo[:, 1] = np.clip(mix_r * 32767.0, -32767, 32767).astype(np.int16)

    with wave.open(wav_path, "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(stereo.tobytes())

    # Compute 12-band audio envelope per video frame for reactive spectrum HUD!
    samples_per_frame = sr // FPS
    env_per_frame = np.zeros((TOTAL_FRAMES, 12), dtype=np.float32)
    mono = 0.5 * (np.abs(mix_l) + np.abs(mix_r))
    for fi in range(TOTAL_FRAMES):
        chunk = mono[fi * samples_per_frame : (fi + 1) * samples_per_frame]
        spec = np.abs(np.fft.rfft(chunk * np.hanning(len(chunk))))
        bands = np.array_split(spec[1:97], 12)
        vals = [float(np.mean(b)) for b in bands]
        mx = max(vals) if max(vals) > 1e-6 else 1.0
        env_per_frame[fi] = np.clip(np.array(vals) / (mx * 0.85), 0.08, 1.0)
    return env_per_frame


# =============================================================================
# 2. PRE-BAKED VOLUMETRIC BACKGROUNDS, GLOW SPRITES & EASING HELPERS
# =============================================================================
def spring(dt: float, dur: float = 0.42) -> float:
    if dt <= 0.0:
        return 0.0
    u = min(1.0, dt / dur)
    return 1.0 - math.exp(-7.5 * u) * math.cos(9.5 * u)


def ease_out_cubic(u: float) -> float:
    u = max(0.0, min(1.0, u))
    return 1.0 - (1.0 - u) ** 3


def build_base_plates():
    y = np.linspace(0, 1, H, dtype=np.float32)[:, None]
    x = np.linspace(0, 1, W, dtype=np.float32)[None, :]

    def make_plate(c_top, c_bot, orb1, orb2):
        arr = np.zeros((H, W, 3), dtype=np.float32)
        for ch in range(3):
            arr[:, :, ch] = c_top[ch] * (1.0 - y) + c_bot[ch] * y
        # Orb 1 (top-right)
        d1 = (x - 0.82) ** 2 + ((y - 0.18) * (H / W)) ** 2
        g1 = np.exp(-d1 * 4.2)
        # Orb 2 (bottom-left)
        d2 = (x - 0.18) ** 2 + ((y - 0.78) * (H / W)) ** 2
        g2 = np.exp(-d2 * 4.0)
        for ch in range(3):
            arr[:, :, ch] += orb1[ch] * g1 * 0.26 + orb2[ch] * g2 * 0.22

        # Crisp architectural 90px grid
        gx = (np.arange(W) % 90 == 0)[None, :]
        gy = (np.arange(H) % 90 == 0)[:, None]
        grid = gx | gy
        arr[grid] = arr[grid] * 0.88 + np.array([38, 52, 84], dtype=np.float32) * 0.16

        # Subtle film grain
        rng = np.random.default_rng(7)
        grain = rng.normal(0.0, 2.2, (H, W, 1)).astype(np.float32)
        arr = np.clip(arr + grain, 0, 255).astype(np.uint8)
        return Image.fromarray(arr, mode="RGB")

    return {
        "cyber": make_plate((5, 9, 20), (8, 13, 28), C_EMERALD, C_INDIGO),
        "danger": make_plate((14, 5, 12), (8, 6, 15), C_CRIMSON, C_AMBER),
        "royal": make_plate((6, 10, 24), (4, 15, 22), C_INDIGO_BRIGHT, C_EMERALD_BRIGHT),
    }


@lru_cache(maxsize=16)
def make_glow_disc(radius: int, color: tuple, alpha_max: int = 95) -> Image.Image:
    radius = max(8, int(radius))
    sz = radius * 2
    yy, xx = np.ogrid[-radius:radius, -radius:radius]
    dist2 = (xx * xx + yy * yy) / float(radius * radius)
    alpha = np.clip(np.exp(-dist2 * 2.8) * alpha_max, 0, 255).astype(np.uint8)
    rgba = np.zeros((sz, sz, 4), dtype=np.uint8)
    rgba[..., 0] = color[0]
    rgba[..., 1] = color[1]
    rgba[..., 2] = color[2]
    rgba[..., 3] = alpha
    return Image.fromarray(rgba, mode="RGBA")


def fit_font(draw: ImageDraw.ImageDraw, text: str, family: str, target_size: int, max_w: int = 920):
    sz = target_size
    while sz > 24:
        f = get_font(family, sz)
        bbox = draw.textbbox((0, 0), text, font=f)
        if (bbox[2] - bbox[0]) <= max_w:
            return f, bbox[2] - bbox[0], bbox[3] - bbox[1]
        sz -= 4
    f = get_font(family, 24)
    bbox = draw.textbbox((0, 0), text, font=f)
    return f, bbox[2] - bbox[0], bbox[3] - bbox[1]


def draw_centered_text(draw: ImageDraw.ImageDraw, y: int, text: str, family: str, size: int, fill: tuple, max_w: int = 930, shadow: bool = True):
    f, tw, th = fit_font(draw, text, family, size, max_w=max_w)
    x = (W - tw) // 2
    if shadow:
        draw.text((x, y + 5), text, font=f, fill=(0, 0, 0))
    draw.text((x, y), text, font=f, fill=fill)
    return th


def draw_pill(draw: ImageDraw.ImageDraw, cx: int, cy: int, text: str, fg: tuple, bg: tuple, border: tuple, size: int = 28, family: str = "mono"):
    f = get_font(family, size)
    bb = draw.textbbox((0, 0), text, font=f)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    pw, ph = tw + 52, th + 30
    x0, y0 = cx - pw // 2, cy - ph // 2
    draw.rounded_rectangle([x0, y0, x0 + pw, y0 + ph], radius=ph // 2, fill=bg, outline=border, width=2)
    draw.text((cx - (bb[0] + bb[2]) // 2, cy - (bb[1] + bb[3]) // 2), text, font=f, fill=fg)


def draw_badge_icon(draw: ImageDraw.ImageDraw, cx: int, cy: int, kind: str):
    if kind == "check":
        r = 20
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(16, 185, 129))
        draw.line([(cx - 9, cy + 1), (cx - 2, cy + 8), (cx + 10, cy - 7)], fill=(4, 32, 22), width=4)
    elif kind == "cross":
        r = 19
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(239, 68, 68))
        draw.line([(cx - 7, cy - 7), (cx + 7, cy + 7)], fill=(255, 255, 255), width=4)
        draw.line([(cx + 7, cy - 7), (cx - 7, cy + 7)], fill=(255, 255, 255), width=4)
    elif kind == "warn":
        pts = [(cx, cy - 19), (cx + 20, cy + 16), (cx - 20, cy + 16)]
        draw.polygon(pts, fill=(245, 158, 11))
        draw.line([(cx, cy - 7), (cx, cy + 5)], fill=(18, 12, 4), width=4)
        draw.ellipse([cx - 2, cy + 9, cx + 2, cy + 13], fill=(18, 12, 4))


def draw_score_ring(img: Image.Image, cx: int, cy: int, radius: int, score: int, color: tuple, sublabel: str):
    # 2x supersampled smooth arc
    scale = 2
    box = (radius + 28) * 2 * scale
    overlay = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    pad = 24 * scale
    r2 = box - pad
    # Track
    od.arc([pad, pad, r2, r2], start=135, end=405, fill=(30, 41, 59, 230), width=18 * scale)
    # Active arc
    sweep = int(270 * max(0.02, min(1.0, score / 100.0)))
    od.arc([pad, pad, r2, r2], start=135, end=135 + sweep, fill=(*color, 255), width=20 * scale)
    smooth = overlay.resize(((radius + 28) * 2, (radius + 28) * 2), Image.Resampling.LANCZOS)
    img.paste(smooth, (cx - radius - 28, cy - radius - 28), smooth)

    d = ImageDraw.Draw(img)
    f_num = get_font("mono", int(radius * 0.74))
    s_txt = str(int(score))
    bb = d.textbbox((0, 0), s_txt, font=f_num)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    d.text((cx - (bb[0] + bb[2]) // 2, cy - (bb[1] + bb[3]) // 2 - 18), s_txt, font=f_num, fill=C_WHITE)

    f_sub = get_font("bold", 24)
    bb2 = d.textbbox((0, 0), sublabel, font=f_sub)
    d.text((cx - (bb2[0] + bb2[2]) // 2, int(cy + radius * 0.44)), sublabel, font=f_sub, fill=color)


def draw_shield_emblem(img: Image.Image, cx: int, cy: int, size: int, accent: tuple, pulse: float = 0.0):
    size = max(32, int(size))
    glow = make_glow_disc(int(size * (1.45 + 0.15 * pulse)), accent, 95)
    img.paste(glow, (cx - glow.width // 2, cy - glow.height // 2), glow)
    d = ImageDraw.Draw(img)
    s = size
    pts = [
        (cx, cy - s),
        (cx + int(s * 0.82), cy - int(s * 0.56)),
        (cx + int(s * 0.72), cy + int(s * 0.25)),
        (cx, cy + s),
        (cx - int(s * 0.72), cy + int(s * 0.25)),
        (cx - int(s * 0.82), cy - int(s * 0.56)),
    ]
    d.polygon(pts, fill=(11, 20, 38), outline=accent)
    # Crisp thicker shield outline
    for i in range(len(pts)):
        d.line([pts[i], pts[(i + 1) % len(pts)]], fill=accent, width=6)
    # Inner monogram AS
    f = get_font("display", int(s * 0.72))
    bb = d.textbbox((0, 0), "AS", font=f)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    d.text((cx - tw // 2, cy - th // 2 - 10), "AS", font=f, fill=C_WHITE)


def apply_rgb_glitch(img: Image.Image, shift_px: int) -> Image.Image:
    if shift_px <= 0:
        return img
    r, g, b = img.split()
    r = ImageChops.offset(r, -shift_px, 0)
    b = ImageChops.offset(b, shift_px, 0)
    return Image.merge("RGB", (r, g, b))


# =============================================================================
# 3. FRAME COMPOSITOR — ALL 8 ACTS (32 BARS / 60.0s)
# =============================================================================
def render_frame(fi: int, plates: dict, spec_bars: np.ndarray) -> bytes:
    t = fi / float(FPS)
    beat_pos = t / BEAT_SEC
    beat_frac = beat_pos - math.floor(beat_pos)
    kick_pulse = math.exp(-beat_frac * 5.0)
    bar = t / BAR_SEC  # 0.0 .. 32.0

    # Choose plate
    if (3.75 <= t < 7.5) or (11.25 <= t < 15.0) or (24.375 <= t < 28.125) or (41.25 <= t < 43.125):
        base = plates["danger"].copy()
        theme_col = C_CRIMSON
    elif t >= 48.75 or (15.0 <= t < 22.5):
        base = plates["royal"].copy()
        theme_col = C_EMERALD
    else:
        base = plates["cyber"].copy()
        theme_col = C_EMERALD

    # Subtle drifting ambient aura tied to beat
    orb = make_glow_disc(360, theme_col, int(38 + 26 * kick_pulse))
    ox = int(W * 0.5 + math.sin(t * 0.9) * 210) - orb.width // 2
    oy = int(H * 0.46 + math.cos(t * 0.7) * 180) - orb.height // 2
    base.paste(orb, (ox, oy), orb)

    d = ImageDraw.Draw(base)

    # -------------------------------------------------------------------------
    # PERSISTENT STUDIO TOP HUD & AUDIO SPECTRUM EQUALIZER
    # -------------------------------------------------------------------------
    d.rounded_rectangle([68, 78, 405, 134], radius=28, fill=(12, 19, 36), outline=(45, 62, 95), width=2)
    d.ellipse([90, 97, 108, 115], fill=theme_col)
    d.text((122, 89), "ALPHASHIELD · LIVE", font=get_font("mono", 23), fill=C_WHITE)

    # 12-band equalizer bars top-right
    eq_x0 = 760
    for bi in range(12):
        bh = int(10 + 36 * float(spec_bars[bi]))
        bx = eq_x0 + bi * 14
        by1 = 126
        d.rounded_rectangle([bx, by1 - bh, bx + 9, by1], radius=3, fill=theme_col if bi < 8 else C_INDIGO_BRIGHT)

    # Timecode
    tc = f"00:{int(t):02d} / 01:00"
    d.text((938 - 178, 140), tc, font=get_font("mono_med", 20), fill=C_MUTED)

    # =========================================================================
    # ACT I (Bars 0..4 | 0.00s - 7.50s): GREEN CANDLE -> RUG CRASH HOOK
    # =========================================================================
    if t < 7.5:
        is_crash = t >= 3.75
        # Animated Trading Chart Card
        d.rounded_rectangle([76, 260, 1004, 920], radius=34, fill=C_PANEL, outline=C_CRIMSON if is_crash else C_EMERALD, width=3)
        d.text((120, 302), "$HYPEMOON / WETH", font=get_font("mono", 30), fill=C_WHITE)
        pct_txt = "-99.8% RUGGED" if is_crash else f"+{int(120 + min(1.0, t / 3.4) * 300)}% PUMPING"
        d.text((620, 300), pct_txt, font=get_font("mono", 32), fill=C_CRIMSON_BRIGHT if is_crash else C_EMERALD_BRIGHT)

        # Draw candlestick / price trajectory
        pts = []
        n_pts = 28
        prog = min(1.0, t / 3.75) if not is_crash else 1.0
        visible = max(2, int(n_pts * prog))
        for i in range(visible):
            u = i / float(n_pts - 1)
            px = int(130 + u * 760)
            py = int(820 - (u ** 1.85) * 410 + math.sin(i * 1.7) * 18)
            pts.append((px, py))
        if is_crash:
            crash_u = ease_out_cubic((t - 3.75) / 0.32)
            last_x, last_y = pts[-1]
            pts.append((last_x + 55, int(last_y + crash_u * (865 - last_y))))

        line_col = C_CRIMSON if is_crash else C_EMERALD_BRIGHT
        if len(pts) >= 2:
            d.line(pts, fill=line_col, width=10)
            gx, gy = pts[-1]
            dot_glow = make_glow_disc(56, line_col, 150)
            base.paste(dot_glow, (gx - 56, gy - 56), dot_glow)
            d.ellipse([gx - 12, gy - 12, gx + 12, gy + 12], fill=C_WHITE)

        # Beat-locked Kinetic Lyrics below chart
        if t < 1.875:
            s = spring(t)
            draw_centered_text(d, int(1050 + (1 - s) * 60), "GREEN CANDLE.", "black", 104, C_WHITE)
            draw_centered_text(d, int(1185 + (1 - s) * 80), "CHART GOING VERTICAL.", "display", 54, C_EMERALD_BRIGHT)
        elif t < 3.75:
            s = spring(t - 1.875)
            draw_centered_text(d, int(1040 + (1 - s) * 60), "EVERYONE'S BUYING.", "display", 78, C_MUTED)
            draw_centered_text(d, int(1155 + (1 - s) * 70), "SO YOU APE IN.", "black", 112, C_EMERALD_BRIGHT)
        elif t < 5.625:
            s = spring(t - 3.75, 0.28)
            draw_centered_text(d, 1020, "ONE SECOND LATER—", "display", 62, C_MUTED)
            draw_centered_text(d, int(1120 + (1 - s) * 50), "ZERO.", "black", 190, C_CRIMSON)
        else:
            s = spring(t - 5.625)
            draw_centered_text(d, int(1040 + (1 - s) * 50), "SELLS BLOCKED.", "black", 104, C_CRIMSON_BRIGHT)
            draw_centered_text(d, int(1175 + (1 - s) * 65), "LIQUIDITY GONE.", "black", 96, C_WHITE)
            draw_pill(d, W // 2, 1375, "TX REVERTED · HONEYPOT TRAP", C_CRIMSON_BRIGHT, (45, 10, 18), C_CRIMSON, 30)

    # =========================================================================
    # ACT II (Bars 4..8 | 7.50s - 15.00s): INSIDE THE BYTECODE TRAP
    # =========================================================================
    elif t < 15.0:
        dt = t - 7.5
        # Streaming EVM Bytecode Matrix Panel
        d.rounded_rectangle([76, 620, 1004, 1520], radius=34, fill=(9, 14, 28), outline=(45, 62, 98), width=2)
        hex_rows = [
            "608060405234801561001057600080fd",
            "5b50600436106100a95760003560e01c",
            "8063 40c10f19 1461011057  << MINT",
            "8063 f9f92be4 1461013057  << BLACKLIST",
            "8063 69fe0e2d 1461017057  << 99% TAX",
            "363d3d373d3d3d363d73deadbeef5af4",
            "3d82803e903d91602b57fd5bf3ff0000",
        ]
        for ri, row in enumerate(hex_rows):
            ry = 675 + ri * 62
            is_trap_row = "<<" in row and t >= 9.375
            col = C_CRIMSON_BRIGHT if is_trap_row else (68, 88, 126)
            d.text((118, ry), row, font=get_font("mono", 28), fill=col)

        # Sweeping Emerald/Crimson Laser Scanline
        scan_y = int(650 + ((dt * 260) % 440))
        d.line([(84, scan_y), (996, scan_y)], fill=C_CRIMSON if t >= 11.25 else C_EMERALD_BRIGHT, width=5)

        if t < 9.375:
            s = spring(t - 7.5)
            draw_centered_text(d, int(250 + (1 - s) * 50), "SCAMMERS DON'T HIDE", "display", 74, C_WHITE)
            draw_centered_text(d, int(350 + (1 - s) * 65), "IN THE CHART.", "black", 104, C_INDIGO_BRIGHT)
        elif t < 11.25:
            s = spring(t - 9.375)
            draw_centered_text(d, int(250 + (1 - s) * 50), "THEY HIDE", "display", 80, C_MUTED)
            draw_centered_text(d, int(350 + (1 - s) * 65), "IN THE BYTECODE.", "black", 98, C_CRIMSON_BRIGHT)
        elif t < 13.125:
            draw_centered_text(d, 260, "3 DEADLY CODE TRAPS", "black", 82, C_WHITE)
            traps = [
                (11.25, "0x40c10f19 · HIDDEN INFINITE MINT"),
                (11.72, "0xf9f92be4 · BUYER WALLET BLACKLIST"),
                (12.19, "0x69fe0e2d · 99% SELL-TAX SWITCH"),
            ]
            for idx, (appear_t, label) in enumerate(traps):
                if t >= appear_t:
                    s = spring(t - appear_t, 0.30)
                    draw_pill(d, W // 2, int(1185 + idx * 105 + (1 - s) * 35), label, C_WHITE, (58, 14, 24), C_CRIMSON, 29)
        else:
            s = spring(t - 13.125)
            draw_centered_text(d, int(250 + (1 - s) * 50), "AND FAKE TRADING APKs", "display", 68, C_AMBER_BRIGHT)
            draw_centered_text(d, int(345 + (1 - s) * 65), "DRAIN YOUR SEED.", "black", 96, C_CRIMSON_BRIGHT)
            draw_pill(d, W // 2, 1290, "CLIPBOARD HIJACK · SEED STEALERS", C_AMBER_BRIGHT, (48, 32, 8), C_AMBER, 30)

    # =========================================================================
    # ACT III (Bars 8..12 | 15.00s - 22.50s): HERO BRAND REVEAL — ALPHASHIELD
    # =========================================================================
    elif t < 22.5:
        dt = t - 15.0
        # Expanding shockwave rings on beat drop
        for r_idx in range(3):
            ring_u = ((dt * 0.85 + r_idx * 0.33) % 1.0)
            rr = int(160 + ring_u * 360)
            d.ellipse([W // 2 - rr, 690 - rr, W // 2 + rr, 690 + rr], outline=(16, 185, 129), width=max(1, int((1 - ring_u) * 4)))

        draw_shield_emblem(base, W // 2, 690, int(165 * spring(dt, 0.45)), C_EMERALD_BRIGHT, kick_pulse)
        d = ImageDraw.Draw(base)

        if t < 16.875:
            s = spring(t - 15.0, 0.35)
            draw_centered_text(d, int(980 + (1 - s) * 55), "STOP APING BLIND.", "black", 98, C_WHITE)
            draw_centered_text(d, int(1110 + (1 - s) * 70), "MEET YOUR SHIELD.", "display", 64, C_EMERALD_BRIGHT)
        elif t < 18.75:
            s = spring(t - 16.875, 0.35)
            draw_centered_text(d, int(965 + (1 - s) * 45), "ALPHASHIELD", "black", 122, C_WHITE)
            draw_centered_text(d, int(1115 + (1 - s) * 60), "by Gandoh Bah Ai", "display", 58, C_INDIGO_BRIGHT)
        elif t < 20.625:
            s = spring(t - 18.75)
            draw_centered_text(d, int(975 + (1 - s) * 50), "2 SECONDS.", "black", 128, C_EMERALD_BRIGHT)
            draw_centered_text(d, int(1125 + (1 - s) * 65), "LIVE ON-CHAIN TRUTH.", "display", 68, C_WHITE)
        else:
            draw_centered_text(d, 960, "5 CHAINS · LIVE RPC", "black", 84, C_WHITE)
            chains = ["ETHEREUM", "BASE", "BNB CHAIN", "ARBITRUM", "POLYGON"]
            positions = [(290, 1150), (790, 1150), (540, 1265), (290, 1380), (790, 1380)]
            for idx, (ch_name, (cx, cy)) in enumerate(zip(chains, positions)):
                if t >= 20.625 + idx * 0.24:
                    draw_pill(d, cx, cy, ch_name, C_EMERALD_BRIGHT, C_PANEL_2, C_EMERALD, 30)

    # =========================================================================
    # ACT IV (Bars 12..16 | 22.50s - 30.00s): LIVE HONEYPOT AUDIT DEMO
    # =========================================================================
    elif t < 30.0:
        draw_centered_text(d, 215, "PASTE ANY 0x TOKEN.", "display", 66, C_MUTED)
        draw_centered_text(d, 300, "CATCH TRAPS INSTANTLY.", "black", 78, C_WHITE)

        # Product Glass Card
        d.rounded_rectangle([72, 440, 1008, 1520], radius=38, fill=C_PANEL, outline=C_CRIMSON if t >= 24.375 else C_INDIGO, width=3)
        # Address input bar
        d.rounded_rectangle([118, 492, 962, 578], radius=18, fill=(6, 10, 20), outline=(55, 72, 110), width=2)
        d.text((146, 518), "0xDEAD0000...9999BEEF  ($MOONRUG)", font=get_font("mono", 27), fill=C_WHITE)

        if t < 24.375:
            u = (t - 22.5) / 1.875
            cur_score = int(100 - u * 65)
            draw_score_ring(base, W // 2, 815, 145, cur_score, C_AMBER_BRIGHT, "DECOMPILING...")
            d = ImageDraw.Draw(base)
            draw_pill(d, W // 2, 1110, "eth_getCode · SCANNING 14 SELECTORS", C_INDIGO_BRIGHT, C_PANEL_2, C_INDIGO, 27)
        else:
            draw_score_ring(base, W // 2, 795, 145, 12, C_CRIMSON, "CRITICAL RUG")
            d = ImageDraw.Draw(base)
            alerts = [
                (24.50, "ACTIVE HONEYPOT: 84 BUYS / 0 SELLS"),
                (25.10, "blacklist(address) SELECTOR FOUND"),
                (25.70, "MODIFIABLE 99% SELL-TAX TRAP"),
            ]
            for idx, (at_t, msg) in enumerate(alerts):
                if t >= at_t:
                    s = spring(t - at_t, 0.28)
                    y0 = int(1045 + idx * 102 + (1 - s) * 30)
                    d.rounded_rectangle([120, y0, 960, y0 + 82], radius=16, fill=(48, 12, 20), outline=C_CRIMSON, width=2)
                    draw_badge_icon(d, 164, y0 + 41, "cross")
                    d.text((202, y0 + 23), msg, font=get_font("mono", 26), fill=C_WHITE)

            if t >= 28.125:
                s = spring(t - 28.125, 0.32)
                d.rounded_rectangle([110, int(1380 + (1 - s) * 40), 970, int(1485 + (1 - s) * 40)], radius=22, fill=C_EMERALD, outline=C_WHITE, width=3)
                draw_centered_text(d, int(1400 + (1 - s) * 40), "WALLET SAVED IN 2 SECONDS.", "black", 50, (3, 35, 25), shadow=False)

    # =========================================================================
    # ACT V (Bars 16..20 | 30.00s - 37.50s): LIVE DEX RADAR & CLEAN ALPHA
    # =========================================================================
    elif t < 37.5:
        s_top = spring(t - 30.0)
        draw_centered_text(d, int(215 + (1 - s_top) * 40), "SPOT REAL BREAKOUTS.", "black", 82, C_WHITE)
        draw_centered_text(d, int(315 + (1 - s_top) * 55), "VERIFY CLEAN LIQUIDITY.", "display", 58, C_EMERALD_BRIGHT)

        rows = [
            ("PEPE / USD", "+11.4%", "LIQ $48.2M", "94 SAFE"),
            ("AERO / USD", "+8.9%", "LIQ $62.5M", "92 SAFE"),
            ("SOL / USD", "+5.8%", "VOL $3.4B", "LIVE FEED"),
        ]
        for idx, (pair, chg, liq, tag) in enumerate(rows):
            appear = 30.3 + idx * 0.45
            if t >= appear:
                s = spring(t - appear, 0.35)
                ry = int(455 + idx * 145 + (1 - s) * 45)
                d.rounded_rectangle([80, ry, 1000, ry + 122], radius=24, fill=C_PANEL, outline=(36, 95, 78), width=2)
                d.text((120, ry + 24), pair, font=get_font("display", 38), fill=C_WHITE)
                d.text((120, ry + 72), liq, font=get_font("mono_med", 24), fill=C_MUTED)
                d.text((535, ry + 40), chg, font=get_font("mono", 36), fill=C_EMERALD_BRIGHT)
                draw_pill(d, 855, ry + 61, tag, C_EMERALD_BRIGHT, (10, 44, 34), C_EMERALD, 24)

        if t >= 33.75:
            u = ease_out_cubic((t - 33.75) / 0.85)
            draw_score_ring(base, W // 2, 1185, 155, int(u * 94), C_EMERALD_BRIGHT, "CLEAN VERIFIED")
            d = ImageDraw.Draw(base)
            draw_centered_text(d, 1445, "ZERO HIDDEN MINT · HEALTHY POOL", "mono", 34, C_EMERALD_BRIGHT)
            draw_centered_text(d, 1515, "GREEN MEANS GO.", "black", 88, C_WHITE)

    # =========================================================================
    # ACT VI (Bars 20..24 | 37.50s - 45.00s): SAFEAPK & WALLET DRAINER GUARD
    # =========================================================================
    elif t < 45.0:
        s0 = spring(t - 37.5)
        draw_centered_text(d, int(215 + (1 - s0) * 40), "MODDED SNIPER APK?", "display", 74, C_AMBER_BRIGHT)
        draw_centered_text(d, int(310 + (1 - s0) * 55), "SCAN BEFORE INSTALLING.", "black", 76, C_WHITE)

        d.rounded_rectangle([76, 455, 1004, 1340], radius=36, fill=C_PANEL, outline=C_AMBER if t < 41.25 else C_CRIMSON, width=3)
        d.text((124, 505), "FILE: SniperBot_Pro_Mod_v4.apk", font=get_font("mono", 30), fill=C_WHITE)
        d.text((124, 555), "SHA-256 · 64-BLOCK SHANNON ENTROPY: 7.82 b/B", font=get_font("mono_med", 23), fill=C_MUTED)

        # Animated 36-bar Shannon Entropy Wave
        for bi in range(36):
            bx = 124 + bi * 23
            wave_h = int(55 + 95 * (0.5 + 0.5 * math.sin(bi * 0.45 + t * 7.0)))
            col = C_CRIMSON if wave_h > 118 else C_AMBER_BRIGHT
            d.rounded_rectangle([bx, 790 - wave_h, bx + 15, 790], radius=4, fill=col)

        flags = [
            (40.2, "BIP-39 SEED PHRASE HARVESTER"),
            (40.8, "ANDROID ACCESSIBILITY OVERLAY"),
            (41.4, "TELEGRAM BOT KEY EXFILTRATION"),
        ]
        for idx, (ft, ftxt) in enumerate(flags):
            if t >= ft:
                s = spring(t - ft, 0.3)
                fy = int(855 + idx * 105 + (1 - s) * 30)
                d.rounded_rectangle([120, fy, 960, fy + 84], radius=16, fill=(52, 16, 22), outline=C_CRIMSON, width=2)
                draw_badge_icon(d, 166, fy + 42, "warn")
                d.text((206, fy + 24), ftxt, font=get_font("mono", 27), fill=C_WHITE)

        if t >= 43.125:
            s = spring(t - 43.125)
            draw_centered_text(d, int(1415 + (1 - s) * 45), "YOUR SEED PHRASE", "display", 72, C_MUTED)
            draw_centered_text(d, int(1510 + (1 - s) * 55), "STAYS YOURS.", "black", 112, C_EMERALD_BRIGHT)

    # =========================================================================
    # ACT VII (Bars 24..28 | 45.00s - 52.50s): 3 FREE SCANS + $19 PRO OFFER
    # =========================================================================
    elif t < 52.5:
        if t < 48.75:
            s = spring(t - 45.0)
            draw_centered_text(d, int(390 + (1 - s) * 50), "3 FREE SCANS", "black", 122, C_EMERALD_BRIGHT)
            draw_centered_text(d, int(540 + (1 - s) * 65), "EVERY SINGLE DAY.", "black", 88, C_WHITE)
            if t >= 46.875:
                s2 = spring(t - 46.875)
                draw_pill(d, W // 2, int(790 + (1 - s2) * 35), "ZERO SIGNUP · ZERO APP STORE", C_WHITE, C_PANEL_2, C_INDIGO_BRIGHT, 32)
                draw_pill(d, W // 2, int(915 + (1 - s2) * 35), "INSTANT IN BRAVE & MOBILE BROWSER", C_EMERALD_BRIGHT, C_PANEL_2, C_EMERALD, 30)
                draw_pill(d, W // 2, int(1040 + (1 - s2) * 35), "1-TAP WHATSAPP · X · TELEGRAM ALERTS", C_AMBER_BRIGHT, C_PANEL_2, C_AMBER, 28)
        else:
            s = spring(t - 48.75, 0.38)
            cy_off = int((1 - s) * 70)
            # Luxury Pro Tier Card
            glow = make_glow_disc(430, C_EMERALD, 85)
            base.paste(glow, (W // 2 - 430, 880 - 430 + cy_off), glow)
            d = ImageDraw.Draw(base)
            d.rounded_rectangle([88, 370 + cy_off, 992, 1290 + cy_off], radius=42, fill=C_PANEL, outline=C_EMERALD_BRIGHT, width=4)
            draw_pill(d, W // 2, 455 + cy_off, "ALPHASHIELD PRO UNLIMITED", C_EMERALD_BRIGHT, (10, 46, 36), C_EMERALD, 28)
            draw_centered_text(d, 540 + cy_off, "$19 / MONTH", "black", 126, C_WHITE)
            draw_centered_text(d, 695 + cy_off, "INSTANT USDT CHECKOUT · GLOBAL", "mono", 30, C_INDIGO_BRIGHT)

            perks = [
                "UNLIMITED MULTI-CHAIN RUG SCANS",
                "UNLIMITED APK & DRAINER AUDITS",
                "FULL 14-TRAP SELECTOR BREAKDOWN",
                "AUTO ON-CHAIN RECEIPT UNLOCK",
            ]
            for pi, pk in enumerate(perks):
                py = 805 + pi * 88 + cy_off
                draw_badge_icon(d, 175, py + 21, "check")
                d.text((216, py), pk, font=get_font("bold", 33), fill=C_WHITE)

            if t >= 50.625:
                s3 = spring(t - 50.625)
                draw_centered_text(d, int(1385 + (1 - s3) * 40), "DODGE JUST ONE RUG—", "display", 66, C_MUTED)
                draw_centered_text(d, int(1475 + (1 - s3) * 50), "IT PAYS FOR ALL YEAR.", "black", 80, C_EMERALD_BRIGHT)

    # =========================================================================
    # ACT VIII (Bars 28..32 | 52.50s - 60.00s): GRAND FINALE & CTA URL
    # =========================================================================
    else:
        dt = t - 52.5
        draw_shield_emblem(base, W // 2, 520, int(155 * spring(dt, 0.4)), C_EMERALD_BRIGHT, kick_pulse)
        d = ImageDraw.Draw(base)

        s1 = spring(dt, 0.38)
        draw_centered_text(d, int(760 + (1 - s1) * 40), "SCAN BEFORE YOU BUY.", "display", 68, C_EMERALD_BRIGHT)
        draw_centered_text(d, int(855 + (1 - s1) * 50), "ALPHASHIELD", "black", 124, C_WHITE)
        draw_centered_text(d, int(1000 + (1 - s1) * 55), "by Gandoh Bah Ai", "display", 52, C_INDIGO_BRIGHT)

        # Glowing Hero URL CTA Button (tinyurl.com/y9zptyn4)
        pulse_pad = int(6 * kick_pulse)
        bx0, by0, bx1, by1 = 76 - pulse_pad, 1145 - pulse_pad, 1004 + pulse_pad, 1345 + pulse_pad
        btn_glow = make_glow_disc(360, C_EMERALD, int(75 + 45 * kick_pulse))
        base.paste(btn_glow, (W // 2 - 360, 1245 - 360), btn_glow)
        d = ImageDraw.Draw(base)
        d.rounded_rectangle([bx0, by0, bx1, by1], radius=46, fill=C_EMERALD, outline=C_WHITE, width=4)
        draw_centered_text(d, 1205, "tinyurl.com/y9zptyn4", "mono", 64, (3, 32, 23), max_w=870, shadow=False)

        draw_centered_text(d, 1415, "3 FREE SCANS DAILY · OPEN IN BRAVE NOW", "bold", 36, C_WHITE)
        draw_pill(d, W // 2, 1545, "ETH · BASE · BNB · ARBITRUM · APK GUARD", C_INDIGO_BRIGHT, C_PANEL_2, C_INDIGO, 26)

    # Bottom Progress Hairline
    prog_w = int((W - 136) * (t / DURATION))
    d.rounded_rectangle([68, 1816, W - 68, 1826], radius=5, fill=(24, 34, 58))
    if prog_w > 6:
        d.rounded_rectangle([68, 1816, 68 + prog_w, 1826], radius=5, fill=theme_col)

    # Trigger brief RGB Chromatic Split on dramatic impact beats!
    if (3.75 <= t < 4.18) or (24.375 <= t < 24.72) or (41.25 <= t < 41.55):
        base = apply_rgb_glitch(base, int(12 * kick_pulse) + 4)

    # Seamless loop fade at 0..0.35s and 59.45..60.0s
    if t < 0.35:
        base = Image.blend(Image.new("RGB", (W, H), C_BG), base, t / 0.35)
    elif t > 59.45:
        base = Image.blend(Image.new("RGB", (W, H), C_BG), base, max(0.0, (60.0 - t) / 0.55))

    # Save 8 inspection keyframes for visual QA
    keyframe_map = {
        45: "act1_pump.png",
        135: "act1_crash.png",
        365: "act2_bytecode.png",
        540: "act3_brand.png",
        795: "act4_honeypot.png",
        1060: "act5_dex_clean.png",
        1275: "act6_apk_guard.png",
        1530: "act7_pro_19.png",
        1695: "act8_cta_url.png",
    }
    if fi in keyframe_map:
        base.save(os.path.join(PREVIEW_DIR, keyframe_map[fi]))

    return base.tobytes()


def main():
    t0 = time.time()
    print("1/3 Synthesizing 60.000s 128-BPM dark-electronic score...")
    env_bars = synthesize_score(WAV_PATH)
    print(f"    Score ready in {time.time() - t0:.2f}s -> {WAV_PATH}")

    print("2/3 Building volumetric plates...")
    plates = build_base_plates()

    ffmpeg_bin = imageio_ffmpeg.get_ffmpeg_exe()
    cmd = [
        ffmpeg_bin,
        "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-pix_fmt", "rgb24",
        "-s", f"{W}x{H}",
        "-r", str(FPS),
        "-i", "-",
        "-i", WAV_PATH,
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "20",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        "-movflags", "+faststart",
        MP4_PATH,
    ]
    print("3/3 Rendering 1,800 Full-HD (1080x1920) frames directly into H.264 + AAC MP4...")
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdin is not None
    for fi in range(TOTAL_FRAMES):
        raw = render_frame(fi, plates, env_bars[fi])
        proc.stdin.write(raw)
        if (fi + 1) % 300 == 0:
            print(f"    Rendered {fi + 1}/{TOTAL_FRAMES} frames ({(fi + 1) / FPS:.0f}s / 60s)...")
    proc.stdin.close()
    stderr_out = proc.stderr.read().decode("utf8", errors="replace") if proc.stderr else ""
    rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"FFmpeg failed ({rc}):\n{stderr_out[-1200:]}")
    sz_mb = os.path.getsize(MP4_PATH) / (1024 * 1024)
    print(f"DONE in {time.time() - t0:.1f}s! Output: {MP4_PATH} ({sz_mb:.2f} MB)")


if __name__ == "__main__":
    main()

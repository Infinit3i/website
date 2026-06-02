#!/usr/bin/env python3
"""Inject an HTB-style pentagon 'Machine Matrix' radar into HTB posts.
Reads matrix_data.json: list of {file, ratings:[enum,reallife,cve,custom,ctf] (0-5), blurb}.
Idempotent: skips posts that already contain '## Machine Matrix'.
Inserts the block immediately before the SECOND H2 heading (after Overview)."""
import json, math, os, sys

POSTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_posts")
R = 110.0  # full radius at rating 5
CX = CY = 150.0
# axis angles (deg), clockwise from top: Enum, Real-Life, CVE, Custom, CTF
ANG = [-90, -18, 54, 126, 198]

def pt(ang, rad):
    a = math.radians(ang)
    return (CX + rad * math.cos(a), CY + rad * math.sin(a))

def poly(scale):  # scale 0..1 → points string for a full pentagon ring
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in (pt(a, R * scale) for a in ANG))

def data_poly(ratings):
    out = []
    for a, v in zip(ANG, ratings):
        x, y = pt(a, R * (max(0, min(5, v)) / 5.0))
        out.append(f"{x:.1f},{y:.1f}")
    return " ".join(out)

# precomputed static label coords (anchor, x, y, text)
LABELS = [
    ("middle", 150, 28, "Enumeration"),
    ("start", 278, 112, "Real-Life"),
    ("start", 226, 258, "CVE"),
    ("end", 74, 258, "Custom Exploitation"),
    ("end", 22, 112, "CTF-like"),
]

def spokes():
    lines = []
    for a in ANG:
        x, y = pt(a, R)
        lines.append(f'    <line x1="150" y1="150" x2="{x:.1f}" y2="{y:.1f}"/>')
    return "\n".join(lines)

def build(ratings, blurb):
    label_svg = "\n".join(
        f'    <text x="{x}" y="{y}"' + (f' text-anchor="{a}"' if a != "middle" else "") + f'>{t}</text>'
        for a, x, y, t in LABELS
    )
    return f'''## Machine Matrix

<div style="text-align:center;margin:1.5rem 0;">
<svg viewBox="-60 0 420 300" width="420" style="max-width:100%;font-family:sans-serif;font-size:13px;">
  <polygon points="{poly(1.0)}" fill="none" stroke="#888" stroke-opacity="0.4"/>
  <polygon points="{poly(0.666)}" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <polygon points="{poly(0.333)}" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <g stroke="#888" stroke-opacity="0.4">
{spokes()}
  </g>
  <polygon points="{data_poly(ratings)}" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
{label_svg}
  </g>
</svg>
</div>

{blurb}

'''

def insert(text, block):
    lines = text.splitlines(keepends=True)
    h2 = [i for i, l in enumerate(lines) if l.startswith("## ")]
    if len(h2) < 2:
        # fall back: after frontmatter (second '---')
        dashes = [i for i, l in enumerate(lines) if l.strip() == "---"]
        idx = (dashes[1] + 1) if len(dashes) >= 2 else 0
    else:
        idx = h2[1]
    return "".join(lines[:idx]) + block + "".join(lines[idx:])

def main():
    data = json.load(open(sys.argv[1] if len(sys.argv) > 1 else
                         os.path.join(os.path.dirname(__file__), "matrix_data.json")))
    done, skip = 0, 0
    for e in data:
        path = os.path.join(POSTS, e["file"])
        if not os.path.exists(path):
            print(f"MISSING {e['file']}"); continue
        txt = open(path).read()
        if "## Machine Matrix" in txt:
            skip += 1; continue
        open(path, "w").write(insert(txt, build(e["ratings"], e["blurb"].strip())))
        done += 1
        print(f"OK {e['file']} {e['ratings']}")
    print(f"\ninjected={done} skipped={skip}")

if __name__ == "__main__":
    main()

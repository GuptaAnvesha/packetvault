"""Show the three M7 benchmark graphs together in one window.

    python scripts/show_graphs.py                 # graphs committed in docs/benchmarks
    python scripts/show_graphs.py demo/results    # graphs from a fresh `packetvault bench` run
"""

import sys
from pathlib import Path

import matplotlib.image as mpimg
import matplotlib.pyplot as plt

GRAPHS = (
    ("bench_aes_modes.png", "AES modes: CBC vs CTR vs GCM"),
    ("bench_hashes.png", "Hashes: MD5 vs SHA-1 vs SHA-256"),
    ("bench_rsa_vs_ecc.png", "RSA-2048 vs ECC P-256"),
)

folder = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "docs" / "benchmarks"
missing = [name for name, _ in GRAPHS if not (folder / name).exists()]
if missing:
    sys.exit(f"missing in {folder}: {', '.join(missing)} (run `python -m packetvault bench` first)")

fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
fig.canvas.manager.set_window_title("PacketVault benchmarks")
for ax, (name, title) in zip(axes, GRAPHS):
    ax.imshow(mpimg.imread(folder / name))
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.axis("off")
fig.tight_layout()
plt.show()

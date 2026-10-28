import io
import shutil
from pathlib import Path

repo = Path(r"D:\hdu-work1")
shot_src = Path(r"D:\[HDU-CS4-26-27-1] Information Security\work1\screenshots")
shot_dst = repo / "docs" / "screenshots"

# 1. copy the evidence screenshots into the repository
shot_dst.mkdir(parents=True, exist_ok=True)
for png in sorted(shot_src.glob("*.png")):
    shutil.copy2(png, shot_dst / png.name)
print("copied", len(list(shot_dst.glob('*.png'))), "screenshots")

# 2. replace the "Screenshots to attach" list with real embedded images
readme = repo / "README.md"
s = io.open(readme, encoding="utf-8").read()

old = """**Screenshots to attach** (open *Actions → latest run → job → step*):
1. The green run overview with all three jobs.
2. `sast` job log showing `No issues identified`.
3. `sca` job log showing `No known vulnerabilities found`.
4. Artifacts section with `bandit-report` and `pip-audit-report`."""

new = """### Evidence from the Actions tab

The three jobs on the captured run (all green, 3 artifacts):

![Actions run: Tests, SAST and SCA all successful](docs/screenshots/02-actions-overview.png)

The SAST job log - bandit reports no issues at `-ll`:

![SAST job: bandit - No issues identified](docs/screenshots/03-sast-bandit.png)

The SCA job log - pip-audit reports no known vulnerabilities:

![SCA job: pip-audit - No known vulnerabilities found](docs/screenshots/04-sca-pip-audit.png)

The same three checks can be reproduced locally (`reports/` holds the output):
`pytest` 25 passed, `bandit` no issues, `pip-audit` no known vulnerabilities."""

assert old in s, "README anchor not found"
s = s.replace(old, new)

# 3. embed the "attack no longer works" proof in section 8, if not already there
anchor = "### Measured result"
if anchor in s and "07-fixed.png" not in s:
    proof = """### Measured result

The same request against the fixed image - the script no longer runs:

![Fixed 1.4.4: the script is rejected](docs/screenshots/07-fixed.png)
"""
    s = s.replace(anchor, proof, 1)

io.open(readme, "w", encoding="utf-8").write(s)
print("README patched, image refs:", s.count("docs/screenshots/"))

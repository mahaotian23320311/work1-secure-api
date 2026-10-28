import io
from pathlib import Path

readme = Path(r"D:\hdu-work1\README.md")
s = io.open(readme, encoding="utf-8").read()

# 1. screenshot of the successful RCE, right after the "uid=0(root)" block
anchor = "# uid=0(root) gid=0(root) groups=0(root)"
if anchor in s and "05-cve-vulnerable.png" not in s:
    idx = s.index(anchor)
    end = s.index("```", idx) + 4          # close of the code fence
    insert = "\n![Vulnerable 1.1.1: the request runs a shell command as root](docs/screenshots/05-cve-vulnerable.png)\n"
    s = s[:end] + insert + s[end:]
    print("added 05 in section 6")

# 2. screenshot of the hardened refusal, after the measured-result table
anchor2 = "After the fix the attack is rejected, nothing is executed, and the same"
if anchor2 in s and "08-hardened.png" not in s:
    insert2 = ("![Hardened 1.1.1: the same request is refused](docs/screenshots/08-hardened.png)\n\n")
    s = s.replace(anchor2, insert2 + anchor2, 1)
    print("added 08 in section 8")

io.open(readme, "w", encoding="utf-8").write(s)
print("total image refs:", s.count("docs/screenshots/"))

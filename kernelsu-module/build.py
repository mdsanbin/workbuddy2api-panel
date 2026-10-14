#!/usr/bin/env python3
"""打包 WorkBuddy2API 的 KernelSU / Magisk 模块 zip。

用法（在本文件所在目录）：
    python build.py

产物：<仓库根>/dist/workbuddy2api-kernelsu-v<模块版本>-arm64.zip

打包前会做几项防呆校验——这些错了发出去就是「装到手机上才发现」：
    - bin/wb2api 必须是 ELF aarch64（本机是 amd64，漏跑交叉编译时最容易踩）
    - module.prop 的 versionCode 必须与 version 折算值一致
    - config/config.json 必须是合法 JSON
    - 所有文本文件统一成 LF（Android 的 mksh 对 CRLF 脚本会报 not found）
并把二进制里的网关版本串抽出来写成 bin/version.txt，供 updater.sh 判版本。
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import struct
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent          # kernelsu-module/
REPO = ROOT.parent                                      # 仓库根

# 这些文件在 zip 里必须是 0755
EXEC_FILES = {
    "bin/wb2api",
    "customize.sh",
    "service.sh",
    "watcher.sh",
    "updater.sh",
    "action.sh",
    "uninstall.sh",
}

REQUIRED = [
    "module.prop",
    "bin/wb2api",
    "service.sh",
    "watcher.sh",
    "updater.sh",
    "config/config.json",
]

TEXT_SUFFIXES = {".sh", ".prop", ".json", ".md", ".txt"}
BINARY_NAMES = {"wb2api"}

ELF_MACHINE_AARCH64 = 0xB7
GATEWAY_VERSION_RE = re.compile(rb"\d+\.\d+\.\d+-panel")

CROSS_BUILD_HINT = (
    '请先交叉编译：GOOS=linux GOARCH=arm64 CGO_ENABLED=0 '
    'go build -trimpath -ldflags "-s -w" -o kernelsu-module/bin/wb2api ./cmd/server'
)


def fail(msg: str) -> None:
    print(f"[x] {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_prop() -> tuple[str, int]:
    prop = (ROOT / "module.prop").read_text(encoding="utf-8")
    version = ""
    code = -1
    for line in prop.splitlines():
        if line.startswith("version="):
            version = line.split("=", 1)[1].strip()
        elif line.startswith("versionCode="):
            raw = line.split("=", 1)[1].strip()
            code = int(raw) if raw.isdigit() else -1
    if not version:
        fail("module.prop 里没有 version= 字段")
    return version, code


def version_code(v: str) -> int:
    """与 CI（magisk-release.yml）同一套折算：a*10000 + b*100 + c。"""
    core = v.split("-")[0].split(".")
    if len(core) < 2 or not all(p.isdigit() for p in core[:3]):
        fail(f"版本号格式异常：{v}")
    return int(core[0]) * 10000 + int(core[1]) * 100 + (int(core[2]) if len(core) > 2 else 0)


def check_binary(path: pathlib.Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 64:
        fail(f"{path.name} 太小，不像是二进制")
    if data[:4] != b"\x7fELF":
        fail(
            f"{path.name} 不是 ELF 文件（magic={data[:4].hex()}）——"
            "多半是把 Windows 版打进来了。" + CROSS_BUILD_HINT
        )
    if data[4] != 2:
        fail(f"{path.name} 不是 64 位 ELF（class={data[4]}）")
    if data[5] != 1:
        fail(f"{path.name} 不是小端 ELF（endian={data[5]}）")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != ELF_MACHINE_AARCH64:
        fail(
            f"{path.name} 的架构码是 {machine}，不是 aarch64(183)。" + CROSS_BUILD_HINT
        )
    return data


def extract_gateway_version(data: bytes) -> str:
    m = GATEWAY_VERSION_RE.search(data)
    if not m:
        fail("二进制里找不到形如 1.13.0-panel 的网关版本串，无法生成 bin/version.txt")
    return m.group(0).decode("ascii")


def collect() -> list[tuple[pathlib.Path, str]]:
    items: list[tuple[pathlib.Path, str]] = []
    for p in sorted(ROOT.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel in ("build.py", "selftest.sh") or rel.startswith("dist/") or "__pycache__" in rel:
            continue
        items.append((p, rel))
    return items


def is_text(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    if name in BINARY_NAMES:
        return False
    return pathlib.PurePosixPath(rel).suffix.lower() in TEXT_SUFFIXES


def main() -> int:
    version, code = read_prop()
    expect = version_code(version)
    if code != expect:
        fail(f"module.prop 的 versionCode={code} 与 version={version} 的折算值 {expect} 不一致")
    print(f"模块版本      : {version}（versionCode={code}）")

    missing = [r for r in REQUIRED if not (ROOT / r).exists()]
    if missing:
        print("缺少必需文件: " + ", ".join(missing), file=sys.stderr)
        print(CROSS_BUILD_HINT, file=sys.stderr)
        return 1

    data = check_binary(ROOT / "bin" / "wb2api")
    print(f"二进制架构    : ELF64 aarch64（{len(data):,} bytes）")

    gw = extract_gateway_version(data)
    (ROOT / "bin" / "version.txt").write_bytes((gw + "\n").encode("utf-8"))
    print(f"内置网关版本  : {gw}（已写入 bin/version.txt，供 updater.sh 判版本）")

    try:
        json.loads((ROOT / "config" / "config.json").read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - 只做校验，原样报错即可
        fail(f"config/config.json 不是合法 JSON：{exc}")

    items = collect()
    if "module.prop" not in {rel for _, rel in items}:
        fail("module.prop 不在模块根，模块结构不对")

    out = REPO / "dist" / f"workbuddy2api-kernelsu-v{version}-arm64.zip"
    out.parent.mkdir(parents=True, exist_ok=True)

    converted: list[str] = []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path, rel in items:
            raw = path.read_bytes()
            if is_text(rel) and b"\r" in raw:
                raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                converted.append(rel)
            zi = zipfile.ZipInfo(rel)
            # 固定时间戳，保证同样输入产出同样 zip
            zi.date_time = (1980, 1, 1, 0, 0, 0)
            mode = 0o755 if rel in EXEC_FILES else 0o644
            zi.external_attr = (mode | 0o100000) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, raw)

    if converted:
        print("已把 CRLF 归一为 LF : " + ", ".join(converted))
    else:
        print("行尾          : 全部已是 LF")

    payload = out.read_bytes()
    sha = hashlib.sha256(payload).hexdigest()
    (out.with_suffix(".zip.sha256")).write_text(f"{sha}  {out.name}\n", encoding="utf-8")

    print(f"打包完成      : {out}")
    print(f"大小          : {len(payload):,} bytes（{len(payload) / 1024 / 1024:.2f} MiB）")
    print(f"SHA256        : {sha}")
    print(f"条目          : {len(items)} 个")
    for _, rel in items:
        flag = "0755" if rel in EXEC_FILES else "0644"
        print(f"  {flag}  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

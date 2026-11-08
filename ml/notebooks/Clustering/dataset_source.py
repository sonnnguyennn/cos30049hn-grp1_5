"""Fetch the configured dataset package only when the local copy is missing."""
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlencode, urlsplit

from clustering_utils import matching_manifest


def drive_source(url):
    """Return a direct download URL for a Drive file, or the original folder URL."""
    link = urlsplit(url)
    if link.scheme != "https" or link.netloc != "drive.google.com":
        raise ValueError("drive_url must be an https://drive.google.com share link.")
    query = parse_qs(link.query)
    file_match = re.fullmatch(r"/file/d/([\w-]+)(?:/.*)?", link.path, re.ASCII)
    if re.fullmatch(r"/drive/(?:u/\d+/)?folders/[\w-]+/?", link.path, re.ASCII):
        return "folder", url
    file_id = file_match[1] if file_match else ""
    if link.path in {"/open", "/uc"}:
        file_id = query.get("id", [""])[0]
    if not re.fullmatch(r"[\w-]+", file_id, re.ASCII):
        raise ValueError("Use a Google Drive file or folder share link for drive_url.")
    download_query = {"id": file_id, "export": "download"}
    if "resourcekey" in query:
        download_query["resourcekey"] = query["resourcekey"][0]
    return "file", "https://drive.google.com/uc?" + urlencode(download_query)


def extract_archive(archive_path, destination):
    """Unpack a ZIP or tar archive into an isolated staging directory."""
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            for member in members:
                path = PurePosixPath(member.filename)
                if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                        or ":" in member.filename or stat.S_ISLNK(member.external_attr >> 16)):
                    raise ValueError("The downloaded ZIP contains an unsafe path.")
            required = sum(member.file_size for member in members)
            if required > shutil.disk_usage(destination).free:
                raise OSError(f"Need {required / 2**30:.1f} GiB of free space to unpack the dataset.")
            for member in members:
                if not member.is_dir():
                    print("Extracting", member.filename, flush=True)
                archive.extract(member, destination)
        return

    try:
        with tarfile.open(archive_path, mode="r|*") as archive:
            for member in archive:
                if not (member.isdir() or member.isfile()):
                    raise ValueError("The downloaded tar archive contains a link or special file.")
                if not member.isdir():
                    print("Extracting", member.name, flush=True)
                archive.extract(member, destination, filter="data")
    except tarfile.ReadError as error:
        raise ValueError("The Drive file must be a ZIP or tar archive of the full dataset package.") from error


def prepare_package(cfg, drive_url):
    """Download, check the expected manifest, and place the package at package_dir."""
    target = Path(cfg["package_dir"])
    if (target / "primary_package.py").is_file():
        print("Using local dataset package at", target, flush=True)
        return target
    if target.exists():
        raise FileExistsError(f"{target} exists without primary_package.py. "
                              "Move the incomplete folder aside before running again.")
    if not drive_url:
        raise FileNotFoundError("The dataset is missing locally. Set drive_url in experiment_config.json.")
    kind, url = drive_source(drive_url.strip())
    try:
        import gdown
    except ModuleNotFoundError as error:
        raise ModuleNotFoundError("Install the updated requirements.txt in your notebook environment.") from error

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".dataset-download-", dir=target.parent) as temporary:
        staging = Path(temporary)
        extracted = staging / "package"
        extracted.mkdir()
        print("Downloading the dataset from Google Drive. The first download is several GiB.", flush=True)
        try:
            if kind == "folder":
                result = gdown.download_folder(url=url, output=str(extracted) + os.sep, quiet=False)
            else:
                archive_path = staging / "dataset.archive"
                result = gdown.download(url=url, output=str(archive_path), quiet=False)
        except gdown.exceptions.DownloadError as error:
            raise RuntimeError("Google Drive download failed. Check link access and download limits.") from error
        if not result:
            raise RuntimeError("Google Drive download failed. Check link access and download limits.")
        if kind == "file":
            extract_archive(archive_path, extracted)

        loaders = list(extracted.rglob("primary_package.py"))
        if len(loaders) != 1:
            raise ValueError("Expected exactly one primary_package.py in the downloaded dataset package.")
        package = loaders[0].parent
        matching_manifest(package, cfg["expected_manifest_sha256"])
        package.rename(target)

    print("Saved dataset package at", target, flush=True)
    return target

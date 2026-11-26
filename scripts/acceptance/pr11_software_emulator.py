#!/usr/bin/env python3
"""One bounded, unprivileged TCG smoke probe of the caller-verified PR11 APK.

This module never signs, rebuilds, substitutes or downloads an APK. It does not
obtain app keys, authenticate MCP, access app-private files, or log into LINE.
A True return means only that the explicitly listed smoke stages completed;
full Android/MCP acceptance remains incomplete. Importing it performs no probe.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile

APK_SHA256 = "cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4"
IMAGE_URL = "https://dl.google.com/android/repository/sys-img/android/x86_64-29_r08-linux.zip"
IMAGE_BYTES = 689676765
IMAGE_SHA1 = "e4b798d6fcddff90d528d74ef22ce3dd4a2ca798"
IMAGE_EXPANSION_CAP = 3500000000
PACKAGE = "tw.linemcp.app.review"
ACTIVITY = PACKAGE + "/tw.linemcp.app.MainActivity"
SERIAL = "emulator-5566"
CONSOLE_PORT = 5566
ADB_PORT = 5039
TOTAL_SECONDS = 480
BOOT_SECONDS = 300
CAPTURE_BYTES = 512 * 1024


class ProbeStop(RuntimeError):
    def __init__(self, reason, timed_out=False):
        super().__init__(reason)
        self.reason = reason
        self.timed_out = timed_out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Capture:
    """Drain an owned process continuously while retaining bounded diagnostics."""
    def __init__(self, process, path):
        self.process = process
        self.path = path
        self.total = 0
        self.kept = 0
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _drain(self):
        with self.path.open("wb") as output:
            while True:
                chunk = self.process.stdout.read(4096)
                if not chunk:
                    break
                self.total += len(chunk)
                retained = chunk[:max(0, CAPTURE_BYTES - self.kept)]
                if retained:
                    output.write(retained)
                    output.flush()
                    self.kept += len(retained)


def run_software(apk_path: Path, emulator: Path, adb: Path, tool_env: dict,
                 out: Path, state: dict, save: callable) -> bool:
    started = time.monotonic()
    hard_end = started + TOTAL_SECONDS
    # Reserve cleanup time within the same eight-minute function budget.
    work_end = hard_end - 15
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    receipt = {
        "scope": "empty API29 x86_64 AOSP guest; bounded TCG app smoke only",
        "expected_apk_sha256": APK_SHA256,
        "serial": SERIAL, "adb_server": "tcp:127.0.0.1:5039",
        "limits": {"total_seconds": TOTAL_SECONDS, "boot_seconds": BOOT_SECONDS,
                   "guest_ram_mib": 1024, "guest_cores": 2, "accelerator": "off"},
        "result": "attempted", "emulator_launch_count": 0, "stages": {}, "commands": [],
        "not_tested": ["MCP PSK authentication", "SDK MCP tools/read-only authorization",
                       "physical device", "arm64", "16KiB device unless observed",
                       "LINE login/sync", "cloud provider", "old-install upgrade"],
        "network_limit": "No harness third-party probes or app credentials; no host network policy changed.",
    }
    stage_names = ("software_input", "system_image", "avd_boot", "guest_identity",
                   "install", "cold_start", "native_endpoint_hello",
                   "background_foreground", "restart", "native_endpoint_hello_after_restart")
    for name in stage_names:
        receipt["stages"][name] = {"status": "not_attempted"}
        state[name] = "not_attempted"
    state["android_mcp_readonly"] = "not_attempted"
    state["android_mcp_auth_proof"] = "not_attempted"
    state["android_mcp_tools"] = "not_attempted"
    state["android_mcp_unverified_reason"] = "No normal UI key provisioning in this smoke probe; HTTP204 is not authentication or a tool result."
    state["overall_android_acceptance"] = "incomplete"
    state["overall_acceptance"] = "incomplete"
    state["phase"] = "bounded_software_emulator_smoke"
    active = None
    owned = []
    captures = []
    forwarded_port = None
    adb_prefix = None
    env = dict(tool_env)
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    smoke_ok = False
    cleanup_ok = True

    def elapsed():
        return round(time.monotonic() - started, 3)

    def flush():
        receipt["elapsed_seconds"] = elapsed()
        state["software_emulator_result"] = receipt["result"]
        (out / "software-emulator.json").write_text(json.dumps(receipt, indent=2) + "\n")
        save()

    def remaining(cap=30, deadline=None):
        limit = min(work_end, deadline) if deadline is not None else work_end
        left = limit - time.monotonic()
        if left <= 0:
            raise ProbeStop("bounded_probe_deadline", True)
        return max(0.05, min(float(cap), left))

    def begin(name):
        nonlocal active
        remaining()
        active = name
        state[name] = "attempted"
        receipt["stages"][name] = {"status": "attempted", "started_seconds": elapsed()}
        flush()

    def passed(**evidence):
        state[active] = "pass"
        receipt["stages"][active].update(status="pass", finished_seconds=elapsed(), **evidence)
        flush()

    def run(args, timeout=20, expected=(0,), deadline=None, readiness=False):
        args = [str(x) for x in args]
        item = {"argv": args, "at_seconds": elapsed()}
        try:
            result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", timeout=remaining(timeout, deadline))
            item.update(exit=result.returncode, output=result.stdout[:16000])
        except subprocess.TimeoutExpired:
            item.update(exit=124, output="command_timeout")
            receipt["commands"].append(item)
            flush()
            if readiness:
                return subprocess.CompletedProcess(args, 124, "readiness_command_timeout")
            raise ProbeStop("command_timeout", True)
        except OSError:
            item.update(exit=127, output="tool_execution_failed")
            receipt["commands"].append(item)
            flush()
            raise ProbeStop("tool_execution_failed")
        receipt["commands"].append(item)
        flush()
        if result.returncode not in expected:
            raise ProbeStop("command_nonzero_exit")
        return result

    def guest(*args, **kwargs):
        if adb_prefix is None or not owned or owned[0][1].poll() is not None:
            raise ProbeStop("owned_adb_server_not_running")
        return run(adb_prefix + list(args), **kwargs)

    def app_pid(expected_present=True):
        result = guest("shell", "pidof", PACKAGE, expected=(0, 1), timeout=10)
        value = result.stdout.strip()
        if expected_present:
            if result.returncode != 0 or not re.fullmatch(r"[0-9]+(?:\s+[0-9]+)*", value):
                raise ProbeStop("own_app_process_not_alive")
            return value.split()
        if value or result.returncode != 1:
            raise ProbeStop("own_app_force_stop_did_not_stop_process")
        return []

    def launch():
        result = guest("shell", "am", "start", "-W", "-n", ACTIVITY, timeout=35)
        if "Status: ok" not in result.stdout or re.search(r"(^|\n)\s*Error", result.stdout):
            raise ProbeStop("own_activity_start_not_ok")
        return app_pid()

    def hello(stage):
        nonlocal forwarded_port
        begin(stage)
        if forwarded_port is None:
            response = guest("forward", "tcp:0", "tcp:47833", timeout=10)
            if not re.fullmatch(r"[0-9]+\s*", response.stdout):
                raise ProbeStop("unexpected_forward_port")
            forwarded_port = int(response.stdout.strip())
            if not 1 <= forwarded_port <= 65535:
                raise ProbeStop("invalid_forward_port")
        # One credential-free request, never followed to another URL. This only
        # observes the endpoint; the returned proof is deliberately not logged.
        url = f"http://127.0.0.1:{forwarded_port}/mcp/secure/hello"
        request = urllib.request.Request(url, headers={"x-lma-mcp-challenge": os.urandom(16).hex()})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(
                    request, timeout=remaining(10)) as response:
                observed = {"http_status": response.status,
                            "epoch_header_present": bool(response.headers.get("x-lma-mcp-epoch")),
                            "proof_header_present_unverified": bool(response.headers.get("x-lma-mcp-proof"))}
                if response.status != 204:
                    raise ProbeStop("hello_not_204")
        except urllib.error.HTTPError as error:
            receipt["stages"][stage]["http_status"] = error.code
            error.close()
            raise ProbeStop("hello_http_rejected")
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            timed_out = isinstance(error, TimeoutError) or isinstance(getattr(error, "reason", None), TimeoutError)
            raise ProbeStop("hello_transport_failed", timed_out)
        passed(**observed, authentication_verified=False, mcp_tool_called=False)

    try:
        begin("software_input")
        if (state.get("fixed_input_verification") != "verified"
                or state.get("fixed_apk_hash") != "verified"):
            raise ProbeStop("caller_fixed_input_gate_not_verified")
        apk_path = Path(apk_path).resolve()
        if not apk_path.is_file() or not Path(emulator).is_file() or not Path(adb).is_file():
            raise ProbeStop("fixed_input_or_tools_missing")
        apk_hash = hashlib.sha256()
        with apk_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                remaining()
                apk_hash.update(chunk)
        if apk_hash.hexdigest() != APK_SHA256:
            raise ProbeStop("fixed_apk_changed_after_caller_gate")
        temp_parent = Path(env.get("RUNNER_TEMP", ""))
        if not env.get("RUNNER_TEMP") or not temp_parent.is_dir():
            raise ProbeStop("private_runner_temp_missing")
        work = Path(tempfile.mkdtemp(prefix="pr11-tcg-", dir=temp_parent))
        work.chmod(0o700)
        if shutil.disk_usage(work).free < 5 * 1024**3:
            raise ProbeStop("insufficient_private_probe_disk")
        for port in (ADB_PORT, CONSOLE_PORT, CONSOLE_PORT + 1):
            with socket.socket() as candidate:
                try:
                    candidate.bind(("127.0.0.1", port))
                except OSError:
                    raise ProbeStop("fixed_private_port_unavailable")
        passed(apk_sha256=apk_hash.hexdigest(), no_apk_substitution=True)

        begin("system_image")
        archive_path = work / "image.zip"
        image_hash = hashlib.sha1()
        image_sha256 = hashlib.sha256()
        count = 0
        with urllib.request.urlopen(IMAGE_URL, timeout=remaining(15)) as response, archive_path.open("wb") as output:
            if response.status != 200 or not response.geturl().startswith("https://"):
                raise ProbeStop("official_image_response_rejected")
            while True:
                remaining()
                chunk = response.read1(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > IMAGE_BYTES:
                    raise ProbeStop("official_image_size_cap")
                image_hash.update(chunk)
                image_sha256.update(chunk)
                output.write(chunk)
        if count != IMAGE_BYTES or image_hash.hexdigest() != IMAGE_SHA1:
            raise ProbeStop("official_image_identity_mismatch")
        image_root = work / "official-image"
        image_root.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or sum(x.file_size for x in archive.infolist()) > IMAGE_EXPANSION_CAP:
                raise ProbeStop("official_image_zip_inventory_rejected")
            for item in archive.infolist():
                remaining()
                name = Path(item.filename)
                if (name.is_absolute() or ".." in name.parts or "\\" in item.filename
                        or (item.external_attr >> 16) & 0o170000 == 0o120000):
                    raise ProbeStop("official_image_unsafe_zip_entry")
                destination = image_root / name
                if item.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as source, destination.open("wb") as output:
                        while True:
                            remaining()
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
        image = image_root / "x86_64"
        for required in ("source.properties", "kernel-ranchu", "ramdisk.img", "system.img", "vendor.img", "userdata.img"):
            if not (image / required).is_file():
                raise ProbeStop("official_image_required_member_missing")
        properties = {}
        for line in (image / "source.properties").read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                properties[key.strip()] = value.strip()
        if (properties.get("AndroidVersion.ApiLevel", "").strip() != "29"
                or properties.get("SystemImage.Abi", "").strip() != "x86_64"):
            raise ProbeStop("official_image_metadata_mismatch")
        passed(url=IMAGE_URL, bytes=count, repository_sha1=image_hash.hexdigest(),
               observed_sha256=image_sha256.hexdigest(), api=29, abi="x86_64", source="AOSP default r08")

        begin("avd_boot")
        config = work / "android-config"
        avd_home = config / "avd"
        avd = avd_home / "pr11_tcg_api29.avd"
        avd.mkdir(parents=True)
        (avd_home / "pr11_tcg_api29.ini").write_text(f"avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-29\n")
        (avd / "config.ini").write_text("\n".join([
            "AvdId=pr11_tcg_api29", "avd.ini.encoding=UTF-8", "PlayStore.enabled=false",
            "abi.type=x86_64", "hw.cpu.arch=x86_64", "hw.cpu.ncore=2", "hw.ramSize=1024",
            "hw.lcd.width=480", "hw.lcd.height=800", "hw.lcd.density=160",
            "hw.keyboard=yes", "hw.sdCard=no", "hw.gpu.enabled=yes", "hw.gpu.mode=swiftshader",
            "disk.dataPartition.size=768M", f"image.sysdir.1={image}/",
            "tag.id=default", "tag.display=Default", "showDeviceFrame=no",
            "fastboot.forceColdBoot=yes", "fastboot.forceFastBoot=no", "runtime.network.latency=none",
            "runtime.network.speed=full", ""]))
        env.update(ANDROID_USER_HOME=str(config), ANDROID_EMULATOR_HOME=str(config),
                   ANDROID_AVD_HOME=str(avd_home), ANDROID_SDK_HOME=str(work),
                   ADB_VENDOR_KEYS=str(config), ANDROID_ADB_SERVER_PORT=str(ADB_PORT),
                   ADB_SERVER_PORT=str(ADB_PORT), ADB_SERVER_SOCKET=f"tcp:127.0.0.1:{ADB_PORT}",
                   ANDROID_I_WANT_MY_TCG="yes")
        adb_prefix = [str(adb), "-H", "127.0.0.1", "-P", str(ADB_PORT), "-s", SERIAL]
        server_args = [str(adb), "-L", f"tcp:127.0.0.1:{ADB_PORT}", "server", "nodaemon"]
        server = subprocess.Popen(server_args, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        owned.append(("adb_server", server))
        captures.append(Capture(server, out / "owned-adb-server.txt"))
        receipt["owned_processes"] = {"adb_server_pid": server.pid}
        ready_until = time.monotonic() + remaining(5)
        while True:
            if server.poll() is not None:
                raise ProbeStop("owned_adb_server_exited")
            try:
                with socket.create_connection(("127.0.0.1", ADB_PORT), timeout=remaining(0.2, ready_until)):
                    break
            except (ConnectionError, OSError):
                remaining(1, ready_until)
                time.sleep(0.1)
        emulator_args = [str(emulator), "-avd", "pr11_tcg_api29", "-datadir", str(avd),
                         "-port", str(CONSOLE_PORT), "-no-window", "-no-audio", "-no-snapshot",
                         "-no-boot-anim", "-camera-back", "none", "-camera-front", "none",
                         "-gpu", "swiftshader", "-feature", "-Vulkan", "-accel", "off",
                         "-memory", "1024", "-cores", "2"]
        receipt["emulator_argv"] = emulator_args
        receipt["adb_server_argv"] = server_args
        process = subprocess.Popen(emulator_args, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        receipt["emulator_launch_count"] = 1
        owned.append(("emulator", process))
        captures.append(Capture(process, out / "owned-emulator.txt"))
        receipt["owned_processes"]["emulator_pid"] = process.pid
        boot_until = min(work_end, time.monotonic() + BOOT_SECONDS)
        flush()
        # Bounded readiness polling is not a second boot or an install retry.
        while True:
            if process.poll() is not None:
                raise ProbeStop("owned_emulator_exited_before_boot")
            response = guest("shell", "getprop", "sys.boot_completed", timeout=4,
                             expected=(0, 1, 124), deadline=boot_until, readiness=True)
            if response.returncode == 0 and response.stdout.strip() == "1":
                break
            remaining(1, boot_until)
            time.sleep(1)
        passed(sys_boot_completed="1", boot_mode="single_cold_boot_TCG", emulator_launches=1)

        begin("guest_identity")
        sdk = guest("shell", "getprop", "ro.build.version.sdk").stdout.strip()
        abi = guest("shell", "getprop", "ro.product.cpu.abi").stdout.strip()
        page = guest("shell", "getconf", "PAGE_SIZE").stdout.strip()
        virtual = guest("shell", "getprop", "ro.kernel.qemu").stdout.strip()
        if sdk != "29" or abi != "x86_64" or page not in ("4096", "16384") or virtual != "1":
            raise ProbeStop("unexpected_guest_identity")
        passed(api=int(sdk), abi=abi, page_size=int(page), emulator_property=virtual,
               page_size_coverage="observed guest only; no other page-size acceptance")

        begin("install")
        response = guest("install", "--no-streaming", str(apk_path), timeout=45)
        if not re.search(r"(^|\n)Success\s*($|\n)", response.stdout):
            raise ProbeStop("fixed_apk_install_not_successful")
        passed(install_attempts=1, apk_sha256=APK_SHA256, no_reinstall_or_permission_grant_flags=True)

        begin("cold_start")
        first_pid = launch()
        time.sleep(min(3, remaining(3)))
        if app_pid() != first_pid:
            raise ProbeStop("own_app_process_changed_after_cold_start")
        passed(activity=ACTIVITY, process_ids=first_pid,
               observed="Activity start status and own process liveness; no UI or key extraction")
        hello("native_endpoint_hello")

        begin("background_foreground")
        guest("shell", "input", "keyevent", "KEYCODE_HOME", timeout=10)
        time.sleep(min(3, remaining(3)))
        background_pid = app_pid()
        if background_pid != first_pid:
            raise ProbeStop("own_app_process_changed_in_background")
        foreground_pid = launch()
        if foreground_pid != first_pid:
            raise ProbeStop("own_app_process_changed_on_foreground")
        passed(home_seconds=3, before_pid=first_pid, background_pid=background_pid,
               foreground_pid=foreground_pid, background_scope="short HOME interval only")

        begin("restart")
        guest("shell", "am", "force-stop", PACKAGE, timeout=10)
        app_pid(expected_present=False)
        restarted_pid = launch()
        if restarted_pid == first_pid:
            raise ProbeStop("own_app_restart_pid_not_changed")
        time.sleep(min(3, remaining(3)))
        if app_pid() != restarted_pid:
            raise ProbeStop("own_app_process_changed_after_restart")
        passed(kind="own_app_force_stop_and_cold_start", before_pid=first_pid,
               after_pid=restarted_pid, guest_reboot=False, data_cleared=False)
        hello("native_endpoint_hello_after_restart")
        receipt["result"] = "completed_limited_smoke"
        smoke_ok = True
    except ProbeStop as error:
        status = "timeout" if error.timed_out else "fail"
        if active is not None and receipt["stages"][active]["status"] == "attempted":
            state[active] = status
            receipt["stages"][active].update(status=status, reason=error.reason, finished_seconds=elapsed())
        receipt["result"] = status
    except Exception as error:
        timed_out = isinstance(error, TimeoutError) or isinstance(getattr(error, "reason", None), TimeoutError)
        status = "timeout" if timed_out else "fail"
        if active is not None and receipt["stages"][active]["status"] == "attempted":
            state[active] = status
            receipt["stages"][active].update(status=status, reason="unexpected_software_probe_failure",
                                             exception_type=type(error).__name__, finished_seconds=elapsed())
        receipt["result"] = status
    finally:
        cleanup = {"status": "attempted", "scope": "only process groups created by this invocation"}
        receipt["stages"]["cleanup"] = cleanup
        if forwarded_port is not None and adb_prefix is not None and owned and owned[0][1].poll() is None:
            try:
                subprocess.run(adb_prefix + ["forward", "--remove", f"tcp:{forwarded_port}"], env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=max(0.05, min(2, hard_end - time.monotonic())))
            except Exception:
                cleanup_ok = False
        for name, process in reversed(owned):
            # start_new_session=True gave each owned launcher its own group;
            # terminating that group also covers its own QEMU subprocesses.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_ok = False
            try:
                process.wait(timeout=max(0.05, min(3, hard_end - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
            # A launcher can exit before its own QEMU child. Check the group
            # created by start_new_session, and never target a global name/PID.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                group_alive = False
            except OSError:
                group_alive = True
                cleanup_ok = False
            else:
                group_alive = True
            if group_alive:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=max(0.05, min(1, hard_end - time.monotonic())))
                except ProcessLookupError:
                    pass
                except Exception:
                    cleanup_ok = False
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                except OSError:
                    cleanup_ok = False
                else:
                    cleanup_ok = False
        for capture in captures:
            capture.thread.join(timeout=max(0, min(0.5, hard_end - time.monotonic())))
        cleanup.update(status="pass" if cleanup_ok else "fail", finished_seconds=elapsed(),
                       process_names=[name for name, _ in owned])
        receipt["diagnostic_captures"] = [{"file": item.path.name, "observed_bytes": item.total,
                                           "retained_bytes": item.kept, "truncated": item.total > item.kept}
                                          for item in captures]
        if not cleanup_ok:
            receipt["result"] = "failed_owned_process_cleanup"
        # Preserve unattempted MCP/auth/device stages even when smoke passed.
        state["overall_android_acceptance"] = "incomplete"
        state["overall_acceptance"] = "incomplete"
        flush()
    return smoke_ok and cleanup_ok

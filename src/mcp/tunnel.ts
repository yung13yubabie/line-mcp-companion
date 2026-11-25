/**
 * 選用：Cloudflare quick tunnel（不用帳號，網址 *.trycloudflare.com，每次重開會變）。
 * 只把「連接器閘道」(127.0.0.1:47825) 轉出去，不碰本機 MCP (47823) 與控制 API (47824)。
 * cloudflared 執行檔由使用者自行安裝（桌面 / Termux）；App 不內建。
 */
import { spawn, type ChildProcess } from "node:child_process";

export interface TunnelStatus {
	state: "off" | "starting" | "up" | "error";
	url: string | null;
	error: string | null;
	started_at: number | null;
}

export class QuickTunnel {
	#proc: ChildProcess | null = null;
	#status: TunnelStatus = { state: "off", url: null, error: null, started_at: null };
	#bin: string;
	onUrl: ((url: string | null) => void) | null = null;

	constructor(bin = process.env.LMA_CLOUDFLARED || "cloudflared") {
		this.#bin = bin;
	}

	status(): TunnelStatus {
		return { ...this.#status };
	}

	start(localPort: number, timeoutMs = 45_000): Promise<TunnelStatus> {
		if (this.#proc) return Promise.resolve(this.status());
		this.#status = { state: "starting", url: null, error: null, started_at: Date.now() };
		return new Promise((resolve) => {
			let done = false;
			const finish = () => {
				if (!done) {
					done = true;
					resolve(this.status());
				}
			};
			let p: ChildProcess;
			try {
				// --no-autoupdate：不自行更新；只轉 http://127.0.0.1:<port>；不寫設定檔
				p = spawn(this.#bin, ["tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${localPort}`], { stdio: ["ignore", "pipe", "pipe"] });
			} catch (e) {
				this.#status = { state: "error", url: null, error: (e as Error).message, started_at: null };
				return finish();
			}
			this.#proc = p;
			const onData = (b: Buffer) => {
				const m = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(b.toString());
				if (m && this.#status.state !== "up") {
					this.#status = { ...this.#status, state: "up", url: m[0] };
					this.onUrl?.(m[0]);
					finish();
				}
			};
			p.stdout?.on("data", onData);
			p.stderr?.on("data", onData);
			p.on("error", (e) => {
				this.#status = { state: "error", url: null, error: (e as NodeJS.ErrnoException).code === "ENOENT" ? "cloudflared not installed" : e.message, started_at: null };
				this.#proc = null;
				finish();
			});
			p.on("exit", (code) => {
				if (this.#status.state !== "error") this.#status = { state: "off", url: null, error: code ? `cloudflared exited ${code}` : null, started_at: null };
				this.#proc = null;
				this.onUrl?.(null);
				finish();
			});
			setTimeout(() => {
				if (this.#status.state === "starting") {
					this.#status = { ...this.#status, state: "error", error: "timeout waiting for tunnel URL" };
					this.stop();
				}
				finish();
			}, timeoutMs).unref?.();
		});
	}

	stop(): void {
		this.#proc?.kill("SIGTERM");
		this.#proc = null;
		if (this.#status.state !== "error") this.#status = { state: "off", url: null, error: null, started_at: null };
	}
}

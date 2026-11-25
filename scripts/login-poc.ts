/**
 * 階段 1 PoC：以 ANDROIDSECONDARY 次要裝置 QR + PIN 登入，確認能取得基本資料。
 *
 *   node scripts/login-poc.ts                  # 完整流程：印 QR → 手機掃 → 輸入 PIN → 印出個人資料與會話數
 *   node scripts/login-poc.ts --exit-after-qr  # 只驗證能拿到 QR URL，不登入任何帳號
 *   node scripts/login-poc.ts --token          # 用上次保存的 token 重新登入（不需掃碼）
 *
 * 狀態存在 ./.state/line.db（token 與 E2EE 金鑰以 LMA_PASSPHRASE 衍生的金鑰加密；已加入 .gitignore）。
 * 已讀回條與 E2EE 金鑰註冊預設封鎖（src/guard/upstream-guard.ts）。
 */
import qrcode from "qrcode-terminal";
import { openDatabase } from "../src/storage/db.ts";
import { Session, DEVICE } from "../src/auth/session.ts";
import { resolveDataKey } from "../src/storage/data-key.ts";

const args = new Set(process.argv.slice(2));
const store = openDatabase(process.env.LINE_MCP_DB ?? ".state/line.db");
const session = new Session(store, resolveDataKey(store, process.env).box); // 需要 LMA_PASSPHRASE

console.log(`[login-poc] device = ${DEVICE}`);
try {
	if (args.has("--token")) {
		await session.loginWithToken();
	} else {
		await session.loginWithQr({
			onQrUrl(url) {
				console.log("\n[login-poc] 用手機 LINE 掃描下方 QR（或在手機開啟這個網址）：");
				console.log(url + "\n");
				qrcode.generate(url, { small: true });
				if (args.has("--exit-after-qr")) {
					console.log("[login-poc] --exit-after-qr：已取得 QR URL，未登入任何帳號，結束。");
					process.exit(0);
				}
			},
			onPincode(pin) {
				console.log(`\n[login-poc] 請在手機 LINE 輸入 PIN：${pin}\n`);
			},
		});
	}
	const p = session.profile!;
	console.log(`[login-poc] 登入成功：${p.displayName} (${p.mid.slice(0, 6)}…)`);
	const mids = (await session.base.talk.getAllChatMids({ request: { withMemberChats: true, withInvitedChats: false }, syncReason: "INTERNAL" })) as { memberChatMids?: string[] };
	console.log(`[login-poc] 群組/多人聊天數：${mids.memberChatMids?.length ?? 0}`);
	console.log("[login-poc] token 已保存到 .state/line.db；下次可用 --token 登入。");
} catch (e) {
	console.error("[login-poc] 失敗：", (e as Error).message);
	process.exitCode = 1;
} finally {
	store.close();
}

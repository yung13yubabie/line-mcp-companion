/** release 建置用：取代 mock-source.ts，確保 APK 裡沒有任何 mock 資料。 */
export class MockSource {
	constructor() {
		throw new Error("mock mode is not available in release builds");
	}
}
export const MOCK_DEFAULT_ALLOWED: string[] = [];

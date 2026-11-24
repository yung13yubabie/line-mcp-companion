/** release 建置用：取代 mock-ai.ts */
export class MockAiProvider {
	constructor() {
		throw new Error("mock AI is not available in release builds");
	}
}
export class MockSender {
	constructor() {
		throw new Error("mock sender is not available in release builds");
	}
}

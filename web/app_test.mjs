import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Test the actual transfer function without starting Go/WASM or replacing a
// browser. The browser integration suite separately covers DOM and transport.
const source = await readFile(new URL("./app.js", import.meta.url), "utf8");
const start = source.indexOf("async function sendStream(");
const end = source.indexOf('\n$("send-btn").onclick', start);
assert.ok(start >= 0 && end > start, "sendStream source must be present");
const makeSendStream = new Function(
  "tailcatDial", "dialOptions", "CHUNK", "window",
  `${source.slice(start, end)}\nreturn sendStream;`,
);

function fixture(failure, teardown) {
  const error = new Error(`fixture ${failure} failure`);
  const calls = { close: 0, abort: 0, write: 0, closeWrite: 0, read: 0 };
  const state = { tcTest: { sendDone: false, sentBytes: 0 } };
  const progress = { textContent: "" };
  const conn = {
    async write() {
      calls.write++;
      if (failure === "write") throw error;
    },
    async closeWrite() {
      calls.closeWrite++;
      if (failure === "closeWrite") throw error;
    },
    async read() {
      calls.read++;
      if (failure === "read") throw error;
      return null;
    },
    close() { calls.close++; return teardown?.promise; },
    abort() { calls.abort++; return teardown?.promise; },
  };
  const send = makeSendStream(
    async () => {
      if (failure === "dial") throw error;
      return conn;
    },
    (addr) => ({ addr }), 64 * 1024, state,
  );
  const run = () => send("mc-fixture", 3, async () => {
    if (failure === "readChunk") throw error;
    return Uint8Array.of(1, 2, 3);
  }, progress);
  return { run, error, calls, state, progress };
}

for (const failure of ["readChunk", "write", "closeWrite", "read"]) {
  test(`sendStream closes after ${failure} fails without claiming success`, async () => {
    const f = fixture(failure);
    await assert.rejects(f.run, (err) => err === f.error);
    assert.equal(f.calls.abort, 1);
    assert.equal(f.calls.close, 0);
    assert.equal(f.state.tcTest.sendDone, false);
    assert.equal(f.state.tcTest.sentBytes, 0);
    assert.doesNotMatch(f.progress.textContent, /^sent /);
  });
}

test("sendStream closes once and reports bytes after successful EOF", async () => {
  const f = fixture(null);
  await f.run();
  assert.deepEqual(f.calls, { close: 1, abort: 0, write: 1, closeWrite: 1, read: 1 });
  assert.equal(f.state.tcTest.sendDone, true);
  assert.equal(f.state.tcTest.sentBytes, 3);
  assert.equal(f.progress.textContent, "sent 3 bytes");
});

test("sendStream preserves dial failure without accessing a missing connection", async () => {
  const f = fixture("dial");
  await assert.rejects(f.run, (err) => err === f.error);
  assert.deepEqual(f.calls, { close: 0, abort: 0, write: 0, closeWrite: 0, read: 0 });
  assert.equal(f.state.tcTest.sendDone, false);
});

test("a failed retry cannot retain a previous transfer's success", async () => {
  const f = fixture("dial");
  f.state.tcTest.sendDone = true;
  f.state.tcTest.sentBytes = 123;
  f.progress.textContent = "sent 123 bytes";
  await assert.rejects(f.run, (err) => err === f.error);
  assert.equal(f.state.tcTest.sendDone, false);
  assert.equal(f.state.tcTest.sentBytes, 0);
  assert.equal(f.progress.textContent, "");
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const pending = Symbol("pending");
const settledWithin = (promise) =>
  Promise.race([promise.then(() => "settled", () => "settled"),
    new Promise((resolve) => setTimeout(() => resolve(pending), 20))]);

for (const failure of [null, "write"]) {
  test(`sendStream waits for ${failure ? "abort" : "close"} teardown before finishing`, async () => {
    const teardown = deferred();
    const f = fixture(failure, teardown);
    const sending = f.run();
    sending.catch(() => {});
    assert.equal(await settledWithin(sending), pending);
    assert.equal(f.state.tcTest.sendDone, false);
    teardown.resolve();
    if (failure) {
      await assert.rejects(sending, (err) => err === f.error);
    } else {
      await sending;
      assert.equal(f.state.tcTest.sendDone, true);
    }
  });
}

test("a teardown failure does not replace the transfer error", async () => {
  const teardown = deferred();
  const f = fixture("read", teardown);
  teardown.reject(new Error("teardown failed"));
  await assert.rejects(f.run, (err) => err === f.error);
  assert.equal(f.calls.abort, 1);
});


import { writeFileSync } from "node:fs";
const RPC = "https://sepolia.base.org", H = "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3", ZERO = "0x" + "0".repeat(64);
async function rpc(method, params) { const fetchedAt = new Date().toISOString(); const r = await (await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })).json(); if (r.error || r.result == null) throw new Error(method + " " + JSON.stringify(r.error)); return { result: r.result, fetchedAt }; }
const chain = await rpc("eth_chainId", []); if (chain.result !== "0x14a34") throw new Error("chainId " + chain.result);
const head = await rpc("eth_blockNumber", []);
const tx = await rpc("eth_getTransactionByHash", [H]);
const rc = await rpc("eth_getTransactionReceipt", [H]);
const blk = await rpc("eth_getBlockByNumber", [rc.result.blockNumber, false]);
const depth = parseInt(head.result, 16) - parseInt(rc.result.blockNumber, 16);
const sealed = tx.result.blockHash && tx.result.blockHash !== ZERO && tx.result.blockHash === rc.result.blockHash && rc.result.blockHash === blk.result.hash;
console.log("head", parseInt(head.result,16), "tx block", parseInt(rc.result.blockNumber,16), "depth", depth, "sealed", sealed, "blockHash", rc.result.blockHash);
if (!sealed || depth < 5) { console.log("not sealed and 5 deep yet; nothing written"); process.exit(1); }
writeFileSync("rpc/transaction.sealed.json", JSON.stringify(tx.result, null, 2) + "\n", { flag: "wx" });
writeFileSync("rpc/receipt.sealed.json", JSON.stringify(rc.result, null, 2) + "\n", { flag: "wx" });
writeFileSync("rpc/block.sealed.json", JSON.stringify(blk.result, null, 2) + "\n", { flag: "wx" });
writeFileSync("rpc/fetched.sealed.json", JSON.stringify({ rpc_url: RPC, chain_id: chain.result, head_block_at_fetch: { number: head.result, fetched_at: head.fetchedAt }, depth_blocks: depth,
  transaction: { method: "eth_getTransactionByHash", fetched_at: tx.fetchedAt }, receipt: { method: "eth_getTransactionReceipt", fetched_at: rc.fetchedAt },
  block: { method: "eth_getBlockByNumber(<receipt blockNumber>, false)", fetched_at: blk.fetchedAt } }, null, 2) + "\n", { flag: "wx" });
console.log("written rpc/*.sealed.json");
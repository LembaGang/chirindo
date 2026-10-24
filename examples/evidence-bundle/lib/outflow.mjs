// The outflow reading of spec 4.3, "Payment values": on the calldata path,
// with a payer S derived, every log of the receipt whose first topic is one
// of the events below is read for S where the event's standard layout puts
// it, or, in a layout with another number of topics, as a 32-byte word among
// its other topics or at a 32-byte boundary of its data. Of the logs read, a
// Transfer from a pinned token in ERC-20's layout with S as from is a
// movement; every other is an outflow this version cannot judge. The logs
// make the verdict worse, never better: they never derive a payer or change
// B-PAY's state.

import { quantity } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";

const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// First topic -> [the event's name, { number of topics: the topic that holds S }]
// for each standard layout (spec 4.3, the list of events).
const EVENTS = new Map([
  [TRANSFER, ["Transfer", { 3: 1, 4: 1 }]],
  ["0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62", ["TransferSingle", { 4: 2 }]],
  ["0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb", ["TransferBatch", { 4: 2 }]],
  ["0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859", ["ERC-6909 Transfer", { 4: 1 }]],
  ["0xceb576d9f15e4e200fdb5096d64d5dfd667e16def20c1eefd14256d8e3faa267", ["ERC-6909 OperatorSet", { 3: 1 }]],
  ["0xb3fd5071835887567a0671151121894ddccc2842f1d10bedad13e0d17cace9a7", ["ERC-6909 Approval", { 4: 1 }]],
  ["0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b", ["Permit2 Approval", { 4: 1 }]],
  ["0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec", ["Permit2 Permit", { 4: 1 }]],
  ["0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925", ["Approval", { 3: 1, 4: 1 }]],
  ["0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31", ["ApprovalForAll", { 3: 1 }]],
]);

const asWord = (addr) => "0x" + addr.slice(2).padStart(64, "0");
const dataWords = (data) => Array.from({ length: Math.floor((data.length - 2) / 64) }, (_, k) => "0x" + data.slice(2 + 64 * k, 66 + 64 * k));

// Returns { movements, unread: [{ log_index, event }] } for the payer S
// (lowercase) over the receipt's logs (as M5.receipt read them), with
// `pinned` the token addresses the pins name for the chain.
built("B-PAY.outflow");
export function readOutflows(logs, S, pinned) {
  const w = asWord(S);
  const movements = [];
  const unread = [];
  for (const l of logs) {
    const ev = EVENTS.get(l.topics[0]);
    if (!ev) continue;
    const [name, layout] = ev;
    const at = layout[l.topics.length];
    const names = at !== undefined ? l.topics[at] === w : l.topics.slice(1).includes(w) || dataWords(l.data).includes(w);
    if (!names) continue;
    const logIndex = Number(quantity(l.logIndex, "logIndex"));
    const token = l.address.toLowerCase();
    if (l.topics[0] === TRANSFER && l.topics.length === 3 && pinned.includes(token) && l.data.length === 66)
      movements.push({ asset: token, amount: BigInt(l.data).toString(), payee: "0x" + l.topics[2].slice(26), source: "log", log_index: logIndex });
    else unread.push({ log_index: logIndex, event: name });
  }
  return { movements, unread };
}

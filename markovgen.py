#!/usr/bin/env python3
"""
markovgen - a smarter-than-a-static-wordlist password candidate generator.

The idea (and why it can beat rockyou):
  A leaked wordlist like rockyou is a *finite, static* set of passwords that were already breached.
  If a target's password was never in a leak, rockyou can never produce it. This tool instead
  learns the *character-level structure* of how humans build passwords - by training an order-k
  Markov model on a corpus (e.g. rockyou) - and then GENERATES candidates, including novel strings
  that are not in any list, emitted in descending order of estimated probability.

The cool applied-CS core: ordered enumeration by probability is a best-first (uniform-cost) search
over the weighted trie of prefixes. Each partial string is a search node; its cost is the summed
negative log-probability of its characters under the model; expanding the lowest-cost node and
emitting completed words yields candidates in (near-)optimal probability order. An optional beam
bound trims the frontier to keep memory finite (turning exact best-first into bounded beam search).

Practical wins over a raw wordlist for WPA cracking:
  * generates unseen-but-plausible passwords (generalises beyond the training leak)
  * emits most-probable-first, so early guesses are the highest-value ones
  * respects WPA's 8-char minimum (no wasted <8 candidates - rockyou wastes ~a third)
  * can be seeded with target-specific words (name, SSID, org) that get tried first

Pipe straight into hashcat (stdin mode):
    ./markovgen.py --train rockyou.txt --count 5000000 --seed Robinson --seed Entropy \
        | hashcat -m 22000 wpa.22000

No third-party dependencies; pure standard library.
"""
import sys, argparse, heapq, math, time
from collections import defaultdict

END = None          # sentinel for "end of password" transition
START = "\x02"       # padding symbol for the initial context (never appears in passwords)


def train(corpus_path, order, maxlen, train_limit, mincount):
    """Build an order-k Markov model: context (last `order` chars) -> {next_char/END: logprob}.
    Trained over a corpus, one password per line. Returns (model, order)."""
    counts = defaultdict(lambda: defaultdict(int))   # ctx -> symbol -> count
    n = 0
    t0 = time.time()
    with open(corpus_path, "r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\n").rstrip("\r")
            if not w or len(w) > maxlen:
                continue
            n += 1
            if train_limit and n > train_limit:
                break
            ctx = START * order
            for ch in w:
                counts[ctx][ch] += 1
                ctx = (ctx + ch)[-order:]
            counts[ctx][END] += 1     # learn where words end
            if n % 1000000 == 0:
                sys.stderr.write(f"[train] {n:,} lines... ({time.time()-t0:.0f}s)\n")
    # normalise to log-probabilities; drop ultra-rare transitions (noise) below mincount
    model = {}
    for ctx, trans in counts.items():
        total = sum(c for c in trans.values() if c >= mincount)
        if total <= 0:
            continue
        model[ctx] = {sym: math.log(c / total) for sym, c in trans.items() if c >= mincount}
    sys.stderr.write(f"[train] done: {n:,} passwords, {len(model):,} contexts, "
                     f"order={order} ({time.time()-t0:.0f}s)\n")
    return model


def emit_seeds(seeds, minlen, maxlen, seen, out):
    """Emit target-specific candidates first: each seed with common human suffix/case mutations.
    These are the highest-value guesses when you know something about the target."""
    if not seeds:
        return 0
    tails = [""] + [str(d) for d in range(0, 1000)] + \
            [str(y) for y in range(1970, 2031)] + \
            ["!", "?", ".", "1!", "12", "123", "1234", "!23", "@123", "00", "000",
             "01", "007", "69", "420", "!!", "#1"]
    count = 0
    for seed in seeds:
        variants = {seed, seed.lower(), seed.upper(), seed.capitalize(),
                    seed.lower().capitalize()}
        for base in variants:
            for t in tails:
                cand = base + t
                if minlen <= len(cand) <= maxlen and cand not in seen:
                    seen.add(cand)
                    out.write(cand + "\n")
                    count += 1
    return count


def generate(model, order, count, minlen, maxlen, beam, seeds, out):
    """Best-first enumeration of candidates in descending probability order.

    Frontier is a min-heap keyed by cost = -sum(logprob). Pop the most probable prefix; if the
    model says it can END, emit it (respecting length bounds); then expand it by every observed
    next character. `beam` bounds the frontier size (approx best-first -> beam search) so memory
    stays finite even with an enormous keyspace."""
    seen = set()
    emitted = emit_seeds(seeds, minlen, maxlen, seen, out)

    start_ctx = START * order
    # heap entries: (cost, tiebreak, prefix, ctx). tiebreak keeps ordering stable + comparable.
    heap = [(0.0, 0, "", start_ctx)]
    tie = 1
    while heap and emitted < count:
        cost, _, prefix, ctx = heapq.heappop(heap)
        trans = model.get(ctx)
        if not trans:
            continue
        for sym, lp in trans.items():
            if sym is END:
                if minlen <= len(prefix) <= maxlen and prefix not in seen:
                    seen.add(prefix)
                    out.write(prefix + "\n")
                    emitted += 1
                    if emitted >= count:
                        break
            else:
                if len(prefix) + 1 <= maxlen:
                    nctx = (ctx + sym)[-order:]
                    heapq.heappush(heap, (cost - lp, tie, prefix + sym, nctx))
                    tie += 1
        # bound the frontier: keep only the `beam` most-promising nodes
        if beam and len(heap) > beam * 2:
            heap = heapq.nsmallest(beam, heap)
            heapq.heapify(heap)
    return emitted


def main():
    ap = argparse.ArgumentParser(
        description="Markov best-first password candidate generator (stream to hashcat).")
    ap.add_argument("--train", required=True, help="training corpus (one password per line, e.g. rockyou.txt)")
    ap.add_argument("--order", type=int, default=3, help="Markov order = context length (default 3)")
    ap.add_argument("--count", type=int, default=1000000, help="max candidates to emit (default 1e6)")
    ap.add_argument("--minlen", type=int, default=8, help="min length (default 8 = WPA minimum)")
    ap.add_argument("--maxlen", type=int, default=16, help="max length (default 16)")
    ap.add_argument("--beam", type=int, default=200000,
                    help="frontier bound (0 = exact best-first, unbounded memory; default 200000)")
    ap.add_argument("--mincount", type=int, default=2,
                    help="drop transitions seen fewer than this many times (noise floor; default 2)")
    ap.add_argument("--train-limit", type=int, default=0, help="train on only the first N lines (0 = all)")
    ap.add_argument("--seed", action="append", default=[],
                    help="target-specific word to try first (repeatable), e.g. --seed Robinson")
    ap.add_argument("-o", "--out", default="-", help="output file ('-' = stdout, for piping to hashcat)")
    args = ap.parse_args()

    if args.minlen > args.maxlen:
        ap.error("--minlen cannot exceed --maxlen")

    out = sys.stdout if args.out == "-" else open(args.out, "w")
    model = train(args.train, args.order, args.maxlen, args.train_limit, args.mincount)
    t0 = time.time()
    n = generate(model, args.order, args.count, args.minlen, args.maxlen, args.beam, args.seed, out)
    if out is not sys.stdout:
        out.close()
    sys.stderr.write(f"[gen] emitted {n:,} candidates in {time.time()-t0:.1f}s\n")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # the reader (e.g. hashcat) closed the pipe - typically because it cracked the key and
        # exited. Redirect stdout to devnull so the interpreter shutdown doesn't re-raise, then
        # exit quietly. This is the standard idiom for a Unix generator in a pipeline.
        import os
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)

#!/usr/bin/env python3
"""
markovgen - a smarter-than-a-static-wordlist password candidate generator.

It is BOTH a model and an algorithm, and it helps to keep them separate:

  * The MODEL is an order-k character Markov chain: the probabilities P(next char | previous k
    chars) learned from a training corpus (e.g. rockyou). It is the statistical artifact - a
    classical probabilistic language model over characters, with Katz-style back-off so unseen
    high-order contexts fall back to shorter ones instead of dead-ending.

  * The ALGORITHM is a best-first (uniform-cost) search that ENUMERATES candidates from that model
    in descending order of probability. Each partial string is a search node whose cost is the
    summed negative log-probability of its characters; we always expand the cheapest (most
    probable) node, and emit a candidate when its *terminal* node is popped - which guarantees
    words come out in exact descending-probability order (up to the optional beam bound).

Why it can beat a leak list like rockyou: rockyou is a finite set of already-breached passwords,
so it can never produce a password that was never leaked. This learns the *structure* of human
passwords and GENERATES novel, plausible strings, most-probable-first, respecting WPA's 8-char
minimum, and optionally seeded with target words that are tried first.

Pipe straight into hashcat (stdin mode):
    ./markovgen.py --train rockyou.txt --count 5000000 --seed Smith --seed Acme \
        | hashcat -m 22000 wpa.22000

Train once, reuse the model (no re-training each run):
    ./markovgen.py --train rockyou.txt --save-model rockyou.mdl
    ./markovgen.py --model rockyou.mdl --count 5000000 | hashcat -m 22000 wpa.22000

No third-party dependencies; pure standard library.
"""
import sys, os, argparse, heapq, math, time, json
from collections import defaultdict

END = None            # sentinel for the "end of password" transition
END_KEY = "\x00"       # JSON-serialisable stand-in for END (a real char is never NUL here)
START = "\x02"         # padding symbol for the initial context (never appears in passwords)


# ----------------------------- the MODEL -----------------------------
def train(corpus_path, order, maxlen, train_limit, mincount):
    """Build an order-k character Markov model WITH back-off tables.

    For every emitted symbol we record its count under contexts of *every* length 0..order
    (suffixes of the START-padded history). That gives us all lower-order models in one pass, so
    generation can back off from an unseen order-k context to the longest context it has seen.
    Returns {"order", "model"} where model[ctx] = {symbol: log P(symbol | ctx)}.
    """
    counts = defaultdict(lambda: defaultdict(int))   # ctx -> symbol -> count
    n = 0
    t0 = time.time()
    with open(corpus_path, "r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\r\n")
            if not w or len(w) > maxlen:
                continue
            n += 1
            if train_limit and n > train_limit:
                break
            stream = START * order + w
            # record each real char, then the END marker, under all context lengths 0..order
            for i in range(order, len(stream) + 1):
                sym = stream[i] if i < len(stream) else END
                for L in range(0, order + 1):
                    counts[stream[i - L:i]][sym] += 1
            if n % 1_000_000 == 0:
                sys.stderr.write(f"[train] {n:,} lines... ({time.time() - t0:.0f}s)\n")
    # normalise each context to log-probabilities, pruning rare (noisy) transitions
    model = {}
    for ctx, trans in counts.items():
        kept = {s: c for s, c in trans.items() if c >= mincount}
        total = sum(kept.values())
        if total <= 0:
            continue
        model[ctx] = {s: math.log(c / total) for s, c in kept.items()}
    sys.stderr.write(f"[train] {n:,} passwords -> {len(model):,} contexts, order={order} "
                     f"({time.time() - t0:.0f}s)\n")
    return {"order": order, "model": model}


def save_model(m, path):
    """Serialise the model to JSON (END represented as NUL so keys stay valid strings)."""
    ser = {ctx: {(END_KEY if s is END else s): lp for s, lp in trans.items()}
           for ctx, trans in m["model"].items()}
    with open(path, "w") as f:
        json.dump({"order": m["order"], "model": ser}, f)
    sys.stderr.write(f"[model] saved {len(ser):,} contexts to {path}\n")


def load_model(path):
    with open(path) as f:
        raw = json.load(f)
    model = {ctx: {(END if s == END_KEY else s): lp for s, lp in trans.items()}
             for ctx, trans in raw["model"].items()}
    sys.stderr.write(f"[model] loaded {len(model):,} contexts (order={raw['order']}) from {path}\n")
    return {"order": raw["order"], "model": model}


def lookup(model, order, ctx, alpha):
    """Katz-style back-off: return the transition dict for the longest suffix of `ctx` that the
    model knows, plus a back-off penalty (log alpha per level dropped) to add to edge costs.
    The empty context is always present (it is the unigram table), so this never fails."""
    for drop in range(0, order + 1):
        sub = ctx[drop:] if drop < len(ctx) else ""
        trans = model.get(sub)
        if trans:
            return trans, drop * math.log(alpha)
    return model.get("", {}), order * math.log(alpha)


# --------------------------- the ALGORITHM ---------------------------
def emit_seeds(seeds, minlen, maxlen, seen, out):
    """Emit target-specific candidates first: each seed with common case + suffix mutations.
    These are the highest-value guesses when you know something about the target."""
    if not seeds:
        return 0
    tails = [""] + [str(d) for d in range(0, 1000)] + [str(y) for y in range(1970, 2031)] + \
            ["!", "?", ".", "1!", "12", "123", "1234", "!23", "@123", "00", "000",
             "01", "007", "69", "420", "!!", "#1"]
    count = 0
    for seed in seeds:
        for base in {seed, seed.lower(), seed.upper(), seed.capitalize()}:
            for t in tails:
                cand = base + t
                if minlen <= len(cand) <= maxlen and cand not in seen:
                    seen.add(cand)
                    out.write(cand + "\n")
                    count += 1
    return count


def generate(m, count, minlen, maxlen, beam, alpha, seeds, out):
    """Best-first enumeration in descending probability order.

    Heap nodes are (cost, tie, prefix, ctx). ctx=None marks a TERMINAL node (a completed word);
    we emit it only when it is popped, so emission is in exact cost order. A prefix node is
    expanded by pushing a terminal node for its END transition plus a prefix node per next char.
    `beam` bounds the frontier (exact best-first -> memory-bounded beam search). count<=0 = no cap.
    """
    order, model = m["order"], m["model"]
    seen = set()
    emitted = emit_seeds(seeds, minlen, maxlen, seen, out)
    unlimited = count <= 0
    t0 = time.time()

    heap = [(0.0, 0, "", START * order)]   # (cost, tie, prefix, ctx)
    tie = 1
    while heap and (unlimited or emitted < count):
        cost, _, prefix, ctx = heapq.heappop(heap)
        if ctx is None:                     # terminal node -> emit the completed word
            if minlen <= len(prefix) <= maxlen and prefix not in seen:
                seen.add(prefix)
                out.write(prefix + "\n")
                emitted += 1
                if emitted % 1_000_000 == 0:
                    sys.stderr.write(f"[gen] {emitted:,} emitted ({time.time() - t0:.0f}s)\n")
            continue
        trans, penalty = lookup(model, order, ctx, alpha)
        for sym, lp in trans.items():
            edge = cost - lp - penalty       # cost = summed -log prob (+ back-off penalty)
            if sym is END:
                if len(prefix) >= minlen:
                    heapq.heappush(heap, (edge, tie, prefix, None))
                    tie += 1
            elif len(prefix) < maxlen:
                heapq.heappush(heap, (edge, tie, prefix + sym, (ctx + sym)[-order:]))
                tie += 1
        if beam and len(heap) > beam * 2:    # trim frontier to the `beam` most promising nodes
            heap = heapq.nsmallest(beam, heap)
            heapq.heapify(heap)
    return emitted


def main():
    ap = argparse.ArgumentParser(
        description="Markov best-first password candidate generator (stream to hashcat).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--train", help="training corpus (one password per line, e.g. rockyou.txt)")
    src.add_argument("--model", help="load a previously --save-model'd model (skips training)")
    ap.add_argument("--save-model", help="after --train, write the model here and exit")
    ap.add_argument("--order", type=int, default=3, help="Markov order = context length (default 3)")
    ap.add_argument("--count", type=int, default=1_000_000, help="max candidates (<=0 = unlimited)")
    ap.add_argument("--minlen", type=int, default=8, help="min length (default 8 = WPA minimum)")
    ap.add_argument("--maxlen", type=int, default=16, help="max length (default 16)")
    ap.add_argument("--beam", type=int, default=200_000,
                    help="frontier bound (0 = exact best-first, unbounded memory; default 200000)")
    ap.add_argument("--alpha", type=float, default=0.4,
                    help="back-off penalty factor per level dropped (Katz-style; default 0.4)")
    ap.add_argument("--mincount", type=int, default=2,
                    help="drop transitions seen fewer than this many times (noise floor; default 2)")
    ap.add_argument("--train-limit", type=int, default=0, help="train on only the first N lines (0 = all)")
    ap.add_argument("--seed", action="append", default=[],
                    help="target-specific word to try first (repeatable), e.g. --seed Smith")
    ap.add_argument("-o", "--out", default="-", help="output file ('-' = stdout, for piping to hashcat)")
    args = ap.parse_args()

    if args.minlen > args.maxlen:
        ap.error("--minlen cannot exceed --maxlen")
    if args.order < 1:
        ap.error("--order must be >= 1")

    if args.model:
        m = load_model(args.model)
    else:
        m = train(args.train, args.order, args.maxlen, args.train_limit, args.mincount)
        if args.save_model:
            save_model(m, args.save_model)
            return

    out = sys.stdout if args.out == "-" else open(args.out, "w")
    t0 = time.time()
    n = generate(m, args.count, args.minlen, args.maxlen, args.beam, args.alpha, args.seed, out)
    if out is not sys.stdout:
        out.close()
    sys.stderr.write(f"[gen] emitted {n:,} candidates in {time.time() - t0:.1f}s\n")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # the reader (e.g. hashcat) closed the pipe, usually because it cracked the key and exited.
        # Redirect stdout to devnull so interpreter shutdown doesn't re-raise, then exit quietly.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)

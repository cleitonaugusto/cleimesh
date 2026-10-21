#!/usr/bin/env python3
"""Splits a demo recording into one clip per act.

The demo, run with CLEAR=1, clears the screen when each act starts; this cuts
an asciicast v2 recording there, so each clip starts on a clean screen.

    python3 examples/demo/split.py examples/demo/demo.cast examples/demo/demo-ato
    # -> demo-ato1.cast ... demo-ato4.cast
"""
import json
import sys

CLEAR = "\x1b[2J"


def main(src, prefix):
    with open(src) as f:
        header = json.loads(f.readline())
        events = [json.loads(line) for line in f if line.strip()]
    starts = [i for i, e in enumerate(events) if e[1] == "o" and CLEAR in e[2]]
    if not starts:
        sys.exit("no act found: record the demo with CLEAR=1")
    for n, start in enumerate(starts, 1):
        end = starts[n] if n < len(starts) else len(events)
        t0 = events[start][0]
        first = events[start][2]
        clip = [[0.0, "o", first[first.index(CLEAR):]]]
        clip += [[round(e[0] - t0, 6), e[1], e[2]] for e in events[start + 1:end]]
        path = f"{prefix}{n}.cast"
        with open(path, "w") as f:
            f.write(json.dumps({**header, "duration": clip[-1][0]}) + "\n")
            for e in clip:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"{path}: {clip[-1][0]:.0f} s")


if __name__ == "__main__":
    main(*sys.argv[1:3])

"""Measure deterministic Python and Rust redaction time and traced peak memory."""

from __future__ import annotations

import random
import statistics
import time
import tracemalloc

import chinescan_engine
from chinescan.core.logging.redaction import _redact_text_python

TARGET_CHARS = 50 * 1024 * 1024
CHUNK_CHARS = 512 * 1024
SEED = 0xC41E5CA1


def make_corpus() -> list[str]:
    templates = (
        "2026-11-09T12:30:00Z user=operator action=read outcome=ok source=local\n",
        "password=SyntheticSecretValue-1234567890; api_key=CanaryKey_0123456789\n",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjYW5hcnkifQ.signature status=200\n",
        "$argon2id$v=19$m=65536,t=3,p=4$salt$encodedhash request=complete\n",
        "path=C:\\Users\\Cipher\\AppData\\Local\\config.toml source=/home/operator/log.txt\n",
        ("x:" * 16) + "_secret=synthetic-canary near-match=ordinary\n",
        "digest=" + ("a" * 64) + " uuid=123e4567-e89b-12d3-a456-426614174000\n",
        "location: [REDACTED] line_number: 27 marker=[REDACTED]]] [REDACTED]]\n",
    )
    rng = random.Random(SEED)
    output: list[str] = []
    current: list[str] = []
    current_chars = 0
    total_chars = 0
    while total_chars < TARGET_CHARS:
        text = rng.choice(templates)
        remaining = TARGET_CHARS - total_chars
        text = text[:remaining]
        text_remaining = text
        while text_remaining:
            available = CHUNK_CHARS - current_chars
            piece = text_remaining[:available]
            current.append(piece)
            current_chars += len(piece)
            total_chars += len(piece)
            text_remaining = text_remaining[len(piece) :]
            if current_chars == CHUNK_CHARS:
                output.append("".join(current))
                current = []
                current_chars = 0
    if current:
        output.append("".join(current))
    return output


def redact_chunks(function, chunks: list[str]) -> str:
    return "".join(function(chunk) for chunk in chunks)


def measure(label: str, function, corpus: list[str]) -> tuple[float, float]:
    elapsed: list[float] = []
    for _ in range(3):
        started = time.perf_counter()
        result = redact_chunks(function, corpus)
        elapsed.append(time.perf_counter() - started)
        if len(result) == 0:
            raise RuntimeError(f"{label} returned an empty redaction result")
        del result

    tracemalloc.start()
    result = redact_chunks(function, corpus)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del result
    median_ms = statistics.median(elapsed) * 1_000
    peak_mib = peak / (1024 * 1024)
    return median_ms, peak_mib


def main() -> None:
    corpus = make_corpus()
    print(
        f"Corpus: {sum(map(len, corpus)):,} characters; fixed seed 0x{SEED:X}; "
        "three timed runs"
    )
    print("Peak memory is tracemalloc-visible Python allocation; the prebuilt input is excluded.")
    print("Engine   Median ms   Peak traced MiB")
    print("-------  ----------  ---------------")
    for label, function in (
        ("Python", _redact_text_python),
        ("Rust", chinescan_engine.redact_text),
    ):
        median_ms, peak_mib = measure(label, function, corpus)
        print(f"{label:<7}  {median_ms:>10.2f}  {peak_mib:>15.2f}")


if __name__ == "__main__":
    main()

import time
import requests
import statistics


def side_channel_attack(
    target_file: bytes,
    hmac_size: int = 20,
    trials: int = 1,
    base_url: str = "http://127.0.0.1:5001",
) -> bytes:
    recovered = bytearray(hmac_size)
    file_hex = target_file.hex()

    for pos in range(hmac_size):
        print(f"Cracking byte {pos}/{hmac_size}", end="", flush=True)
        best_byte = 0
        best_median = -1.0

        for candidate in range(256):
            recovered[pos] = candidate
            probe = bytes(recovered)
            probe_hex = probe.hex()

            samples = []
            for _ in range(trials):
                t0 = time.perf_counter()
                try:
                    requests.get(
                        f"{base_url}/validate_file",
                        params={"file": file_hex, "file_checksum": probe_hex},
                        timeout=hmac_size * 0.05 * 2 + 2,
                    )
                except requests.RequestException:
                    pass
                samples.append(time.perf_counter() - t0)

            med = statistics.median(samples)
            if med > best_median:
                best_median = med
                best_byte = candidate

        recovered[pos] = best_byte
        print(f" 0x{best_byte:02x}  (median={best_median:.4f}s)")

    result = bytes(recovered)
    print(f"Recovered HMAC: {result.hex()}")
    return result


if __name__ == "__main__":
    f = open("./hmac_timing.py", "rb").read()
    recovered_signature = bytes.fromhex("d1f121d60c06a83c12e1280fa3d3c2010183355c")#side_channel_attack(f)
    res = requests.get(
        "http://127.0.0.1:5001/validate_file",
        params={"file": f.hex(), "file_checksum": recovered_signature.hex()},
    ).text
    print(res)
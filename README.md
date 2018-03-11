# CapFuzz
## capture | intercept | fuzz

### Usage

```
$ git clone https://github.com/MobSF/CapFuzz.git
$ cd CapFuzz
$ python capfuzz
usage: capfuzz [-h] [-m MODE] [-p PORT] [-n NAME]

optional arguments:
  -h, --help            show this help message and exit
  -m MODE, --mode MODE  Supported modes
                        1. capture: Capture requests.
                        2. fuzz: Run Fuzzing Server.
                        3. runfuzz: Fuzz on captured requests with default configuration.
                        4. intercept: Intercept and tamper the flow in live.
  -p PORT, --port PORT  Proxy Port
  -n NAME, --name NAME  Project Name
```

1. Capture - `capfuz -m capture`
   * Starts HTTPS proxy at `1337` by default.
   * Install Root CA available under `capfuzz/ca` to browser or system.
2. Intercept - `capfuz -m intercept`
   * To Fiddle with request and response in live.
   * Use: `capfuzz/core/interceptor.py` (If you did pip install, the location will change)
3. Fuzz UI - `capfuzz -m fuzz`
   * Starts the Fuzzer Web UI for configuration and fuzzing: `https://0.0.0.0:1337`
4. Fuzz - `capfuzz -m runfuzz`
   * Fuzz from command line.

### Install

`pip install capfuzz`
You can type `capfuzz` to access from anywhere.

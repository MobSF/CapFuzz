# CapFuzz
## capture | intercept | fuzz

### Install
`pip install capfuzz`

## Root CA

Install Root CA available under `capfuzz/ca` to browser or system.

### Usage

```
$ capfuzz
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
2. Intercept - `capfuz -m intercept`
3. Fuzz UI - `capfuzz -m fuzz`
4. Fuzz - `capfuzz -m runfuzz`

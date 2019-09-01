# CapFuzz (Depreciated, use: https://github.com/MobSF/httptools) 
## capture | intercept | fuzz
Yet another https proxy to capture and fuzz web apis. Tailor made for fuzzing Mobile App APIs & web services with a scriptable interface. CapFuzz is built on top of [mitmproxy](https://mitmproxy.org/)

<img width="1261" alt="screen shot 2018-03-11 at 2 57 55 pm" src="https://user-images.githubusercontent.com/4301109/37251800-af620840-253c-11e8-89ed-ce3594e243e9.png">

### Install
```
$ git clone https://github.com/MobSF/CapFuzz.git
$ cd CapFuzz
$ python setup.py install
```

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
   * Starts HTTPS proxy at `1337` by default.
   * Install Root CA cert available under `capfuzz/ca` to browser or system.
2. Intercept - `capfuz -m intercept`
   * To Fiddle with request and response in live.
   * Use: `capfuzz/core/interceptor.py` (The location will be relative to where capfuzz is installed)
3. Fuzz UI - `capfuzz -m fuzz`
   * Starts the Fuzzer Web UI for configuration and fuzzing: `https://0.0.0.0:1337`
4. Fuzz - `capfuzz -m runfuzz`
   * Fuzz from command line.


# WM-BUS for LakeShark

Wireless M-Bus (EN 13757-4 / OMS) meter receiver for [LakeShark](https://github.com/SAMS0N1TE/LakeShark)
boards with an LR2021 radio: T1, C1 and S1 telegrams, AES-128 (security modes 5 and 7, ELL),
DIF/VIF records, Techem billing frames and public manufacturer default keys.

| Path | What |
|---|---|
| `wmbus/` | the app as submitted to [lakeshark-apps](https://github.com/SAMS0N1TE/lakeshark-apps): source, `app.json`, screenshot, README; the store copy adds `LICENSE` |
| `tests/test_wmbus.c` | host unit tests for the protocol and AES code |

Build the app:

```
python <LakeShark>/app-sdk/lap.py build wmbus -o wmbus.lap
```

Run the tests with any C11 compiler:

```
cc -std=c11 -Iwmbus tests/test_wmbus.c wmbus/wm_aes.c wmbus/wm_proto.c -o test_wmbus && ./test_wmbus
```

Author: zenobik (zenobik@gmail.com). MIT license, see `LICENSE`.

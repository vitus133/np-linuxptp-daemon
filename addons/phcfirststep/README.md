# PHC First-Step Plugin

`phc-first-step` synchronously applies the initial PHC correction for a
time-receiver profile before normal daemon profile application continues.
The operator enables the plugin by default, but a profile runs it only when
its `plugins` map contains `phc-first-step`.

The plugin identifies each TR interface from a `ptp4lConf` interface section
with `masterOnly 0`. All selected interfaces must resolve to one PHC, and at
least one device in the same profile's `e825.devices` must expose that PHC. Its
name may differ from the TR interface name. The
plugin runs free-running `ptp4l`, collects the first 16 valid master-offset
samples with non-zero path delay, and averages them. It then reads the shared
PHC and sets it to the current PHC time minus the mean offset. A successful
`phc_ctl set` exit is completion; the PHC is not read back.

```yaml
spec:
  profile:
    - name: boundary-clock-tr
      ptp4lConf: |
        [eno1]
        masterOnly 0
        [global]
        domainNumber 24
      plugins:
        phc-first-step:
          timeout: 30s
        e825:
          devices:
            - eno1
```

The `timeout` option is optional and accepts Go duration syntax such as `30s`
or `2m`. It bounds only offset measurement. When omitted, measurement waits
indefinitely for 16 valid samples. PHC read and set commands are not bounded by
this timeout.

When the selected profile is invalid, hardware cannot be resolved, measurement
times out, or a command fails, the callback returns an error. The daemon reports
`HardwarePluginReady=False` and continues normal profile application.

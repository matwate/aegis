# Aegis Autorruning 

## What is that?

Aegis Autorunnign is my attempt at making USB drive autoruns a thing in linux, similar to what you can do on window, removing all that *potentially plugging in some malware and fucking your system* part of it. 

The idea is simple, the autorun is *encrypted with YOUR key* so that the only thing your system will actually try and run is something that YOU made, and nothing else.

As an extra safety measure, the autorun system can be configured so that the USB only contains a so called "Autorun directive" where it justtells your system what to run inside your own filesystem, so that the actual code that is being automatically ran is not even on the USB drive. 

## How it works.

Here's an example YAML autorun directive file:

```yaml
autorun:
  name: My Secure Autorun
  description: This autorun will launch a terminal with btop when plugged in. (requires btop and ghostty to be installed on the host)
  provides_file: false  # true if the USB provides the file to run; must be false when using a direct command
  run:
    file: null          # path to the file to run (USB path if provides_file, else host path); set to null when using command
    interpreter: null   # interpreter used only when running a file; null when using command
    arguments: null     # list of arguments to pass to the file; null when none
    command: "ghostty -e 'bash -c \"btop\"'"  # alternatively, run a direct command instead of a file
```

And that's it, the Aegis Daemon will take care of the rest, decrypting the autorun file, verifying it, and running it in your computer, we don't do sandboxing here, that's your job to make sure what you're autorunning is safe.




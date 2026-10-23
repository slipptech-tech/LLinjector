# LLInjector

DLL loader to an arbitrary process via 'LoadLibraryExW'. Separate
GUI, process selection from the list, DLL selection via File Explorer, 
Request for administrator rights at window start. 

## Assembly

```
build.bat
```

The script finds the installed Visual Studio via 'vswhere' (first taken
the latest version, i.e. VS 2026 if available) and collects both bit sizes. 

The result in 'build': 

| File | Purpose |
| --- | --- |
| `LLInjector.exe` | 64-bit Injector |
| `LLInjector_x86.exe` | 32-bit injector, for 32-bit processes |
| `test_payload_x64.dll` | test DLL, writes a file in '%TEMP%' |
| `test_payload_x86.dll` | the same for 32-bit processes |

## How to use

1. Run 'LLInjector.exe'. A UAC prompt will appear — the window works with permissions
administrator. 
2. Find a process: The "Filter" field narrows down the list by name. 
3. Select a line in the list. 
4. Click "Browse..." and specify the DLL. You can simply drag and drop the '.dll' file into the window. 
5. Click "Inject". 

Scroll down ...

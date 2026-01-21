# Static analysis
## Ghidra
### Top-Down
- Goto WinMain (after preembule code)
    - look like  : 
          GetStartupInfoA(&local_60);
          GetModuleHandleA((LPCSTR)0x0);
          local_6c = FUN_00408140();<- RealMain
        or
          DAT_0040d010 = FUN_00401e3b();<- RealMain
          if (DAT_0040d00c != 0) {
            if (DAT_0040d008 != 0) {
    -> change signature to WinMain

- InternetOpenA -> correct signature (-> Create new typedef)
- GetModuleFileName -> argc
- sprintf -> formatString -> Adapt signature
    -> if not recognise -> clear codebyte 
- CreateService
    -> if fixed IOC
- GetProcAdress -> pointer to FCT (obfuscation)
    -> rename + retype to FCT *
    -> moveFileExA + CreateFile = obfuscation
FindRessources (num in HEX -> convert)
    -> load + lock -> pointer to ressource
    |-> Symbol tree, find ressource, make selection, extract/import
_____________________________________________________________________

### Down-Top
Window  -> Defined Strings (keys)
        -> Symbole Rerferencs  (mutex, regOpen, connect, ...)

- RegOpenKeyA -> return code
             |-> find references
- CopyFileA (source, dest)
- GetFolderPath(..., O, ...) - CSIDL
                     |-> set Equate
- CreatePipe(in, out)

## OlyDbg


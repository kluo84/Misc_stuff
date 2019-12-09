!include <Win32.Mak>

!if "$(CPU)" == "i386"
cflags = $(cflags) -D_CRTAPI1=_cdecl -D_CRTAPI2=_cdecl
!else
cflags = $(cflags) -D_CRTAPI1= -D_CRTAPI2=
!endif

all : dnsxplc 

# Make the client side application dnsxplc
dnsxplc : dnstest.exe
dnstest.exe : dnsxplc.obj dnsxpl_c.obj
    $(link) $(linkdebug) $(conflags) -out:dnstest.exe \
      dnsxplc.obj dnsxpl_c.obj \
      rpcrt4.lib $(conlibsdll)

# dnsxplc main program
dnsxplc.obj : dnsxplc.c dnsxpl.h
   $(cc) $(cdebug) $(cflags) $(cvarsdll) /W3 $*.c

# dnsxplc stub
dnsxpl_c.obj : dnsxpl_c.c dnsxpl.h
   $(cc) $(cdebug) $(cflags) $(cvarsdll) /W3 $*.c


# remote procedures
dnsxplp.obj : dnsxplp.c dnsxpl.h
   $(cc) $(cdebug) $(cflags) $(cvarsdll) /W3 $*.c

# Stubs and header file from the IDL file
dnsxpl.h dnsxpl_c.c : dnsxpl.idl dnsxpl.acf
    midl $(MIDL_OPTIMIZATION) -oldnames -use_epv -no_cpp dnsxpl.idl

# Clean up everything
clean : 
    -del *.exe
    -del dnsxpl_s.c
    -del *.pdb
    -del *.obj
    -del dnsxpl_c.c
    -del dnsxpl.h


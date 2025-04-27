# DropperDataSection
Dropper inside the Data Section

Which sections of the PE we can put our code into


Today Lets try to understand different sections where the malicious payload or we can place the code or shellcode in the PE file.

PE has many sections , but her we would be concentrating on main three sections. Which are ...  

1. .text
2. .data
3. .rsrc

To do that lets create a simple code which helps us to understand more , for this we need visual studio (or gcc compiler being installed and use it to compile and create an exe file to run) and x64dbg
https://x64dbg.com/ to download the x64dbg debugger and installation is simple 

![image](https://github.com/user-attachments/assets/f97d1670-b7cb-4668-ad9d-2ac625eadeb4)

It's just a simple diagram which shows the different sections we would be seeing in the PE file.

so we shall first discuss on steps 
1. what API methods are used to allocate a space in the process memory  
2. move our payload into the virtually allocated memory  
3. Then how to provide the permissions after that we can also see the x64dbg being used to see the payload placement.
4. Create a Threat inside the current Process. 


VirutallAlloc is an API which is defined in Kernel32.dll, which allocates a memory in the process we mention

		void * exec_memory;
		
		LPVOID VirtualAlloc( 		
		  LPVOID lpAddress,                // Starting address from which the allacotion should happen , exmple a memory  
		  SIZE_T dwSize,                  // Size of the memory to be allocated   
		  DWORD  flAllocationType,        // What kind of allocation for the memory to be allocated like MEM_COMMIT, MEM_RESERVE 
		  DWORD  flProtect                // Memory Protection to be allocated PAGE_EXECUTE , PAGE_READWRITE etc 
		  );  


Sample line of code =>  

	exec_memory = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  
 
 Here we are allocting the memory from 0 address until payload_len, we are having a allocation type as MEM_COMMIT and MEM_RESERVE and giving the permission as PAGE_READWRITE just to avoid the EDR triggering as suspicious if the allocated memory is given directly as PAGE_EXECUTE  

We can find more detailed information in the link [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

Next API Used is RtlMoveMemory, which is used to copy the payload from Source to Destination

		VOID RtlMoveMemory( 		
		  VOID UNALIGNED *Destination,   // Where to move the memory  
		  const VOID UNALIGNED *Source,   // From where to move the payload 
		  SIZE_T         Length           //size of the payload  
		  );  


Sample line of code =>  

	RtlMoveMemory(exec_memory, payload, payload_len); 
 
Here the payload is moved to address pointed or allocated from the VirtualAlloc API  

We can find more detailed information in the link [RtlMoveMemory](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

Next API is VirtualProtect, which Changes the protection on a region of committed pages in the virtual address space of the calling process.

		BOOL VirtualProtect(		
		  [in]  LPVOID lpAddress,    // Source address or address to which we need to change the protection or permission  
		  [in]  SIZE_T dwSize,       // Size of the memory to change the protect
		  [in]  DWORD  flNewProtect, // New Protection we apply from the old protection
		  [out] PDWORD lpflOldProtect // A pointer to a variable that receives the previous access protection value, that is initial page 
		  );  

Sample line of code => 

	rv = VirtualProtect(exec_memory, payload_len, PAGE_EXECUTE_READ, &oldprotect);  
 
 the exec_mem which has the payload or pointing to the payload had a protection PAGE_READWRITE initially and now its being changed to PAGE_EXECUTE_READ

We can find more detailed information in the link [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

Next API would be CreateThread, which creates thread in the process 

	HANDLE CreateThread(  
	  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,     // A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle can be inherited by child processes.  
	  [in]            SIZE_T                  dwStackSize,    // The initial size of the stack, in bytes  
	  [in]            LPTHREAD_START_ROUTINE  lpStartAddress, //   This pointer represents the starting address of the thread  
	  [in, optional]  __drv_aliasesMem LPVOID lpParameter,    //  A pointer to a variable to be passed to the thread.  
	  [in]            DWORD                   dwCreationFlags,  // The flags that control the creation of the thread  
	  [out, optional] LPDWORD                 lpThreadId   //  A pointer to a variable that receives the thread identifier  
	);   

Sample line of code => 

	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_memory, 0, 0, 0); 
 
 LPTHREAD_START_ROUTINE  Points to a function that notifies the host that a thread has started to execute and exec_mem start of payload to start

We can find more detailed information in the link [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)


Now lets start to understand how it works using the debugger x64dbg

The code which is attached in the post is which you can compile using gcc and create a obj and exe file , Once the exe file is created follow the steps

1. Once you execute the code you would be seeing the address

   ![image](https://github.com/user-attachments/assets/1fdc35a0-3b1b-4333-84c7-814cf218d29f)

   Copy it and save it on the notepad

   payload addr         : 0x00007FF7DE0BD000
   exec_mem addr        : 0x0000020E7F2B0000

2.  Now lets launch my favourite tool x64dbg and see the payload details

    Click on the Attach, which attaches the running exe file to the debugger

    ![image](https://github.com/user-attachments/assets/5e5ea275-648a-4225-9a92-24761b47173d)

3. Once clicked select the code or exe which is being executed or name of our exe file

   ![image](https://github.com/user-attachments/assets/69bbe6e3-98d6-4d91-a1e5-cd63709abae7)

4.  After the running exe is attached, Now we can see the x64dbg is in Paused state so we need to run the debugger by clicking on run and watch the state moves form Paused to 	    Running.

   ![image](https://github.com/user-attachments/assets/95ae35c6-29e0-446f-b984-31b1882d0dfb)

5. Now lets go to the terminal where we ran the exe file, which is waiting for our input press Enter key. Once Enter the debugger stops at the INT3 op code which we have in 	   our payload as the screnshot

   ![image](https://github.com/user-attachments/assets/0c1ce261-92b0-4c21-9405-fa899cc27082)

   In the above image we can see the payload we had in our code is being shown , The sample payload being used in the code is being pasted here

		unsigned char payload[] = {  
				0x40,		// INC EAX  
				0x90,		// NOP  
				0xcc,		// INT3  
				0xc3		// RET  
			};

   Now our main objective is to find where the payload is stored and which sections we can see them.

   Steps

    1. Got to Memory Map Tab and right click on empty space and select Find Patterns

   ![image](https://github.com/user-attachments/assets/a62069c7-a0b4-4f7e-93aa-747bcc35f192)

    2. Type the payload in the below format and click on Entire block, which is equal to find whole word ...

   ![image](https://github.com/user-attachments/assets/1bd39c83-137f-4d19-9630-e96213dd79df)

    3. We will get the address where the pattern or payload is saved

![image](https://github.com/user-attachments/assets/ad5f3f7b-8068-4649-be1e-545b3a142ed7)

    4. we will select, right click and copy the Cropped Table

    ![image](https://github.com/user-attachments/assets/cd67adb6-3802-45a4-aacb-ec7e26dd8c60)

    		
    5. Now lets start comparing them in the Memory map 
    		Address           Data                                                                                                                                                               
		0000020E7F2B0000  40 90 CC C3
		00007FF7DE0BD000  40 90 CC C3

  	1. Pasted all the details in he same screenshot 
![image](https://github.com/user-attachments/assets/832fa6fb-9c22-4d1c-b34c-7810c5300bec)

  	2. Now we are considering the first address 0000020E7F2B0000 and we will find out where it being saved or stored , here we can see the Priv which means the 
                   exec memory is stored here and also initial it was RW (read write) and now its ER which is Execute Read(to avoid triggering as issue from EDR)

![image](https://github.com/user-attachments/assets/956494ee-ceda-4a05-84ea-eb19324d1e5d)

	3. Now if we check the second address where it falls , it falls under the section .data which means anything stored or decalred as variables outside main function or 
        any function are saved in .data 

 ![image](https://github.com/user-attachments/assets/8c0574d6-85f3-4015-ac89-9403bada607f)



 For more information on Section .text , please visit [.text](https://github.com/kumarsiddappa-git/Dropper)





     










   


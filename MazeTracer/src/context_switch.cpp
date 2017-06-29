#include "pin.H"
#include "mazewarker.h"

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	char buf[1024];

    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
	LOG("\n\n\n[" + string(__FUNCTION__) + "]\n >>>>>>>>>>> Exception <<<<<<<<<<<\n");
    LOG(PIN_ExceptionToString(pExceptInfo));
	
    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, sizeof(buf) - 1, 
        "\tException code=0x%x address=0x%x tid=%d\n"
        "\t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x "
        "eip=%08x esp=%08x ebp=%08x\n",
		pExceptInfo->GetExceptCode(), 
		PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP), PIN_ThreadId(),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EAX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_ECX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EDX),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESI),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EDI),
        PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP), 
		PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESP), 
		PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBP));
    LOG(string(buf));
	LOG("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n\n");

	// log callstack    
	ADDRINT eip = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EIP);
    ADDRINT esp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_ESP);
    ADDRINT ebp = PIN_GetPhysicalContextReg(pPhysCtxt, REG_EBP);
    ADDRINT childebp = 0;
    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, sizeof(buf) - 1, 
        "\tCallstack:\n"
        "\t\tFramePtr ChildEBP RetAddr\n");
    LOG(buf);

    int count = 0;
    memset(buf, 0, sizeof(buf));
    while(ebp != 0 && count < 20)
    {
        if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
            break;
        if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
            break;      

        sprintf_s(buf, sizeof(buf) -1, "\t\t%08x %08x %08x\n", 
            ebp, childebp, eip);
        LOG(buf);

        if(PIN_SafeCopy(&ebp, (ADDRINT *)ebp, 4) != 4) 
            break;

        count++;
    }

    return EHR_UNHANDLED ;
}

VOID ContextCallback(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
    switch(reason)
    {
    case CONTEXT_CHANGE_REASON_EXCEPTION:
        ADDRINT eip = PIN_GetContextReg(from, REG_EIP);
        ADDRINT esp = PIN_GetContextReg(from, REG_ESP);
        ADDRINT ebp = PIN_GetContextReg(from, REG_EBP);
        ADDRINT childebp = 0;
    
        char buf[1024];
        memset(buf, 0, sizeof(buf));
        sprintf_s(buf, sizeof(buf) - 1, 
            "\tException code=0x%x address=0x%x tid=%d\n"
            "\t\teax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x "
            "eip=%08x esp=%08x ebp=%08x\n",
            info, eip, tid,
            PIN_GetContextReg(from, REG_EAX),
            PIN_GetContextReg(from, REG_EBX),
            PIN_GetContextReg(from, REG_ECX),
            PIN_GetContextReg(from, REG_EDX),
            PIN_GetContextReg(from, REG_ESI),
            PIN_GetContextReg(from, REG_EDI),
            eip, esp, ebp);
        LOG("[" + string(__FUNCTION__) + "]\n" + string(buf));

        // log callstack        
        memset(buf, 0, sizeof(buf));
        sprintf_s(buf, sizeof(buf) - 1, 
            "\tCallstack:\n"
            "\t\tFramePtr ChildEBP RetAddr\n");
        LOG(buf);

        int count = 0;
        memset(buf, 0, sizeof(buf));
        while(ebp != 0 && count < 20)
        {
            if(PIN_SafeCopy(&childebp, (ADDRINT *)(ebp), 4) != 4) 
                break;
            if(PIN_SafeCopy(&eip, (ADDRINT *)(ebp + 4), 4) != 4) 
                break;      

            sprintf_s(buf, sizeof(buf) -1, "\t\t%08x %08x %08x\n", 
                ebp, childebp, eip);
            LOG(buf);

            if(PIN_SafeCopy(&ebp, (ADDRINT *)ebp, 4) != 4) 
                break;

            count++;
        }
        break;
    }
}
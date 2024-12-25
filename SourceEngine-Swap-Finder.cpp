#include "SDK/Chdr/chdr.h"
#include "SDK/Misc/fnv.h"

#include <unordered_map>

struct SummedInterfaceReg_t {
    fnv_t m_fnvInterfaceNameHash;
    std::uintptr_t m_nInterfaceAddress;
    std::uintptr_t m_nInterfaceVFTableAddress;
};

#define CHLCLIENT_INTERFACE_NAME FNV("VClient016")
#define ENGINECVAR_INTERFACE_NAME FNV("VEngineCvar007")

#define EFFECTDATALIST_HEAD_OFFSET 0X7AD278
#define CHLCLIENT_GETALLCLASSES_IDX 7
#define CCVAR_GETBOOL_IDX 13

std::vector<SummedInterfaceReg_t> g_SummedInterfaceRegs = {};

static std::unordered_map<fnv_t, std::vector<std::pair<const char*, int>>> g_WishVFTableScan = {
    { FNV("VClient016"), {
        std::make_pair("CHLClient::CreateMove", 20),
        std::make_pair("CHLClient::FrameStageNotify", 34),
        std::make_pair("CHLClient::LevelInitPreEntity", 4),
        std::make_pair("CHLClient::LevelShutdown", 6),
        }
    },
    { FNV("VClientPrediction001"), {
        std::make_pair("CPrediction::InPrediction", 14)
        }
    },
};

// Walk every module, finding s_pInterfaceRegs if available and traversing that list.
void Gather_InterfaceData(chdr::Process_t& TargetProcess, std::vector<chdr::Process_t::ModuleInformation_t>& Modules) {
    for (const auto& CurrentModule : Modules) {
        chdr::Module_t Module(TargetProcess, CurrentModule.m_szName.c_str());
        if (!Module.IsValid())
            continue;

        const auto ExportDataList = Module.GetPEHeaderData().GetExportData();
        auto it = std::find_if(ExportDataList.begin(), ExportDataList.end(), [](const auto& pair) {
            return std::strcmp(pair.m_szName.c_str(), "CreateInterface") == 0;
            });

        if (it == ExportDataList.end())
            continue;

        // Certain modules don't invoke an internal CreateInterface, rather an inlined version.
        // We can check if there's an expected JMP present to the internal function. ^ (steamclient.dll, vstdlib_s.dll, crashhandler.dll)
        /*
            .text:102860A0 55                                push    ebp
            .text:102860A1 8B EC                             mov     ebp, esp
            .text:102860A3 5D                                pop     ebp
            .text:102860A4 E9 87 FF FF FF                    jmp     CreateInterface_Internal
        */

        std::uintptr_t s_pInterfaceRegs = 0u; // Final interface regs address.
        std::uint8_t uFoundInstruction = 0u; // Where we expect the JMP to be.

        const std::uintptr_t nRelJMPAddr = CurrentModule.m_BaseAddress + it->m_nAddress + 0x4; // JMP to internal createinterface.
        TargetProcess.Read(nRelJMPAddr, &uFoundInstruction, sizeof(uFoundInstruction));

        if (uFoundInstruction == 0x4D) 
            continue; // Edge case for crashhandler.dll (It all redirects to one VFTable, who cares about this really?)
        
        if (uFoundInstruction == 0xE9) {
            // Get relative jmp offset.
            std::uintptr_t nRelativeOffset = 0u;
            TargetProcess.Read(nRelJMPAddr + 0x1, &nRelativeOffset, sizeof(nRelativeOffset));

            const std::uintptr_t CreateInterface_Internal = nRelJMPAddr + nRelativeOffset + 0x5;
            const std::uintptr_t s_pInterfaceRegsAddr = CreateInterface_Internal + 0x6;

            TargetProcess.Read(s_pInterfaceRegsAddr, &s_pInterfaceRegs, sizeof(s_pInterfaceRegs));
            TargetProcess.Read(s_pInterfaceRegs, &s_pInterfaceRegs, sizeof(s_pInterfaceRegs));
        } 
        else /*if (uFoundInstruction == 0x8B)*/ {
            const std::uintptr_t s_pInterfaceRegsAddr = (CurrentModule.m_BaseAddress + it->m_nAddress) + 0x6;

            TargetProcess.Read(s_pInterfaceRegsAddr, &s_pInterfaceRegs, sizeof(s_pInterfaceRegs));
            TargetProcess.Read(s_pInterfaceRegs, &s_pInterfaceRegs, sizeof(s_pInterfaceRegs));
        }

        if (!s_pInterfaceRegs) 
            continue; // launcher.dll doesn't contain any interfaces.
    
        // https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/tier1/interface.h#L72
        struct InterfaceReg_t {
            std::uintptr_t m_pCreateFN;
            std::uintptr_t m_InterfaceName;
            std::uintptr_t m_pNext;
        };

        InterfaceReg_t InterfaceRegInst = {};
        for (std::uintptr_t pCur = s_pInterfaceRegs; pCur; pCur = InterfaceRegInst.m_pNext) {
            char szInterfaceName[128];

            TargetProcess.Read(pCur, &InterfaceRegInst, sizeof(InterfaceRegInst));
            TargetProcess.Read(InterfaceRegInst.m_InterfaceName, szInterfaceName, sizeof(szInterfaceName));

            std::uintptr_t nInterfaceAddr = 0u;
            TargetProcess.Read(InterfaceRegInst.m_pCreateFN + 0x1, &nInterfaceAddr, sizeof(nInterfaceAddr));

            // Access VFtable of the interface.
            std::uintptr_t nInterfaceVFTableAddr = 0u;
            TargetProcess.Read(nInterfaceAddr + 0x0, &nInterfaceVFTableAddr, sizeof(nInterfaceVFTableAddr));

            std::string szHashableString = std::string(szInterfaceName); // Simple conversion to hash up to null-terminator.
            g_SummedInterfaceRegs.emplace_back(SummedInterfaceReg_t{ fnv::hash_runtime(szHashableString.c_str()), nInterfaceAddr, nInterfaceVFTableAddr });
        }
    }
}

// For each of the interfaces we cached, check the appropriate entries to determine if any reside in unbacked memory.
void WalkList_Interfaces(chdr::Process_t &TargetProcess, std::vector<chdr::Process_t::ModuleInformation_t>& Modules) {

    for (const auto& CurrentInterfaceReg : g_SummedInterfaceRegs) {
        if (!g_WishVFTableScan.contains(CurrentInterfaceReg.m_fnvInterfaceNameHash))
            continue;

        for (const auto& [szVFuncName, nVFuncIndex] : g_WishVFTableScan.at(CurrentInterfaceReg.m_fnvInterfaceNameHash)) {
            std::uintptr_t nInterfaceFunctionAddr = 0u;
            TargetProcess.Read(CurrentInterfaceReg.m_nInterfaceVFTableAddress + (nVFuncIndex * sizeof(void*)), &nInterfaceFunctionAddr, sizeof(nInterfaceFunctionAddr));

            MEMORY_BASIC_INFORMATION MBI = { };
            TargetProcess.Query(reinterpret_cast<LPVOID>(nInterfaceFunctionAddr), &MBI);

            // Does this allocation base match up with any of the modules loaded in the process?
            bool bFoundAsValidModule = std::any_of(Modules.begin(), Modules.end(), [&](const auto& CurrentModule) {
                return CurrentModule.m_BaseAddress == reinterpret_cast<std::uintptr_t>(MBI.AllocationBase);
                });

            if (!bFoundAsValidModule)
                std::printf("[Detection] VFunc %s(%i) in unexpected location (0x%X). AllocBase: 0x%X\n",
                    szVFuncName, nVFuncIndex, nInterfaceFunctionAddr, reinterpret_cast<std::uintptr_t>(MBI.AllocationBase));
       
            // TODO; To refine it more, we can add inline-hook detections at the function address.
        }
    }
}

// Walk g_pClientClassHead, checking all classes' m_pCreateFn determining if any reside in unbacked memory, then walk the props from the clientclass checking m_pProxyFn along the way.
void WalkList_ClientClasses(chdr::Process_t& TargetProcess, std::vector<chdr::Process_t::ModuleInformation_t>& Modules, chdr::Module_t &ClientDLL) {
    auto it = std::find_if(g_SummedInterfaceRegs.begin(), g_SummedInterfaceRegs.end(), [](const auto& CurrentInterface) {
        return CurrentInterface.m_fnvInterfaceNameHash == CHLCLIENT_INTERFACE_NAME;
        });

    if (it == g_SummedInterfaceRegs.end())
        return;

    std::uintptr_t nCHLClient_GetClientClassesAddr = 0u;
    TargetProcess.Read(
        it->m_nInterfaceVFTableAddress + (CHLCLIENT_GETALLCLASSES_IDX * sizeof(void*)),
        &nCHLClient_GetClientClassesAddr,
        sizeof(nCHLClient_GetClientClassesAddr));

    /*
        .text:100A8A40 A1 D4 A4 73 10                    mov     eax, g_pClientClassHead
        .text:100A8A45 C3                                retn
    */

    std::uintptr_t g_pClientClassHead = 0u;
    TargetProcess.Read(nCHLClient_GetClientClassesAddr + 0x1, &g_pClientClassHead, sizeof(g_pClientClassHead));
    TargetProcess.Read(g_pClientClassHead, &g_pClientClassHead, sizeof(g_pClientClassHead));
   
    // https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/client_class.h#L49
    struct ClientClass_t {
        std::uintptr_t m_pCreateFn;
        std::uintptr_t m_pCreateEventFn;
        std::uintptr_t m_pNetworkName;
        std::uintptr_t m_pRecvTable;
        std::uintptr_t m_pNext;
    };

    // https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/dt_recv.h#L87
    struct RecvProp {
        std::uintptr_t m_pPropName;
        std::uintptr_t m_nPropType;
        std::uintptr_t m_nPropFlags;
        std::uintptr_t m_nBufferSize;
        std::uintptr_t m_bInsideArray;
        std::uintptr_t m_pExtraDataPtr;
        std::uintptr_t m_pArrProp;
        std::uintptr_t m_pArrLenProxy;
        std::uintptr_t m_pProxyFn;
        std::uintptr_t m_pDataTableProxyFn;
        std::uintptr_t m_pDataTable;
        std::uintptr_t m_nOffset;
        std::uintptr_t m_nElementsStride;
        std::uintptr_t m_nElementsCount;
        std::uintptr_t m_pParentArrayPropName;
    };
    
    ClientClass_t ClientClassInst = {};
    for (std::uintptr_t pCur = g_pClientClassHead; pCur; pCur = ClientClassInst.m_pNext) {
        TargetProcess.Read(pCur, &ClientClassInst, sizeof(ClientClassInst));

        char szClassName[128];
        TargetProcess.Read(ClientClassInst.m_pNetworkName, szClassName, sizeof(szClassName));

        std::uintptr_t nRecvPropsAddr = 0u;
        std::uint32_t  nRecvPropCount = 0u;
        TargetProcess.Read(ClientClassInst.m_pRecvTable + 0x0, &nRecvPropsAddr, sizeof(nRecvPropsAddr));
        TargetProcess.Read(ClientClassInst.m_pRecvTable + 0x4, &nRecvPropCount, sizeof(nRecvPropCount));

        if (nRecvPropCount <= 0)
            continue;

        // Reading all props here in one go for some performance gain, it's contigious in memory.
        const auto RecvPropData = std::make_unique<RecvProp[]>(nRecvPropCount * sizeof(RecvProp));
        TargetProcess.Read(nRecvPropsAddr, RecvPropData.get(), nRecvPropCount * sizeof(RecvProp));

        for (int i = 0; i < nRecvPropCount; ++i) {
            const RecvProp& CurrentProp = RecvPropData.get()[i];
            if (CurrentProp.m_pProxyFn == 0u)
                continue; // A lot won't have it.

            // Read name from pointer.
            char szPropName[128];
            TargetProcess.Read(CurrentProp.m_pPropName, szPropName, sizeof(szPropName));

            // m_pProxyFn if non-null is expected to reside in client.dll
            const bool bAddressBackedByClientDLL =
                CurrentProp.m_pProxyFn >= ClientDLL.m_dModuleBaseAddress &&
                CurrentProp.m_pProxyFn <= ClientDLL.m_dModuleBaseAddress + ClientDLL.m_dModuleSize;

            if (!bAddressBackedByClientDLL)
                std::printf("[Detection] %s->%s m_pProxyFn in unexpected location (0x%X)\n", szClassName, szPropName, CurrentProp.m_pProxyFn);
        }

        const bool bAddressBackedByModule = (ClientClassInst.m_pCreateFn == 0) ||
            std::any_of(Modules.begin(), Modules.end(), [&](const auto& Module) {
            return ClientClassInst.m_pCreateFn >= Module.m_BaseAddress &&
                ClientClassInst.m_pCreateFn <= Module.m_BaseAddress + Module.m_nSize;
                });

        if (!bAddressBackedByModule)
            printf("[Detection] %s->m_pCreateFn in unexpected location (0x%X).\n", szClassName, ClientClassInst.m_pCreateFn);
    }
}

// Walk the ConCommandBase list to gather all ConVars, and check their respecting GetBool/GetInt determining if any reside in unbacked memory.
void WalkList_ConVars(chdr::Process_t& TargetProcess, std::vector<chdr::Process_t::ModuleInformation_t> &Modules) {
    auto it = std::find_if(g_SummedInterfaceRegs.begin(), g_SummedInterfaceRegs.end(), [](const auto& CurrentInterface) {
        return CurrentInterface.m_fnvInterfaceNameHash == ENGINECVAR_INTERFACE_NAME;
        });

    if (it == g_SummedInterfaceRegs.end())
        return;

    std::uintptr_t nCVarLinkedList = 0u;
    TargetProcess.Read(it->m_nInterfaceAddress + 0x30, &nCVarLinkedList, sizeof(nCVarLinkedList));

    // https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/tier1/convar.h#L151
    struct ConCommandBase_t {
        std::uintptr_t m_pVFTable;
        std::uintptr_t m_pNext;
        std::uint8_t   m_bRegistered;
        std::uintptr_t m_pName;
    };

    ConCommandBase_t ConCommandInst = {};
    for (std::uintptr_t pCur = nCVarLinkedList; pCur; pCur = ConCommandInst.m_pNext) {
        TargetProcess.Read(pCur, &ConCommandInst, sizeof(ConCommandInst));

        char szConVarName[128];
        TargetProcess.Read(ConCommandInst.m_pName, szConVarName, sizeof(szConVarName));

        std::uintptr_t nGetBoolFunctionAddress = 0u;
        TargetProcess.Read(ConCommandInst.m_pVFTable + (CCVAR_GETBOOL_IDX * sizeof(int)), &nGetBoolFunctionAddress, sizeof(nGetBoolFunctionAddress));

        MEMORY_BASIC_INFORMATION MBI = { };
        TargetProcess.Query(reinterpret_cast<LPVOID>(nGetBoolFunctionAddress), &MBI);

        // Does this allocation base match up with any of the modules loaded in the process?
        bool bFoundAsValidModule = std::any_of(Modules.begin(), Modules.end(), [&](const auto& CurrentModule) {
            return CurrentModule.m_BaseAddress == reinterpret_cast<std::uintptr_t>(MBI.AllocationBase);
            });

        if (!bFoundAsValidModule)
            std::printf("[Detection] ConVar %s's GetBool in unexpected location (0x%X). AllocBase: 0x%X\n",
                szConVarName, nGetBoolFunctionAddress, reinterpret_cast<std::uintptr_t>(MBI.AllocationBase));

        // TODO; To refine it more, we can add inline-hook detections at the function address.
    }
}

// Walk the CClientEffectRegistration::s_pHead to gather all effects, and check their respecting m_pFunction determining if any reside in unbacked memory.
void WalkList_CClientEffectRegistration(chdr::Process_t& TargetProcess, std::vector<chdr::Process_t::ModuleInformation_t>& Modules, chdr::Module_t& ClientDLL) {
    std::uintptr_t nEffectDataListHead = 0u;
    TargetProcess.Read(ClientDLL.m_dModuleBaseAddress + EFFECTDATALIST_HEAD_OFFSET, &nEffectDataListHead, sizeof(nEffectDataListHead));
 
    // https://github.com/ValveSoftware/source-sdk-2013/blob/0d8dceea4310fde5706b3ce1c70609d72a38efdf/sp/src/game/client/c_te_effect_dispatch.h#L21
    struct CClientEffectRegistration_t {
        std::uintptr_t m_pEffectName;
        std::uintptr_t m_pFunction;
        std::uintptr_t m_pNext;
    };

    CClientEffectRegistration_t CClientEffectRegistrationInst = {};
    for (std::uintptr_t pCur = nEffectDataListHead; pCur; pCur = CClientEffectRegistrationInst.m_pNext) {
        TargetProcess.Read(pCur, &CClientEffectRegistrationInst, sizeof(CClientEffectRegistrationInst));

        char szEffectName[128];
        TargetProcess.Read(CClientEffectRegistrationInst.m_pEffectName, szEffectName, sizeof(szEffectName));

        MEMORY_BASIC_INFORMATION MBI = { };
        TargetProcess.Query(reinterpret_cast<LPVOID>(CClientEffectRegistrationInst.m_pFunction), &MBI);

        // Does this allocation base match up with any of the modules loaded in the process?
        bool bFoundAsValidModule = std::any_of(Modules.begin(), Modules.end(), [&](const auto& CurrentModule) {
            return CurrentModule.m_BaseAddress == reinterpret_cast<std::uintptr_t>(MBI.AllocationBase);
            });

        if (!bFoundAsValidModule)
            std::printf("[Detection] %s->m_pFunction in unexpected location (0x%X). AllocBase: 0x%X\n",
                szEffectName, CClientEffectRegistrationInst.m_pFunction, reinterpret_cast<std::uintptr_t>(MBI.AllocationBase));
    }
}

int main() {
    chdr::Process_t TargetProcess(L"left4dead2.exe", chdr::PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_NONE); // L4D2 my beloved <3
    if (!TargetProcess.IsValid()) {
        std::printf("[!!] Unable to locate target process.\n");
        return 0;
    }

    chdr::Module_t TargetClientDLL(TargetProcess, "client.dll", chdr::PEHeaderData_t::PEHEADER_PARSING_TYPE::TYPE_NONE);   
    if (!TargetClientDLL.IsValid()) {
        std::printf("[!!] Unable to locate client.dll within target process.\n");
        return 0;
    }

    std::vector<chdr::Process_t::ModuleInformation_t> TargetModules = TargetProcess.EnumerateModules(true);
    std::printf("[++] Gathering engine data from target process.\n");

    Gather_InterfaceData(TargetProcess, TargetModules);
    if (g_SummedInterfaceRegs.empty()) {
        std::printf("[!!] Unable to gather interface list within target process.\n");
        return 0;
    }

    std::printf("[++] Scanning for potentially swapped data...\n\n");

    WalkList_ConVars(TargetProcess, TargetModules);
    WalkList_Interfaces(TargetProcess, TargetModules);
    WalkList_ClientClasses(TargetProcess, TargetModules, TargetClientDLL);
    WalkList_CClientEffectRegistration(TargetProcess, TargetModules, TargetClientDLL);

    std::printf("[++] Scan complete!\n");
}
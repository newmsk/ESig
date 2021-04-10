import idaapi
import ida_search
import ida_bytes
import ida_name
import ida_nalt
import ida_lines
import ida_xref
import ida_funcs
import ida_auto
import ida_segment

def get_ida_signame(lib_cn_name):
    sig_names = {
    "系统核心支持库":           "e_lang_krnln",
    "编码转换支持库":           "e_lang_iconv",
    "远程服务支持库":           "e_lang_Exmlrpc",
    "应用接口支持库":           "e_lang_eAPI",
    "压缩解压支持库":           "e_lang_eCompress",
    "网络通讯支持库二":         "e_lang_ERawSock",
    "网络通讯支持库":           "e_lang_sock",
    "网络传送支持库":           "e_lang_downlib",
    "扩展功能支持库一":         "e_lang_shellEx",
    "局域网操作支持库":         "e_lang_WNet",
    "互联网支持库":             "e_lang_internet",
    "多线程支持库":             "e_lang_EThread",
    "操作系统界面功能支持库":    "e_lang_shell",
    "保密通讯支持库":           "e_lang_ESSLayer",
    "XML解析支持库":            "e_lang_EXMLParser",
    "数据操作支持库一":         "e_lang_dp1",
    "特殊功能支持库":           "e_lang_spec",
    "正则表达式支持库":         "e_lang_RegEx"
    }

    if lib_cn_name in sig_names:
        return sig_names[lib_cn_name]

    return None

def get_code_segs():
    codesegs = []
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg.type == ida_segment.SEG_CODE:
            codesegs.append(seg)
    return codesegs

def poi(ea):
    return ida_bytes.get_dword(ea)

def create_and_get_typec_string(ea):
    size = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNCLT | ida_bytes.ALOPT_IGNHEADS | ida_bytes.ALOPT_IGNPRINT)
    if size == 0:
        return ""
    ida_bytes.create_strlit(ea, size, ida_nalt.STRTYPE_C)
    string = str(ida_bytes.get_strlit_contents(ea, size, ida_nalt.STRTYPE_C), encoding="utf-8")
    return string

def get_E_info_entry():
    # .text:004AE780 50                            push    eax
    # .text:004AE781 64 89 25 00 00 00 00          mov     large fs:0, esp
    # .text:004AE788 81 EC AC 01 00 00             sub     esp, 1ACh
    # .text:004AE78E 53                            push    ebx
    # .text:004AE78F 56                            push    esi
    # .text:004AE790 57                            push    edi
    E_lib_pat = "50 64 89 25 00 00 00 00 81 ec ac 01 00 00 53 56 57"
    E_lib_addr_offset = 0x25

    E_lib_infos_ea = 0
    code_segs = get_code_segs()

    for seg in code_segs:
        start_ea = seg.start_ea
        end_ea = seg.end_ea
        E_lib_pat_ea = ida_search.find_binary(start_ea, end_ea, E_lib_pat, 16, ida_search.SEARCH_DOWN)
        if E_lib_pat_ea != idaapi.BADADDR:
            mov_ins_ea = E_lib_pat_ea + E_lib_addr_offset
            E_lib_infos_ea = ida_bytes.get_dword(mov_ins_ea + 1)
            break
    
    return E_lib_infos_ea


class Elib:

    def __init__(self, ea):
        self.guid = create_and_get_typec_string(poi(ea+0x4))
        self.name = create_and_get_typec_string(poi(ea+0x24))
        self.sig_name = get_ida_signame(self.name)

    def __repr__(self):
        return "elib guid is %s, name is %s" %(self.guid, self.name)


class Elibs:

    def __init__(self, start_ea, count):
        self.elib_count = count
        self.libs = []
        for i in range(self.elib_count):
            self.libs.append(Elib(poi(start_ea + 4*i)))
    
    def __repr__(self):
        hdr = "total %d elibs: \n" %self.elib_count
        lib_infos = ""
        for lib in self.libs:
            lib_infos += lib.__repr__() + "\n"
        return hdr + lib_infos

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index >= self.elib_count: 
            raise StopIteration
        result = self.libs[self.index]
        self.index += 1
        return result

class Dll_calls:
    def __init__(self, libname_start_ea, func_name_start_ea, dll_call_count, show_module=False):
        self.show_module = show_module
        self.dll_call_count = dll_call_count
        self.libnames = []
        self.funcnames = []
        self.func_name_start_ea = []
        for i in range(self.dll_call_count):
            libname_ea = poi(libname_start_ea + 4*i)
            funcname_ea = poi(func_name_start_ea + 4*i)
            libname = create_and_get_typec_string(libname_ea)
            funcname = create_and_get_typec_string(funcname_ea)
            self.libnames.append(libname)
            self.funcnames.append(funcname)
    
    def __repr__(self):
        hdr = "total %d Dll calls: \n"
        calls_infos = ""
        for i in range(self.dll_call_count):
            call_info = "lib: %s, func: %s\n" %(self.libnames[i], self.funcnames[i])
            calls_infos += call_info
        return calls_infos

    def __getitem__(self, index):
        call_infos = ""
        if self.show_module:
            return self.libnames[index] + self.funcnames[index]
        else:
            return self.funcnames[index]

def get_E_main():
    # .text:00485090 55                          push    ebp
    # .text:00485091 8B EC                       mov     ebp, esp
    # .text:00485093 51                          push    ecx
    # .text:00485094 53                          push    ebx
    # .text:00485095 56                          push    esi
    # .text:00485096 8B F1                       mov     esi, ecx
    # .text:00485098 57                          push    edi
    # .text:00485099 8B 4E 68                    mov     ecx, [esi+68h]
    # .text:0048509C 8D 86 D8 00 00 00           lea     eax, [esi+0D8h]
    # .text:004850A2 50                          push    eax             ; int
    # .text:004850A3 51                          push    ecx             ; hModule
    # .text:004850A4 E8 C7 D3 00 00              call    krnln_?GetInstancePath@@YAXPAUHINSTANCE__@@AAVCString@@@Z
    E_main_pat = "55 8B EC 51 53 56 8B F1 57 8B 4E 68 8D 86 D8 00 00 00 50 51 E8"
    E_main_call_ins_offset = 0x37

    E_main_func_ea = 0
    code_segs = get_code_segs()
    for seg in code_segs:
        start_ea = seg.start_ea
        end_ea = seg.end_ea
        E_main_pat_ea = ida_search.find_binary(start_ea, end_ea, E_main_pat, 16, ida_search.SEARCH_DOWN)
        if E_main_pat_ea != idaapi.BADADDR:
            call_ins_ea = E_main_pat_ea + E_main_call_ins_offset
            addr_off = ida_bytes.get_dword(call_ins_ea + 1)
            E_main_func_ea = call_ins_ea + 5 + idaapi.as_int32(addr_off)
            print("Find E_main addr 0x%X" %(E_main_func_ea))
            break

    return E_main_func_ea
    

class E_Sigs:
    E_main_name = "E_main"

    # elib info offsets
    elib_count_offset = 0x20
    elib_infos_entry_offset = 0x24

    # dll_call info offsets
    dll_call_count_offset = 0x28
    dll_call_lib_names_offset = 0x2C
    dll_call_func_names_offset = 0x30

    def __init__(self, E_main_ea):
        self.E_main_ea = E_main_ea
        self.E_info_entry_ea = get_E_info_entry()

    def set_E_main_name(self):
        ida_name.set_name(self.E_main_ea, self.E_main_name, ida_name.SN_CHECK)

    def load_flirt_sigs(self):
        elib_count = ida_bytes.get_dword(self.E_info_entry_ea + self.elib_count_offset)
        elibs_start_ea = ida_bytes.get_dword(self.E_info_entry_ea + self.elib_infos_entry_offset)
        self.elibs = Elibs(elibs_start_ea, elib_count)
        for elib in self.elibs:
            if elib.sig_name:
                rc = ida_funcs.plan_to_apply_idasgn(elib.sig_name)
                if rc == 0:
                    print("Plan to apply %s ida signature error, may be there is no correspoing sig file in sig folder !!!" %elib.sig_name)
            else:
                print("There is no known sigature file corresponding to the library %s, you can make it by yourself !!!" %elib.name)

    def handle_dll_calls(self):
        dll_call_count = ida_bytes.get_dword(self.E_info_entry_ea + self.dll_call_count_offset)
        dll_call_lib_names_ea = ida_bytes.get_dword(self.E_info_entry_ea + self.dll_call_lib_names_offset)
        dll_call_func_names_ea = ida_bytes.get_dword(self.E_info_entry_ea + self.dll_call_func_names_offset)
        self.dll_calls = Dll_calls(dll_call_lib_names_ea, dll_call_func_names_ea, dll_call_count)
        
        ida_auto.auto_wait()

        ea = ida_name.get_name_ea(idaapi.BADADDR, "j__krnl_MCallDllCmd")
        code_fref_eas = []
        fref_ea = ida_xref.get_first_fcref_to(ea)

        while fref_ea != idaapi.BADADDR:
            code_fref_eas.append(fref_ea)
            fref_ea = ida_xref.get_next_cref_to(ea, fref_ea)

        for ref_ea in code_fref_eas:
            #get prev mov instruction
            prev_ins_ea = idaapi.get_item_head(ref_ea - 1)
            ins = ida_lines.generate_disasm_line(prev_ins_ea, ida_lines.GENDSM_REMOVE_TAGS)
            if(ins.startswith("mov     eax,")):
                index = ida_bytes.get_dword(prev_ins_ea + 1)
                cmt = self.dll_calls[index]
                ida_bytes.set_cmt(ref_ea, cmt, False)

    def handle_CallKrnlLibCmd_args_type(self):
        pass

    def display_E_strings(self):
        pass

    def display_E_imports(self):
        pass

class ESigPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "E language or FlyStudio signature plugin"
    help = "E language or FlyStudio signature plugin"
    wanted_name = "ESigPlugin"
    wanted_hotkey = ""
    def init(self):
        idaapi.msg("ESigPlugin init")
        return idaapi.PLUGIN_OK
    
    def run(self, arg):
        idaapi.msg("ESigPlugin run")
        e_main_ea = get_E_main()
        if e_main_ea != 0:
            e_sig = E_Sigs(e_main_ea)
            e_sig.set_E_main_name()
            e_sig.load_flirt_sigs()
            e_sig.handle_dll_calls()
            idaapi.jumpto(e_main_ea)
            print("e sig finish")
        else:
            idaapi.msg("Can not find E language main function, the file may not be compiled by E compiler.")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return ESigPlugin()


